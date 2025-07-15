// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use identity_core::common::Url;
use identity_did::DID as _;
use iota_interaction::rpc_types::IotaExecutionStatus;
use iota_interaction::rpc_types::IotaObjectDataOptions;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI as _;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::id::UID;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::types::TypeTag;
use iota_interaction::types::STARDUST_PACKAGE_ID;
use iota_interaction::IotaTransactionBlockEffectsMutAPI as _;
use iota_interaction::OptionalSync;

use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction;
use serde;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::OnceCell;

use crate::rebased::client::IdentityClientReadOnly;

use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::Error;
use crate::IotaDID;
use iota_interaction::IotaClientTrait;
use iota_interaction::MoveType;

use super::get_identity;
use super::migration_registry_id;
use super::Identity;
use super::OnChainIdentity;

/// A legacy IOTA Stardust Output type, used to store DID Documents.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnmigratedAlias {
  /// The ID of the Alias = hash of the Output ID that created the Alias Output in Stardust.
  /// This is the AliasID from Stardust.
  pub id: UID,

  /// The last State Controller address assigned before the migration.
  pub legacy_state_controller: Option<IotaAddress>,
  /// A counter increased by 1 every time the alias was state transitioned.
  pub state_index: u32,
  /// State metadata that can be used to store additional information.
  pub state_metadata: Option<Vec<u8>>,

  /// The sender feature.
  pub sender: Option<IotaAddress>,

  /// The immutable issuer feature.
  pub immutable_issuer: Option<IotaAddress>,
  /// The immutable metadata feature.
  pub immutable_metadata: Option<Vec<u8>>,
}

impl MoveType for UnmigratedAlias {
  fn move_type(_: ObjectID) -> TypeTag {
    format!("{STARDUST_PACKAGE_ID}::alias::Alias")
      .parse()
      .expect("valid move type")
  }
}

/// Resolves an [`UnmigratedAlias`] given its ID `object_id`.
pub async fn get_alias(client: &IdentityClientReadOnly, object_id: ObjectID) -> Result<Option<UnmigratedAlias>, Error> {
  match client.get_object_by_id(object_id).await {
    Ok(Some(alias)) => Ok(Some(alias)),
    Ok(None) => Ok(None),
    Err(e) => Err(e.into()),
  }
}

/// A [Transaction] that migrates a legacy Identity to
/// a new [OnChainIdentity].
pub struct MigrateLegacyIdentity {
  alias: UnmigratedAlias,
  cached_ptb: OnceCell<ProgrammableTransaction>,
}

impl MigrateLegacyIdentity {
  /// Returns a new [MigrateLegacyIdentity] transaction.
  pub fn new(alias: UnmigratedAlias) -> Self {
    Self {
      alias,
      cached_ptb: OnceCell::new(),
    }
  }

  async fn make_ptb<C>(&self, client: &C) -> Result<ProgrammableTransaction, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    // Try to parse a StateMetadataDocument out of this alias.
    let identity = Identity::Legacy(self.alias.clone());
    let did_doc = identity.did_document(client.network_name())?;
    let Identity::Legacy(alias) = identity else {
      unreachable!("alias was wrapped by us")
    };
    // Get the ID of the `AliasOutput` that owns this `Alias`.
    let dynamic_field_wrapper = client
      .client_adapter()
      .read_api()
      .get_object_with_options(*alias.id.object_id(), IotaObjectDataOptions::new().with_owner())
      .await
      .map_err(|e| Error::RpcError(e.to_string()))?
      .owner()
      .expect("owner was requested")
      .get_owner_address()
      .expect("alias is a dynamic field")
      .into();
    let alias_output_id = client
      .client_adapter()
      .read_api()
      .get_object_with_options(dynamic_field_wrapper, IotaObjectDataOptions::new().with_owner())
      .await
      .map_err(|e| Error::RpcError(e.to_string()))?
      .owner()
      .expect("owner was requested")
      .get_owner_address()
      .expect("alias is owned by an alias_output")
      .into();
    // Get alias_output's ref.
    let alias_output_ref = client
      .client_adapter()
      .read_api()
      .get_object_with_options(alias_output_id, IotaObjectDataOptions::default())
      .await
      .map_err(|e| Error::RpcError(e.to_string()))?
      .object_ref_if_exists()
      .expect("alias_output exists");
    // Get migration registry ref.
    let migration_registry_id = migration_registry_id(client)
      .await
      .map_err(Error::MigrationRegistryNotFound)?;
    let migration_registry_ref = client
      .get_object_ref_by_id(migration_registry_id)
      .await?
      .expect("migration registry exists");

    // Extract creation metadata
    let created = did_doc
      .metadata
      .created
      // `to_unix` returns the seconds since EPOCH; we need milliseconds.
      .map(|timestamp| timestamp.to_unix() as u64 * 1000);

    let package = identity_package_id(client).await?;

    // Build migration tx.
    let tx = move_calls::migration::migrate_did_output(alias_output_ref, created, migration_registry_ref, package)
      .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;

    Ok(bcs::from_bytes(&tx)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl Transaction for MigrateLegacyIdentity {
  type Output = OnChainIdentity;
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.to_string()));
    }

    let legacy_did: Url = IotaDID::new(&self.alias.id.object_id().into_bytes(), client.network_name())
      .to_url()
      .into();
    let is_target_identity =
      |identity: &OnChainIdentity| -> bool { identity.did_document().also_known_as().contains(&legacy_did) };

    let created_objects = effects
      .created()
      .iter()
      .enumerate()
      .filter(|(_, obj_ref)| obj_ref.owner.is_shared())
      .map(|(i, obj_ref)| (i, obj_ref.object_id()));

    let mut target_identity_pos = None;
    let mut target_identity = None;
    for (i, obj_id) in created_objects {
      match get_identity(client, obj_id).await {
        Ok(Some(identity)) if is_target_identity(&identity) => {
          target_identity_pos = Some(i);
          target_identity = Some(identity);
          break;
        }
        _ => continue,
      }
    }

    let (Some(i), Some(identity)) = (target_identity_pos, target_identity) else {
      return Err(Error::TransactionUnexpectedResponse(
        "failed to find the correct identity in this transaction's effects".to_owned(),
      ));
    };

    effects.created_mut().swap_remove(i);

    Ok(identity)
  }
}
