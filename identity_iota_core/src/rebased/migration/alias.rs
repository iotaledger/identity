// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr as _;

use identity_core::common::Url;
use identity_did::DID as _;
use iota_sdk::graphql_client::Client;
use iota_sdk::move_types::iota_framework::object::UID;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use itertools::Itertools as _;
use product_core::move_type::MoveType;
use product_core::operation::Operation;
use product_core::product_client::ProductClient;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::client::IdentityClient;
use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::migration::get_identity;
use crate::rebased::Error;
use crate::IotaDID;

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
  pub legacy_state_controller: Option<Address>,
  /// A counter increased by 1 every time the alias was state transitioned.
  pub state_index: u32,
  /// State metadata that can be used to store additional information.
  pub state_metadata: Option<Vec<u8>>,

  /// The sender feature.
  pub sender: Option<Address>,

  /// The immutable issuer feature.
  pub immutable_issuer: Option<Address>,
  /// The immutable metadata feature.
  pub immutable_metadata: Option<Vec<u8>>,
}

impl MoveType for UnmigratedAlias {
  fn move_type(_client: &impl ProductClient) -> TypeTag {
    let stardust_pkg_id = ObjectId::from_hex("0x107a").expect("valid shortened object ID");
    TypeTag::from_str(&format!("{stardust_pkg_id}::alias::Alias")).expect("valid move type")
  }
}

/// Resolves an [`UnmigratedAlias`] given its ID `object_id`.
pub async fn get_alias(client: &IdentityClient, object_id: ObjectId) -> Result<Option<UnmigratedAlias>, Error> {
  match client.move_object_contents(object_id, None).await {
    Ok(Some(alias)) => serde_json::from_value(alias)
      .map(Some)
      .map_err(|e| Error::RpcError(e.to_string())),
    Ok(None) => Ok(None),
    Err(e) => Err(Error::RpcError(e.to_string())),
  }
}

/// An [Operation] that migrates a legacy Identity to
/// a new [OnChainIdentity].
pub struct MigrateLegacyIdentity {
  alias: UnmigratedAlias,
}

impl MigrateLegacyIdentity {
  /// Returns a new [MigrateLegacyIdentity] transaction.
  pub fn new(alias: UnmigratedAlias) -> Self {
    Self { alias }
  }

  async fn make_ptb(&self, client: &IdentityClient, ptb: &mut TransactionBuilder<Client>) -> Result<(), Error> {
    // Try to parse a StateMetadataDocument out of this alias.
    let identity = Identity::Legacy(self.alias.clone());
    let did_doc = identity.did_document(client.network())?;
    let Identity::Legacy(alias) = identity else {
      unreachable!("alias was wrapped by us")
    };
    // Get the ID of the `AliasOutput` that owns this `Alias`.
    let dynamic_field_wrapper = client
      .object(*alias.id.object_id(), None)
      .await
      .map_err(|e| Error::RpcError(e.to_string()))?
      .expect("alias exists")
      .owner
      .into_object();
    let alias_output = client
      .object(dynamic_field_wrapper, None)
      .await
      .map_err(|e| Error::RpcError(e.to_string()))?
      .expect("dynamic field wrapper exists")
      .owner
      .into_object();
    // Get migration registry ref.
    let migration_registry = migration_registry_id(client)
      .await
      .map_err(Error::MigrationRegistryNotFound)?;

    // Extract creation metadata
    let created = did_doc
      .metadata
      .created
      // `to_unix` returns the seconds since EPOCH; we need milliseconds.
      .map(|timestamp| timestamp.to_unix() as u64 * 1000);

    let package = identity_package_id(client.network()).await?;

    // Build migration tx.
    move_calls::migration::migrate_did_output(ptb, alias_output, created, migration_registry, package);

    Ok(())
  }
}

impl Operation for MigrateLegacyIdentity {
  type Client = IdentityClient;
  type Output = OnChainIdentity;
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &IdentityClient,
    mut ptb: TransactionBuilder<Client>,
  ) -> Result<TransactionBuilder<Client>, Self::Error> {
    self.make_ptb(client, &mut ptb).await?;
    Ok(ptb)
  }

  async fn apply_effects(
    self,
    client: &IdentityClient,
    effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = effects.as_v1().status.error() {
      return Err(tx_error.clone().into());
    }

    let legacy_did: Url = IotaDID::from_object_id(*self.alias.id.object_id(), client.network())
      .to_url()
      .into();
    let is_target_identity =
      |identity: &OnChainIdentity| -> bool { identity.did_document().also_known_as().contains(&legacy_did) };

    let candidates = effects
      .as_v1()
      .changed_objects
      .iter()
      .filter_map(|obj| obj.id_operation.is_created().then_some(obj.object_id))
      .collect_vec();

    for candidate_id in candidates {
      if let Ok(Some(identity)) = get_identity(client, candidate_id).await {
        if is_target_identity(&identity) {
          return Ok(identity);
        }
      }
    }

    Err(Error::TransactionUnexpectedResponse(
      "failed to find the correct identity in this transaction's effects".to_owned(),
    ))
  }
}
