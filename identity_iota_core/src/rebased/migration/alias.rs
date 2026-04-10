// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Url;
use identity_did::DID as _;
use iota_sdk::graphql_client::query_types::ObjectFilter;
use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_repr::Uid;
use product_core::move_type::MoveType;
use product_core::move_type::UnknownTypeForNetwork;
use product_core::network::Network;
use product_core::operation::Operation;
use product_core::product_client::ProductClient;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
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
  pub id: Uid,

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
  fn move_type(_: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    let stardust_pkg_id = ObjectId::from_hex("0x107a").expect("valid shortened object ID");
    Ok(
      format!("{stardust_pkg_id}::alias::Alias")
        .parse()
        .expect("valid move type"),
    )
  }
}

/// Resolves an [`UnmigratedAlias`] given its ID `object_id`.
pub async fn get_alias(client: &impl ProductClient, object_id: ObjectId) -> Result<Option<UnmigratedAlias>, Error> {
  match client.get_object_by_id(object_id).await {
    Ok(Some(alias)) => Ok(Some(alias)),
    Ok(None) => Ok(None),
    Err(e) => Err(e.into()),
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

  async fn make_ptb(&self, client: &impl ProductClient, ptb: &mut TransactionBuilder<Client>) -> Result<(), Error> {
    // Try to parse a StateMetadataDocument out of this alias.
    let identity = Identity::Legacy(self.alias.clone());
    let did_doc = identity.did_document(client.network_name())?;
    let Identity::Legacy(alias) = identity else {
      unreachable!("alias was wrapped by us")
    };
    // Get the ID of the `AliasOutput` that owns this `Alias`.
    let dynamic_field_wrapper = client
      .object(alias.id.id, None)
      .await?
      .expect("alias exists")
      .owner
      .into_object();
    let alias_output = client
      .object(dynamic_field_wrapper, None)
      .await?
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
  type Output = OnChainIdentity;
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    mut ptb: TransactionBuilder<Client>,
  ) -> Result<TransactionBuilder<Client>, Self::Error> {
    self.make_ptb(client, &mut ptb).await?;
    Ok(ptb)
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = effects.status().error() {
      return Err(tx_error.into());
    }

    let legacy_did: Url = IotaDID::from_object_id(self.alias.id.id, client.network())
      .to_url()
      .into();
    let is_target_identity =
      |identity: &OnChainIdentity| -> bool { identity.did_document().also_known_as().contains(&legacy_did) };

    let candidates = effects
      .as_v1()
      .changed_objects
      .iter()
      .filter_map(|obj| obj.id_operation.is_created().then_some(obj.object_id))
      .collect();
    let identity_type = OnChainIdentity::move_type(client.network())
      .expect("type can be determined")
      .to_string();
    let filter = ObjectFilter {
      object_ids: Some(candidates),
      type_: Some(identity_type),
      ..Default::default()
    };
    let identity = client
      .objects_content_stream(filter)
      .filter_map(|maybe_identity| maybe_identity.ok().filter(|identity| is_target_identity(identity)))
      .next()
      .await
      .ok_or_else(|| {
        Error::TransactionUnexpectedResponse(
          "failed to find the correct identity in this transaction's effects".to_owned(),
        )
      })?;

    effects
      .as_mut_v1()
      .changed_objects
      .retain(|obj| obj.object_id != identity.id());

    Ok(identity)
  }
}
