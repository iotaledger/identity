// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::str::FromStr as _;
use std::sync::LazyLock;

use iota_interaction::move_types::language_storage::StructTag;
use iota_interaction::rpc_types::EventFilter;
use iota_interaction::rpc_types::IotaData;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::id::ID;
use iota_interaction::IotaClientTrait;
use phf::phf_map;
use phf::Map;
use product_common::core_client::CoreClientReadOnly;
use tokio::sync::RwLock;

use crate::rebased::client::IdentityClientReadOnly;
use crate::rebased::iota::package::identity_package_id;

use super::get_identity;
use super::OnChainIdentity;

static MIGRATION_REGISTRY_ON_IOTA_NETWORK: Map<&str, &str> = phf_map! {
  "e678123a" => "0x940ae1c2c48dade9ec01cc1eebab33ab6fecadda422ea18b105c47839fc64425", // Devnet
  "2304aa97" => "0xaacb529c289aec9de2a474faaa4ef68b04632bb6a5d08372ca5b60e3df659f59", // Testnet
  "6364aad5" => "0xa884c72da9971da8ec32efade0a9b05faa114770ba85f10925d0edbc3fa3edc3", // Mainnet
};

static MIGRATION_REGISTRY_ON_CUSTOM_NETWORK: LazyLock<RwLock<HashMap<String, ObjectID>>> =
  LazyLock::new(|| RwLock::new(HashMap::default()));

pub(crate) async fn migration_registry_id<C>(client: &C) -> Result<ObjectID, Error>
where
  C: CoreClientReadOnly,
{
  let network_id = client.network_name().as_ref();

  // The registry has already been computed for this network.
  if let Some(registry) = MIGRATION_REGISTRY_ON_CUSTOM_NETWORK.read().await.get(network_id) {
    return Ok(*registry);
  }

  // Client is connected to a well-known network.
  if let Some(registry) = MIGRATION_REGISTRY_ON_IOTA_NETWORK.get(network_id) {
    return Ok(registry.parse().unwrap());
  }

  let package_id = identity_package_id(client)
    .await
    .map_err(|_| Error::Client(anyhow::anyhow!("unknown network {network_id}")))?;
  let registry_id = find_migration_registry(client, package_id).await?;

  // Cache registry for network.
  MIGRATION_REGISTRY_ON_CUSTOM_NETWORK
    .write()
    .await
    .insert(network_id.to_string(), registry_id);

  Ok(package_id)
}

pub(crate) fn set_migration_registry_id(chain_id: &str, id: ObjectID) {
  MIGRATION_REGISTRY_ON_CUSTOM_NETWORK
    .blocking_write()
    .insert(chain_id.to_owned(), id);
}

/// Errors that can occur during migration registry operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
  /// An error occurred while interacting with the IOTA Client.
  #[error(transparent)]
  Client(#[from] anyhow::Error),
  /// The MigrationRegistry object was not found.
  #[error("could not locate MigrationRegistry object: {0}")]
  NotFound(String),
  /// The MigrationRegistry object is malformed.
  #[error("malformed MigrationRegistry's entry: {0}")]
  Malformed(String),
}

/// Lookup a legacy `alias_id` into the migration registry
/// to get the ID of the corresponding migrated DID document, if any.
pub async fn lookup(id_client: &IdentityClientReadOnly, alias_id: ObjectID) -> Result<Option<OnChainIdentity>, Error> {
  let registry_id = migration_registry_id(id_client).await?;
  let dynamic_field_name = serde_json::from_value(serde_json::json!({
    "type": "0x2::object::ID",
    "value": alias_id.to_string()
  }))
  .expect("valid move value");

  let identity_id = id_client
    .read_api()
    .get_dynamic_field_object(registry_id, dynamic_field_name)
    .await
    .map_err(|e| Error::Client(e.into()))?
    .data
    .map(|data| {
      data
        .content
        .and_then(|content| content.try_into_move())
        .and_then(|move_object| move_object.fields.to_json_value().get_mut("value").map(std::mem::take))
        .and_then(|value| serde_json::from_value::<ID>(value).map(|id| id.bytes).ok())
        .ok_or(Error::Malformed(
          "invalid MigrationRegistry's Entry encoding".to_string(),
        ))
    })
    .transpose()?;

  if let Some(id) = identity_id {
    get_identity(id_client, id).await.map_err(|e| Error::Client(e.into()))
  } else {
    Ok(None)
  }
}

async fn find_migration_registry<C>(iota_client: &C, package_id: ObjectID) -> Result<ObjectID, Error>
where
  C: CoreClientReadOnly,
{
  #[derive(serde::Deserialize)]
  struct MigrationRegistryCreatedEvent {
    id: ObjectID,
  }

  let event_filter = EventFilter::MoveEventType(
    StructTag::from_str(&format!("{package_id}::migration_registry::MigrationRegistryCreated")).expect("valid utf8"),
  );
  let mut returned_events = iota_client
    .client_adapter()
    .event_api()
    .query_events(event_filter, None, Some(1), false)
    .await
    .map_err(|e| Error::Client(e.into()))?
    .data;
  let event = if !returned_events.is_empty() {
    returned_events.swap_remove(0)
  } else {
    return Err(Error::NotFound(format!(
      "No MigrationRegistryCreated event on network {}",
      iota_client.network_name()
    )));
  };

  serde_json::from_value::<MigrationRegistryCreatedEvent>(event.parsed_json)
    .map(|e| e.id)
    .map_err(|e| Error::Malformed(e.to_string()))
}
