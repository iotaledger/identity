// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::LazyLock;

use iota_sdk::graphql_client::query_types::EventFilter;
use iota_sdk::graphql_client::Direction;
use iota_sdk::graphql_client::PaginationFilter;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TypeTag;
use phf::phf_map;
use phf::Map;
use product_core::network::Network;
use product_core::product_client::ProductClient;
use serde::Deserialize;
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

static MIGRATION_REGISTRY_ON_CUSTOM_NETWORK: LazyLock<RwLock<HashMap<String, ObjectId>>> =
  LazyLock::new(|| RwLock::new(HashMap::default()));

pub(crate) async fn migration_registry_id(client: &impl ProductClient) -> Result<ObjectId, Error> {
  let network_id = client.network().as_chain_id();

  // The registry has already been computed for this network.
  if let Some(registry) = MIGRATION_REGISTRY_ON_CUSTOM_NETWORK.read().await.get(network_id) {
    return Ok(*registry);
  }

  // Client is connected to a well-known network.
  if let Some(registry) = MIGRATION_REGISTRY_ON_IOTA_NETWORK.get(network_id) {
    return Ok(registry.parse().unwrap());
  }

  let package_id = identity_package_id(client.network())
    .await
    .map_err(|_| Error::UnknownNetwork(client.network()))?;
  let registry_id = find_migration_registry(client, package_id).await?;

  // Cache registry for network.
  MIGRATION_REGISTRY_ON_CUSTOM_NETWORK
    .write()
    .await
    .insert(network_id.to_string(), registry_id);

  Ok(package_id)
}

pub(crate) fn set_migration_registry_id(chain_id: &str, id: ObjectId) {
  MIGRATION_REGISTRY_ON_CUSTOM_NETWORK
    .blocking_write()
    .insert(chain_id.to_owned(), id);
}

/// Errors that can occur during migration registry operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
  /// An error occurred while interacting with the IOTA Client.
  #[error(transparent)]
  Client(#[from] iota_sdk::graphql_client::error::Error),
  /// Unknown network.
  #[error("unknown network '{0}'")]
  UnknownNetwork(Network),
  /// The MigrationRegistry object was not found.
  #[error("could not locate MigrationRegistry object: {0}")]
  NotFound(String),
  /// The MigrationRegistry object is malformed.
  #[error("malformed MigrationRegistry's entry: {0}")]
  Malformed(String),
}

/// Lookup a legacy `alias_id` into the migration registry
/// to get the ID of the corresponding migrated DID document, if any.
pub async fn lookup(id_client: &IdentityClientReadOnly, alias_id: ObjectId) -> Result<Option<OnChainIdentity>, Error> {
  let registry_id = migration_registry_id(id_client).await?;
  let type_ = TypeTag::from_str("0x2::object::ID").expect("valid type id");

  let Some(df_value) = id_client
    .dynamic_field(alias_id.into(), type_, alias_id)
    .await?
    .and_then(|df| df.value_as_json)
  else {
    return Ok(None);
  };

  #[derive(Debug, Deserialize)]
  struct Id {
    bytes: ObjectId,
  }

  let id = serde_json::from_value::<Id>(df_value)
    .map_err(|e| Error::Malformed(e.to_string()))?
    .bytes;
  get_identity(id_client, id).await
}

async fn find_migration_registry<C>(client: &impl ProductClient, package_id: ObjectId) -> Result<ObjectId, Error> {
  #[derive(serde::Deserialize)]
  struct MigrationRegistryCreatedEvent {
    id: ObjectId,
  }

  let event_filter = EventFilter {
    event_type: Some(format!("{package_id}::migration_registry::MigrationRegistryCreated")),
    ..Default::default()
  };
  let pagination_filter = PaginationFilter {
    direction: Direction::Forward,
    ..Default::default()
  };

  let event = client
    .events(event_filter, pagination_filter)
    .await?
    .data()
    .first()
    .ok_or_else(Error::NotFound(format!(
      "No MigrationRegistryCreated event on network {}",
      client.network_name()
    )))?;

  serde_json::from_value::<MigrationRegistryCreatedEvent>(event.json)
    .map(|e| e.id)
    .map_err(|e| Error::Malformed(e.to_string()))
}
