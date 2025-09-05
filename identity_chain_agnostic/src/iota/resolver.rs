// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::IotaResourceLocator;
use crate::iota::IotaNetwork;

use iota_client::Client;
use iota_types::ObjectId;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt::Display;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A resolver for IOTA-based Chain Agnostic Resource Locators.
#[derive(Default)]
pub struct Resolver {
  established_clients: RwLock<HashMap<IotaNetwork, Arc<Client>>>,
  custom_networks: Vec<(IotaNetwork, String)>,
}

impl Resolver {
  /// Returns a new [Resolver] capable of dereferencing [IotaResourceLocator]s
  /// that reference resources on any official IOTA networks (mainnet, testnet, devnet).
  pub fn new() -> Self {
    Self::default()
  }

  /// Returns a new [Resolver] capable of dereferencing [IotaResourceLocator]s
  /// that reference resources on any official IOTA networks and any other custom network
  /// specified through the argument `custom_networks`.
  ///
  /// `custom_networks` must be an iterable collection of `(IotaNetwork, String)`, where the first
  /// value must be a custom IOTA network (will be ignored otherwise), and the second value of the
  /// tuple must be the GraphQL endpoint for that network.
  pub fn new_with_custom_networks(custom_networks: impl IntoIterator<Item = (IotaNetwork, String)>) -> Self {
    Self {
      custom_networks: custom_networks
        .into_iter()
        .filter(|(network, _)| network.is_custom())
        .collect(),
      ..Default::default()
    }
  }

  /// Resolves the resource referenced by the given [IotaResourceLocator].
  pub async fn resolve(&self, resource: &IotaResourceLocator) -> Result<Value, ResolutionError> {
    // Get hold of an IOTA client for the network referenced in the queried resource.
    let iota_client = self
      .get_or_init_client(&resource.network)
      .await
      .map_err(|kind| ResolutionError {
        resource: resource.clone(),
        kind,
      })?;

    // Query the object referenced in the resource.
    let object_id = ObjectId::new(resource.object_id.into_bytes());
    let mut json_object = iota_client
      .move_object_contents(object_id, None)
      .await
      .map_err(|e| ResolutionError {
        resource: resource.clone(),
        kind: ResolutionErrorKind::QueryError(e.into()),
      })?
      .ok_or_else(|| ResolutionError {
        resource: resource.clone(),
        kind: ResolutionErrorKind::NotFound,
      })?;

    if resource.relative_url.path() != "/" {
      let target = json_object
        .pointer_mut(&format!("/{}", resource.relative_url.path()))
        // If the path inside the object doesn't yield any value, we return NOT FOUND for now.
        .ok_or_else(|| ResolutionError {
          resource: resource.clone(),
          kind: ResolutionErrorKind::NotFound,
        })?;
      Ok(std::mem::take(target))
    } else {
      Ok(json_object)
    }
  }

  /// Returns an IOTA client for the given network.
  async fn get_or_init_client(&self, network: &IotaNetwork) -> Result<Arc<Client>, ResolutionErrorKind> {
    if let Some(client) = self.established_clients.read().await.get(network) {
      return Ok(client.clone());
    }

    let client = {
      let client = match network {
        &IotaNetwork::Mainnet => Client::new_mainnet(),
        &IotaNetwork::Testnet => Client::new_testnet(),
        &IotaNetwork::Devnet => Client::new_devnet(),
        network => {
          let endpoint = self
            .custom_networks
            .iter()
            .find_map(|(net, endpoint)| (network == net).then_some(endpoint.as_str()))
            .ok_or_else(|| ResolutionErrorKind::UnknownNetwork(network.clone()))?;
          Client::new(endpoint).map_err(|e| ResolutionErrorKind::ConnectionIssue {
            network: network.clone(),
            endpoint: endpoint.to_owned(),
            source: e.into(),
          })?
        }
      };
      Arc::new(client)
    };

    self
      .established_clients
      .write()
      .await
      .insert(network.clone(), client.clone());
    Ok(client)
  }
}

/// A failure in the resolution of a given IOTA resource.
#[derive(Debug)]
#[non_exhaustive]
pub struct ResolutionError {
  /// The resource's location that was being resolved.
  pub resource: IotaResourceLocator,
  /// The type of failure.
  pub kind: ResolutionErrorKind,
}

impl Display for ResolutionError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "failed to resolve `{}`", self.resource)
  }
}

impl StdError for ResolutionError {
  fn source(&self) -> Option<&(dyn StdError + 'static)> {
    Some(&self.kind)
  }
}

/// Types of resolution failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResolutionErrorKind {
  /// The requested resource couldn't be found.
  NotFound,
  /// The requested resource is located on an unknown network.
  UnknownNetwork(IotaNetwork),
  /// Failed to establish a connection with the network the
  /// requested resource is located on.
  #[non_exhaustive]
  ConnectionIssue {
    network: IotaNetwork,
    endpoint: String,
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The underlying query failed.
  QueryError(Box<dyn StdError + Send + Sync>),
}

impl Display for ResolutionErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::NotFound => f.write_str("not found"),
      Self::UnknownNetwork(network) => write!(f, "unknown network `iota:{network}`"),
      Self::ConnectionIssue { network, endpoint, .. } => {
        write!(f, "failed to connect to `iota:{network}` through endpoint `{endpoint}`")
      }
      Self::QueryError(e) => write!(f, "{e}"),
    }
  }
}

impl StdError for ResolutionErrorKind {
  fn source(&self) -> Option<&(dyn StdError + 'static)> {
    match &self {
      Self::ConnectionIssue { source, .. } => Some(source.as_ref()),
      Self::QueryError(e) => e.source(),
      _ => None,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn resolve_raw_did_bytes() -> Result<(), Box<dyn StdError>> {
    let resource = IotaResourceLocator::parse(
      "iota:mainnet/0xf4d6f08f5a1b80dd578da7dc1b49c886d580acd4cf7d48119dfeb82b538ad88a/state_metadata",
    )?;
    let resolver = Resolver::default();

    let json_result = resolver.resolve(&resource).await?;
    let did_raw_bytes: Vec<u8> = serde_json::from_value(json_result)?;

    assert_eq!(&did_raw_bytes[..3], b"DID");

    Ok(())
  }

  #[tokio::test]
  async fn empty_path_returns_entire_object() -> Result<(), Box<dyn StdError>> {
    let resolver = Resolver::default();
    let resource = "iota:mainnet/0x508974bc41f08e86ed3eb223c90081a9bc3f198be1e758c6ade9eff8db06a2dd".parse()?;
    let resolved_coin = resolver.resolve(&resource).await?;

    let sdk_resolved_coin = resolver
      .get_or_init_client(&IotaNetwork::Mainnet)
      .await
      .unwrap()
      .move_object_contents(ObjectId::new(resource.object_id.into_bytes()), None)
      .await?
      .unwrap();

    assert_eq!(resolved_coin, sdk_resolved_coin);

    Ok(())
  }
}
