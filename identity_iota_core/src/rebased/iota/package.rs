// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use std::collections::HashMap;

use iota_interaction::types::base_types::ObjectID;
use product_common::core_client::CoreClientReadOnly;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::RwLockReadGuard;
use tokio::sync::RwLockWriteGuard;

use crate::rebased::Error;

pub(crate) use super::package_registry::IOTA_IDENTITY_PACKAGE_REGISTRY;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Env {
  pub chain_id: String,
  pub alias: Option<String>,
}

impl Env {
  /// Creates a new package's environment.
  pub(crate) fn new(chain_id: impl Into<String>) -> Self {
    Self {
      chain_id: chain_id.into(),
      alias: None,
    }
  }

  /// Creates a new package's environment with the given alias.
  pub(crate) fn new_with_alias(chain_id: impl Into<String>, alias: impl Into<String>) -> Self {
    Self {
      chain_id: chain_id.into(),
      alias: Some(alias.into()),
    }
  }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PackageRegistry {
  aliases: HashMap<String, String>,
  envs: HashMap<String, Vec<ObjectID>>,
}

impl PackageRegistry {
  /// Returns the historical list of this package's versions for a given `chain`.
  /// `chain` can either be a chain identifier or its alias.
  ///
  /// ID at position `0` is the first ever published version of the package, `1` is
  /// the second, and so forth until the last, which is the currently active version.
  pub(crate) fn history(&self, chain: &str) -> Option<&[ObjectID]> {
    let from_alias = || self.aliases.get(chain).and_then(|chain_id| self.envs.get(chain_id));
    self.envs.get(chain).or_else(from_alias).map(|v| v.as_slice())
  }

  /// Returns this package's latest version ID for a given chain.
  pub(crate) fn package_id(&self, chain: &str) -> Option<ObjectID> {
    self.history(chain).and_then(|versions| versions.last()).copied()
  }

  /// Returns the alias of a given chain-id.
  pub(crate) fn chain_alias(&self, chain_id: &str) -> Option<&str> {
    self
      .aliases
      .iter()
      .find_map(|(alias, chain)| (chain == chain_id).then_some(alias.as_str()))
  }

  /// Adds or replaces this package's metadata for a given environment.
  pub(crate) fn insert_env(&mut self, env: Env, history: Vec<ObjectID>) {
    let Env { chain_id, alias } = env;

    if let Some(alias) = alias {
      self.aliases.insert(alias, chain_id.clone());
    }
    self.envs.insert(chain_id, history);
  }

  pub(crate) fn insert_new_package_version(&mut self, chain_id: &str, package: ObjectID) {
    let history = self.envs.entry(chain_id.to_string()).or_default();
    if history.last() != Some(&package) {
      history.push(package)
    }
  }
}

pub(crate) async fn identity_package_registry() -> RwLockReadGuard<'static, PackageRegistry> {
  IOTA_IDENTITY_PACKAGE_REGISTRY.read().await
}

pub(crate) async fn identity_package_registry_mut() -> RwLockWriteGuard<'static, PackageRegistry> {
  IOTA_IDENTITY_PACKAGE_REGISTRY.write().await
}

pub(crate) async fn identity_package_id<C>(client: &C) -> Result<ObjectID, Error>
where
  C: CoreClientReadOnly,
{
  let network = client.network_name().as_ref();
  IOTA_IDENTITY_PACKAGE_REGISTRY
    .read()
    .await
    .package_id(network)
    .ok_or_else(|| Error::InvalidConfig(format!("cannot find IdentityIota package ID for network {network}")))
}

#[cfg(test)]
mod tests {
  use iota_sdk::IotaClientBuilder;

  use crate::rebased::client::IdentityClientReadOnly;

  #[tokio::test]
  async fn can_connect_to_testnet() -> anyhow::Result<()> {
    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    let _identity_client = IdentityClientReadOnly::new(iota_client).await?;

    Ok(())
  }

  #[tokio::test]
  async fn can_connect_to_devnet() -> anyhow::Result<()> {
    let iota_client = IotaClientBuilder::default().build_devnet().await?;
    let _identity_client = IdentityClientReadOnly::new(iota_client).await?;

    Ok(())
  }

  #[tokio::test]
  async fn can_connect_to_mainnet() -> anyhow::Result<()> {
    let iota_client = IotaClientBuilder::default().build_mainnet().await?;
    let _identity_client = IdentityClientReadOnly::new(iota_client).await?;

    Ok(())
  }

  #[tokio::test]
  async fn testnet_has_multiple_package_versions() -> anyhow::Result<()> {
    use product_common::core_client::CoreClientReadOnly as _;

    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    let identity_client = IdentityClientReadOnly::new(iota_client).await?;

    assert!(identity_client.package_history().len() > 1);
    Ok(())
  }
}
