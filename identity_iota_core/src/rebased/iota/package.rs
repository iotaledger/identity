// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::LazyLock;

use iota_interaction::types::base_types::ObjectID;
use product_common::core_client::CoreClientReadOnly;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::RwLock;
use tokio::sync::RwLockReadGuard;
use tokio::sync::RwLockWriteGuard;

use crate::rebased::Error;

macro_rules! object_id {
  ($id:literal) => {
    ObjectID::from_hex_literal($id).unwrap()
  };
}

static IOTA_IDENTITY_PACKAGE_REGISTRY: LazyLock<RwLock<PackageRegistry>> = LazyLock::new(|| {
  RwLock::new({
    let mut registry = PackageRegistry::default();
    // Add well-known networks.
    registry.insert_env(
      Env::new_with_alias("6364aad5", "iota"),
      vec![object_id!(
        "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08"
      )],
    );
    registry.insert_env(
      Env::new_with_alias("2304aa97", "testnet"),
      vec![
        object_id!("0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555"),
        object_id!("0x3403da7ec4cd2ff9bdf6f34c0b8df5a2bd62c798089feb0d2ebf1c2e953296dc"),
      ],
    );
    registry.insert_env(
      Env::new_with_alias("e678123a", "devnet"),
      vec![
        object_id!("0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103"),
        object_id!("0x6a976d3da90db5d27f8a0c13b3268a37e582b455cfc7bf72d6461f6e8f668823"),
      ],
    );

    registry
  })
});

/// Network / Chain information.
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
    .ok_or_else(|| Error::InvalidConfig(format!("cannot find `IotaIdentity` package ID for network {network}")))
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
