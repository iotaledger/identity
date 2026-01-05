// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for [IdentityClient].

use std::fmt::Debug;

use iota_interaction::types::base_types::ObjectID;
use iota_interaction::IotaClient;
use iota_interaction::IotaKeySignature;
use secret_storage::Signer;

use crate::rebased::client::IdentityClient;
use crate::rebased::client::IdentityClientReadOnly;

const TESTNET_RPC_ENDPOINT: &str = "https://api.testnet.iota.cafe/";
const DEVNET_RPC_ENDPOINT: &str = "https://api.devnet.iota.cafe/";
const MAINNET_RPC_ENDPOINT: &str = "https://api.mainnet.iota.cafe/";
const LOCALNET_RPC_ENDPOINT: &str = "http://localhost:9000/";

/// A marker type used to indicate that no signer is provided.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSigner;

/// Builder for [`IdentityClient`].
/// # Example
/// ```
/// # use identity_iota_core::rebased::client::builder::IdentityClientBuilder;
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let identity_client = IdentityClientBuilder::new().build_testnet().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct IdentityClientBuilder<S = NoSigner> {
  signer: S,
  iota_client: Option<IotaClient>,
  pkg_id: Option<ObjectID>,
}

impl IdentityClientBuilder<NoSigner> {
  /// Creates a new [`IdentityClientBuilder`] with default values.
  pub fn new() -> Self {
    Self::default()
  }

  /// Creates a new [`IdentityClientBuilder`] from an existing [`IotaClient`].
  pub fn from_iota_client(iota_client: IotaClient) -> Self {
    Self {
      iota_client: Some(iota_client),
      ..Self::new()
    }
  }

  /// Sets the signer of the resulting [IdentityClient].
  pub fn with_signer<S>(self, signer: S) -> IdentityClientBuilder<S> {
    IdentityClientBuilder {
      signer,
      iota_client: self.iota_client,
      pkg_id: self.pkg_id,
    }
  }

  /// Sets a custom package ID for the identity framework.
  /// # Warning
  /// Using a custom Identity package should only be done when targeting a local or private network.
  pub fn with_custom_identity_package(mut self, custom_pkg_id: ObjectID) -> Self {
    self.pkg_id = Some(custom_pkg_id);
    self
  }

  /// Builds an [IdentityClient] connected to the mainnet.
  pub async fn build_mainnet(self) -> anyhow::Result<IdentityClient> {
    self.build(MAINNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the testnet.
  pub async fn build_testnet(self) -> anyhow::Result<IdentityClient> {
    self.build(TESTNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the devnet.
  pub async fn build_devnet(self) -> anyhow::Result<IdentityClient> {
    self.build(DEVNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the default local network RPC endpoint.
  /// If you are using a different endpoint, use [`Self::build`] instead.
  pub async fn build_localnet(self) -> anyhow::Result<IdentityClient> {
    if self.pkg_id.is_none() {
      anyhow::bail!("A custom Identity package ID must be provided when connecting to a local network");
    }
    self.build(LOCALNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the specified RPC endpoint.
  pub async fn build(self, rpc_endpoint: impl AsRef<str>) -> anyhow::Result<IdentityClient> {
    #[cfg(not(target_arch = "wasm32"))]
    {
      let mut iota_client = iota_sdk::IotaClientBuilder::default().build(rpc_endpoint).await?;

      let chain_id = iota_client.read_api().get_chain_identifier().await?;
      // Reuse the previously supplied client if it matches the chain ID.
      if let Some(prev_client) = self.iota_client {
        let prev_client_chain_id = prev_client.read_api().get_chain_identifier().await?;
        if chain_id == prev_client_chain_id {
          iota_client = prev_client;
        }
      }

      let read_client = if let Some(custom_pkg_id) = self.pkg_id {
        IdentityClientReadOnly::new_with_pkg_id(iota_client, custom_pkg_id).await?
      } else {
        IdentityClientReadOnly::new(iota_client).await?
      };

      Ok(IdentityClient {
        read_client,
        public_key: None,
        signer: (),
      })
    }
    #[cfg(target_arch = "wasm32")]
    {
      todo!()
    }
  }
}

impl<S: Signer<IotaKeySignature>> IdentityClientBuilder<S> {
  /// Builds an [IdentityClient] connected to the mainnet.
  pub async fn build_mainnet(self) -> anyhow::Result<IdentityClient<S>> {
    self.build(MAINNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the testnet.
  pub async fn build_testnet(self) -> anyhow::Result<IdentityClient<S>> {
    self.build(TESTNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the devnet.
  pub async fn build_devnet(self) -> anyhow::Result<IdentityClient<S>> {
    self.build(DEVNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the default local network RPC endpoint.
  pub async fn build_localnet(self) -> anyhow::Result<IdentityClient<S>> {
    if self.pkg_id.is_none() {
      anyhow::bail!("A custom Identity package ID must be provided when connecting to a local network");
    }
    self.build(LOCALNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to the specified RPC endpoint.
  pub async fn build(self, rpc_endpoint: impl AsRef<str>) -> anyhow::Result<IdentityClient<S>> {
    let signer = self.signer;
    let public_key = signer.public_key().await?;
    let builder = IdentityClientBuilder {
      signer: NoSigner,
      iota_client: self.iota_client,
      pkg_id: self.pkg_id,
    };

    let identity_client = builder.build(rpc_endpoint).await?;
    Ok(IdentityClient {
      read_client: identity_client.read_client,
      public_key: Some(public_key),
      signer,
    })
  }
}

impl<S: Debug> Debug for IdentityClientBuilder<S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("IdentityClientBuilder")
      .field("signer", &self.signer)
      .field("iota_client", &self.iota_client.as_ref().and(Some("[IotaClient]")))
      .field("pkg_id", &self.pkg_id)
      .finish()
  }
}
