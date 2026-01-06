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
#[derive(Debug, Default)]
pub struct IdentityClientBuilder<S = NoSigner> {
  signer: S,
  pkg_id: Option<ObjectID>,
}

impl IdentityClientBuilder<NoSigner> {
  /// Creates a new [`IdentityClientBuilder`] with default values.
  pub fn new() -> Self {
    Self::default()
  }

  /// Sets the signer of the resulting [IdentityClient].
  pub fn signer<S>(self, signer: S) -> IdentityClientBuilder<S> {
    IdentityClientBuilder {
      signer,
      pkg_id: self.pkg_id,
    }
  }

  /// Sets a custom package ID for the identity framework.
  /// # Warning
  /// Using a custom Identity package should only be done when targeting a local or private network.
  pub fn custom_identity_package(mut self, custom_pkg_id: ObjectID) -> Self {
    self.pkg_id = Some(custom_pkg_id);
    self
  }

  /// Builds an [IdentityClient] connected to mainnet.
  pub async fn build_mainnet(self) -> anyhow::Result<IdentityClient> {
    self.build(MAINNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to testnet.
  pub async fn build_testnet(self) -> anyhow::Result<IdentityClient> {
    self.build(TESTNET_RPC_ENDPOINT).await
  }

  /// Builds an [IdentityClient] connected to devnet.
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

  /// Builds an [IdentityClient] using the provided [IotaClient].
  pub async fn build_from_iota_client(self, iota_client: IotaClient) -> anyhow::Result<IdentityClient> {
    // No need to set the public key since there is no signer.
    self.build_internal(iota_client).await
  }

  /// Builds an [IdentityClient] connected to the specified RPC endpoint.
  pub async fn build(self, rpc_endpoint: impl AsRef<str>) -> anyhow::Result<IdentityClient> {
    #[cfg(not(target_arch = "wasm32"))]
    {
      let iota_client = iota_sdk::IotaClientBuilder::default().build(rpc_endpoint).await?;
      self.build_internal(iota_client).await
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
    let (signer, builder_without_signer) = self.pop_signer();
    Ok(
      builder_without_signer
        .build_mainnet()
        .await?
        .with_signer(signer)
        .await?,
    )
  }

  /// Builds an [IdentityClient] connected to the testnet.
  pub async fn build_testnet(self) -> anyhow::Result<IdentityClient<S>> {
    let (signer, builder_without_signer) = self.pop_signer();
    Ok(
      builder_without_signer
        .build_testnet()
        .await?
        .with_signer(signer)
        .await?,
    )
  }

  /// Builds an [IdentityClient] connected to the devnet.
  pub async fn build_devnet(self) -> anyhow::Result<IdentityClient<S>> {
    let (signer, builder_without_signer) = self.pop_signer();
    Ok(builder_without_signer.build_devnet().await?.with_signer(signer).await?)
  }

  /// Builds an [IdentityClient] connected to the default local network RPC endpoint.
  pub async fn build_localnet(self) -> anyhow::Result<IdentityClient<S>> {
    let (signer, builder_without_signer) = self.pop_signer();
    Ok(
      builder_without_signer
        .build_localnet()
        .await?
        .with_signer(signer)
        .await?,
    )
  }

  /// Builds an [IdentityClient] using the provided [IotaClient].
  pub async fn build_from_iota_client(self, iota_client: IotaClient) -> anyhow::Result<IdentityClient<S>> {
    let (signer, builder_without_signer) = self.pop_signer();
    let identity_client = builder_without_signer
      .build_internal(iota_client)
      .await?
      // Safety: this sets the signer and the public key, upholding IdentityClient's invariant.
      .with_signer(signer)
      .await?;

    Ok(identity_client)
  }

  /// Builds an [IdentityClient] connected to the specified RPC endpoint.
  pub async fn build(self, rpc_endpoint: impl AsRef<str>) -> anyhow::Result<IdentityClient<S>> {
    let (signer, builder_without_signer) = self.pop_signer();
    let identity_client = builder_without_signer
      .build(rpc_endpoint)
      .await?
      // Safety: this sets the signer and the public key, upholding IdentityClient's invariant.
      .with_signer(signer)
      .await?;

    Ok(identity_client)
  }
}

impl<S> IdentityClientBuilder<S> {
  /// Builds an [IdentityClient] using the provided [IotaClient] and whatever signer and package ID had been set.
  /// Note: if the signer impl `Signer<IotaKeySignature>`, the caller *MUST* set the client's public key.
  async fn build_internal(self, client: IotaClient) -> anyhow::Result<IdentityClient<S>> {
    let read_client = if let Some(custom_pkg_id) = self.pkg_id {
      IdentityClientReadOnly::new_with_pkg_id(client, custom_pkg_id).await?
    } else {
      IdentityClientReadOnly::new(client).await?
    };

    Ok(IdentityClient {
      read_client,
      public_key: None,
      signer: self.signer,
    })
  }

  fn pop_signer(self) -> (S, IdentityClientBuilder<NoSigner>) {
    (
      self.signer,
      IdentityClientBuilder {
        signer: NoSigner,
        pkg_id: self.pkg_id,
      },
    )
  }
}
