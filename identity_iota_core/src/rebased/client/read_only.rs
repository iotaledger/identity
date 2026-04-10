// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::str::FromStr;

use futures::stream::FuturesUnordered;
use futures::Stream;
use futures::StreamExt as _;
use futures::TryStreamExt as _;
use identity_core::common::Url;
use identity_did::DID;
use iota_sdk::graphql_client::error::Error as IotaClientError;
use iota_sdk::graphql_client::Client as IotaClient;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use product_core::move_type::MoveType;
use product_core::network::Network;
use product_core::operation::Operation;
use product_core::product_client::ProductClient;

use crate::rebased::iota::package::identity_package_registry;
use crate::rebased::migration::get_alias;
use crate::rebased::migration::get_identity;
use crate::rebased::migration::lookup;
use crate::rebased::migration::ControllerToken;
use crate::rebased::migration::Identity;
use crate::rebased::Error;
use crate::IotaDID;
use crate::IotaDocument;

/// An IOTA Identity client.
#[derive(Clone)]
pub struct IdentityClientReadOnly {
  iota_client: IotaClient,
  package_id: ObjectId,
  network: Network,
}

impl Deref for IdentityClientReadOnly {
  type Target = IotaClient;
  fn deref(&self) -> &Self::Target {
    &self.iota_client
  }
}

impl ProductClient for IdentityClientReadOnly {
  fn network(&self) -> Network {
    self.network
  }
  fn package_id(&self) -> ObjectId {
    self.package_id
  }
}

impl IdentityClientReadOnly {
  /// Creates a new [IdentityClient], with **no** signing capabilities, from the given [IotaClient].
  ///
  /// # Warning
  /// Passing a `custom_package_id` is **only** required when connecting to a custom IOTA network.
  ///
  /// Relying on a custom Identity package when connected to an official IOTA network is **highly
  /// discouraged** and is sure to result in compatibility issues when interacting with other official
  /// IOTA Trust Framework's products.
  ///
  /// # Examples
  /// ```
  /// # use identity_iota_core::rebased::client::IdentityClient;
  ///
  /// # #[tokio::main(flavor = "current_thread")]
  /// # async fn main() -> anyhow::Result<()> {
  /// let iota_client = iota_sdk::IotaClientBuilder::default()
  ///   .build_testnet()
  ///   .await?;
  /// // No package ID is required since we are connecting to an official IOTA network.
  /// let identity_client = IdentityClient::from_iota_client(iota_client, None).await?;
  /// # Ok(())
  /// # }
  /// ```
  pub async fn from_iota_client(
    iota_client: IotaClient,
    custom_package_id: impl Into<Option<ObjectId>>,
  ) -> Result<Self, FromIotaClientError> {
    let network = get_network(&iota_client)
      .await
      .map_err(|e| FromIotaClientErrorKind::NetworkResolution(e.into()))?;
    let package_id = if network.is_custom() {
      custom_package_id
        .into()
        .ok_or(FromIotaClientErrorKind::MissingPackageId)?
    } else {
      identity_package_registry()
        .await
        .package_id(network.as_str())
        .expect("package id for official networks is tracked by this library")
    };

    Ok(Self {
      iota_client,
      package_id,
      network,
    })
  }

  /// Sets the migration registry ID for the current network.
  /// # Notes
  /// This is only needed when automatic retrieval of MigrationRegistry's ID fails.
  pub fn set_migration_registry_id(&mut self, id: ObjectId) {
    crate::rebased::migration::set_migration_registry_id(self.network.as_chain_id(), id);
  }

  /// Queries an [`IotaDocument`] DID Document through its `did`.
  pub async fn resolve_did(&self, did: &IotaDID) -> Result<IotaDocument, Error> {
    // Make sure `did` references a DID Document on the network
    // this client is connected to.
    let did_network = did.network_str();
    let client_network = self.network.as_ref();
    if did_network != client_network && did_network != self.chain_id() {
      return Err(Error::DIDResolutionError(format!(
        "provided DID `{did}` \
        references a DID Document on network `{did_network}`, \
        but this client is connected to network `{client_network}`"
      )));
    }
    let identity = self.get_identity(did.to_object_id()).await?;
    let did_doc = identity.did_document(self.network())?;

    match identity {
      Identity::FullFledged(identity) if identity.has_deleted_did() => {
        Err(Error::DIDResolutionError(format!("could not find DID Document {did}")))
      }
      _ => Ok(did_doc),
    }
  }

  /// Resolves an [`Identity`] from its ID `object_id`.
  pub async fn get_identity(&self, object_id: ObjectId) -> Result<Identity, Error> {
    // spawn all checks
    cfg_if::cfg_if! {
      // Unfortunately the compiler runs into lifetime problems if we try to use a 'type ='
      // instead of the below ugly platform specific code
      if #[cfg(feature = "send-sync")] {
        let all_futures = FuturesUnordered::<Pin<Box<dyn Future<Output = Result<Option<Identity>, Error>> + Send>>>::new();
      } else {
        let all_futures = FuturesUnordered::<Pin<Box<dyn Future<Output = Result<Option<Identity>, Error>>>>>::new();
      }
    }
    all_futures.push(Box::pin(resolve_new(self, object_id)));
    all_futures.push(Box::pin(resolve_migrated(self, object_id)));
    all_futures.push(Box::pin(resolve_unmigrated(self, object_id)));

    all_futures
      .filter_map(|res| Box::pin(async move { res.ok().flatten() }))
      .next()
      .await
      .ok_or_else(|| Error::DIDResolutionError(format!("could not find DID document for {object_id}")))
  }

  /// Returns a stream yielding the unique DIDs the given address can access as a controller.
  /// # Notes
  /// This is a streaming version of [dids_controlled_by](Self::dids_controlled_by).
  /// # Errors
  /// This stream might return a [QueryControlledDidsError] when the underlying RPC call fails.
  /// When an error occurs, the stream might successfully yield a value if polled again, depending
  /// on the actual RPC error.
  /// [QueryControlledDidsError]'s source can be downcasted to [SDK's Error](iota_interaction::error::Error).
  /// # Example
  /// ```ignore
  /// # use std::pin::pin;
  /// # use identity_iota_core::rebased::client::IdentityClientReadOnly;
  /// # use identity_iota_core::IotaDID;
  /// # use iota_sdk::IotaClientBuilder;
  /// # use futures::{Stream, StreamExt};
  /// #
  /// # #[tokio::main]
  /// # async fn main() -> anyhow::Result<()> {
  /// # let iota_client = IotaClientBuilder::default().build_testnet().await?;
  /// # let identity_client = IdentityClientReadOnly::new(iota_client).await?;
  /// #
  /// let address = "0x666638f5118b8f894c4e60052f9bc47d6fcfb04fdb990c9afbb988848b79c475".parse()?;
  /// let mut controlled_dids = pin!(identity_client.streamed_dids_controlled_by(address));
  /// assert_eq!(
  ///   controlled_dids.next().await.unwrap()?,
  ///   IotaDID::parse(
  ///     "did:iota:testnet:0x052cfb920024f7a640dc17f7f44c6042ea0038d26972c2cff5c7ba31c82fbb08"
  ///   )?,
  /// );
  /// # Ok(())
  /// # }
  /// ```
  pub(crate) fn streamed_dids_controlled_by(
    &self,
    address: Address,
  ) -> impl Stream<Item = Result<IotaDID, QueryControlledDidsError>> + use<'_> {
    self.objects_for_address::<ControllerToken>(address, None).map(|res| {
      res
        .map(|token| IotaDID::from_object_id(token.controller_of(), self.network))
        .map_err(|e| QueryControlledDidsError {
          address,
          source: e.into(),
        })
    })
  }

  /// Returns the list of **all** unique DIDs the given address has access to as a controller.
  /// # Notes
  /// For a streaming version of this API see [dids_controlled_by_streamed](Self::dids_controlled_by_streamed).
  /// # Errors
  /// This method might return a [QueryControlledDidsError] when the underlying RPC call fails.
  /// [QueryControlledDidsError]'s source can be downcasted to [SDK's Error](iota_interaction::error::Error)
  /// in order to check whether calling this method again might return a successful result.
  /// # Example
  /// ```
  /// # use identity_iota_core::rebased::client::IdentityClientReadOnly;
  /// # use identity_iota_core::IotaDID;
  /// # use iota_sdk::IotaClientBuilder;
  /// #
  /// # #[tokio::main]
  /// # async fn main() -> anyhow::Result<()> {
  /// # let iota_client = IotaClientBuilder::default().build_testnet().await?;
  /// # let identity_client = IdentityClientReadOnly::new(iota_client).await?;
  /// #
  /// let address = "0x666638f5118b8f894c4e60052f9bc47d6fcfb04fdb990c9afbb988848b79c475".parse()?;
  /// let controlled_dids = identity_client.dids_controlled_by(address).await?;
  /// assert_eq!(
  ///   controlled_dids,
  ///   vec![IotaDID::parse(
  ///     "did:iota:testnet:0x052cfb920024f7a640dc17f7f44c6042ea0038d26972c2cff5c7ba31c82fbb08"
  ///   )?]
  /// );
  /// # Ok(())
  /// # }
  /// ```
  pub async fn dids_controlled_by(&self, address: Address) -> Result<Vec<IotaDID>, QueryControlledDidsError> {
    self.streamed_dids_controlled_by(address).try_collect().await
  }
}

/// Error that might occur when querying an address for its controlled DIDs.
#[derive(Debug, thiserror::Error)]
#[error("failed to query the DIDs controlled by address `{address}`")]
#[non_exhaustive]
pub struct QueryControlledDidsError {
  /// The queried address.
  pub address: Address,
  source: Box<dyn std::error::Error + Send + Sync>,
}

async fn get_network(iota_client: &IotaClient) -> Result<Network, IotaClientError> {
  Ok(
    iota_client
      .chain_id()
      .await?
      .parse()
      .expect("a successful call to chain_id returns a valid Network"),
  )
}

async fn resolve_new(client: &IdentityClientReadOnly, object_id: ObjectId) -> Result<Option<Identity>, Error> {
  let onchain_identity = get_identity(client, object_id).await.map_err(|err| {
    Error::DIDResolutionError(format!(
      "could not get identity document for object id {object_id}; {err}"
    ))
  })?;
  Ok(onchain_identity.map(Identity::FullFledged))
}

async fn resolve_migrated(client: &IdentityClientReadOnly, object_id: ObjectId) -> Result<Option<Identity>, Error> {
  let onchain_identity = lookup(client, object_id).await.map_err(|err| {
    Error::DIDResolutionError(format!(
      "failed to look up object_id {object_id} in migration registry; {err}"
    ))
  })?;
  let Some(mut onchain_identity) = onchain_identity else {
    return Ok(None);
  };
  let queried_did = IotaDID::from_object_id(object_id, client.network);
  let doc = onchain_identity.did_document_mut();
  let identity_did = doc.id().clone();
  // When querying a migrated identity we obtain a DID document with DID `identity_did` and the `alsoKnownAs`
  // property containing `queried_did`. Since we are resolving `queried_did`, lets replace in the document these
  // values. `queried_id` becomes the DID Document ID.
  *doc.core_document_mut().id_mut_unchecked() = queried_did.clone().into();
  // The DID Document `alsoKnownAs` property is cleaned of its `queried_did` entry,
  // which gets replaced by `identity_did`.
  doc
    .also_known_as_mut()
    .replace::<Url>(&queried_did.into_url().into(), identity_did.into_url().into());

  Ok(Some(Identity::FullFledged(onchain_identity)))
}

async fn resolve_unmigrated(client: &IdentityClientReadOnly, object_id: ObjectId) -> Result<Option<Identity>, Error> {
  let unmigrated_alias = get_alias(client, object_id)
    .await
    .map_err(|err| Error::DIDResolutionError(format!("could not query for object id {object_id}; {err}")))?;
  Ok(unmigrated_alias.map(Identity::Legacy))
}

/// The error that results from a failed attempt at creating an [IdentityClient]
/// from a given [IotaClient].
#[derive(Debug, thiserror::Error)]
#[error("failed to create an 'IdentityClient' from the given 'IotaClient'")]
#[non_exhaustive]
pub struct FromIotaClientError {
  /// Type of failure for this error.
  #[source]
  pub kind: FromIotaClientErrorKind,
}

/// Types of failure for [FromIotaClientError].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FromIotaClientErrorKind {
  /// A package ID is required, but was not supplied.
  #[error("an IOTA Identity package ID must be supplied when connecting to an unofficial IOTA network")]
  MissingPackageId,
  /// Network ID resolution through an RPC call failed.
  #[error("failed to resolve the network the given client is connected to")]
  NetworkResolution(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[cfg(test)]
mod tests {
  use crate::IotaDID;

  use super::IdentityClientReadOnly;
  use iota_sdk::IotaClientBuilder;
  use product_core::network::Network;

  #[tokio::test]
  async fn resolution_of_a_did_for_a_different_network_fails() -> anyhow::Result<()> {
    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    let identity_client = IdentityClientReadOnly::new(iota_client).await?;

    let did = IotaDID::new(&[1; 32], Network::Devnet);
    let error = identity_client.resolve_did(&did).await.unwrap_err();

    assert!(matches!(error, crate::rebased::Error::DIDResolutionError(_)));

    Ok(())
  }
}
