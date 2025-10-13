// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::collections::VecDeque;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::str::FromStr;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use futures::Stream;
use futures::StreamExt as _;
use futures::TryStreamExt as _;
use identity_core::common::Url;
use identity_did::DID;
use iota_interaction::move_types::language_storage::StructTag;
use iota_interaction::rpc_types::IotaObjectDataFilter;
use iota_interaction::rpc_types::IotaObjectDataOptions;
use iota_interaction::rpc_types::IotaObjectResponseQuery;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::TypeTag;
use iota_interaction::IotaClientTrait;
use iota_interaction::MoveType;
use product_common::core_client::CoreClientReadOnly;
use product_common::network_name::NetworkName;

use crate::iota_interaction_adapter::IotaClientAdapter;
use crate::rebased::iota;
use crate::rebased::migration::get_alias;
use crate::rebased::migration::get_identity;
use crate::rebased::migration::lookup;
use crate::rebased::migration::ControllerCap;
use crate::rebased::migration::ControllerToken;
use crate::rebased::migration::DelegationToken;
use crate::rebased::migration::Identity;
use crate::rebased::Error;
use crate::IotaDID;
use crate::IotaDocument;

#[cfg(not(target_arch = "wasm32"))]
use iota_interaction::IotaClient;

#[cfg(target_arch = "wasm32")]
use iota_interaction_ts::bindings::WasmIotaClient;

/// An [`IotaClient`] enriched with identity-related
/// functionalities.
#[derive(Clone)]
pub struct IdentityClientReadOnly {
  iota_client: IotaClientAdapter,
  package_history: Vec<ObjectID>,
  network: NetworkName,
  chain_id: String,
}

impl Deref for IdentityClientReadOnly {
  type Target = IotaClientAdapter;
  fn deref(&self) -> &Self::Target {
    &self.iota_client
  }
}

impl IdentityClientReadOnly {
  /// Returns `iota_identity`'s package ID.
  /// The ID of the packages depends on the network
  /// the client is connected to.
  pub fn package_id(&self) -> ObjectID {
    *self
      .package_history
      .last()
      .expect("at least one package exists in history")
  }

  /// Returns the name of the network the client is
  /// currently connected to.
  pub const fn network(&self) -> &NetworkName {
    &self.network
  }

  /// Returns the chain identifier for the network this client is connected to.
  /// This method differs from [IdentityClientReadOnly::network] as it doesn't
  /// return the human-readable network ID when available.
  pub fn chain_id(&self) -> &str {
    &self.chain_id
  }

  /// Attempts to create a new [`IdentityClientReadOnly`] from a given [`IotaClient`].
  ///
  /// # Failures
  /// This function fails if the provided `iota_client` is connected to an unrecognized
  /// network.
  ///
  /// # Notes
  /// When trying to connect to a local or unofficial network, prefer using
  /// [`IdentityClientReadOnly::new_with_pkg_id`].
  pub async fn new(
    #[cfg(target_arch = "wasm32")] iota_client: WasmIotaClient,
    #[cfg(not(target_arch = "wasm32"))] iota_client: IotaClient,
  ) -> Result<Self, Error> {
    let client = IotaClientAdapter::new(iota_client);
    let network = network_id(&client).await?;
    Self::new_internal(client, network).await
  }

  async fn new_internal(iota_client: IotaClientAdapter, network: NetworkName) -> Result<Self, Error> {
    let chain_id = network.as_ref().to_string();
    let (network, package_history) = {
      let package_registry = iota::package::identity_package_registry().await;
      let package_history = package_registry
        .history(&network)
        .ok_or_else(|| {
        Error::InvalidConfig(format!(
          "no information for a published `iota_identity` package on network {network}; try to use `IdentityClientReadOnly::new_with_package_id`"
        ))
      })?
      .to_vec();
      let network = package_registry
        .chain_alias(&chain_id)
        .and_then(|alias| NetworkName::try_from(alias).ok())
        .unwrap_or(network);

      (network, package_history)
    };
    Ok(IdentityClientReadOnly {
      iota_client,
      package_history,
      network,
      chain_id,
    })
  }

  /// Attempts to create a new [`IdentityClientReadOnly`] from the given IOTA client
  /// and the ID of the IotaIdentity package published on the network the client is
  /// connected to.
  pub async fn new_with_pkg_id(
    #[cfg(target_arch = "wasm32")] iota_client: WasmIotaClient,
    #[cfg(not(target_arch = "wasm32"))] iota_client: IotaClient,
    package_id: ObjectID,
  ) -> Result<Self, Error> {
    let client = IotaClientAdapter::new(iota_client);
    let network = network_id(&client).await?;

    // Use the passed pkg_id to force it at the end of the list or create a new env.
    {
      let mut registry = iota::package::identity_package_registry_mut().await;
      registry.insert_new_package_version(&network, package_id);
    }

    Self::new_internal(client, network).await
  }

  /// Sets the migration registry ID for the current network.
  /// # Notes
  /// This is only needed when automatic retrieval of MigrationRegistry's ID fails.
  pub fn set_migration_registry_id(&mut self, id: ObjectID) {
    crate::rebased::migration::set_migration_registry_id(&self.chain_id, id);
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
    let identity = self.get_identity(get_object_id_from_did(did)?).await?;
    let did_doc = identity.did_document(self.network())?;

    match identity {
      Identity::FullFledged(identity) if identity.has_deleted_did() => {
        Err(Error::DIDResolutionError(format!("could not find DID Document {did}")))
      }
      _ => Ok(did_doc),
    }
  }

  /// Resolves an [`Identity`] from its ID `object_id`.
  pub async fn get_identity(&self, object_id: ObjectID) -> Result<Identity, Error> {
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
    address: IotaAddress,
  ) -> impl Stream<Item = Result<IotaDID, QueryControlledDidsError>> + use<'_> {
    // Create a filter that matches objects of type ControllerCap or DelegationToken with any package ID in history.
    let all_struct_tags = history_type_tags::<ControllerCap>(&self.package_history)
      .chain(history_type_tags::<DelegationToken>(&self.package_history))
      .map(IotaObjectDataFilter::StructType)
      .collect();
    let query = IotaObjectResponseQuery::new(
      Some(IotaObjectDataFilter::MatchAny(all_struct_tags)),
      Some(IotaObjectDataOptions::default().with_bcs()),
    );

    // Create a stream that returns unique DIDs.
    async_stream::try_stream! {
      let mut page = self
      .client_adapter()
      .read_api()
      .get_owned_objects(address, Some(query.clone()), None, None)
      .await
      .map_err(|e| QueryControlledDidsError { address, source: e.into() })?;
      let mut identities = HashSet::new();

      loop {
        // Return data from the front of the current page until it is exhausted.
        let mut data = VecDeque::from(std::mem::take(&mut page.data));
        if let Some(obj_data) = data.pop_front() {
          let bcs_content = obj_data.move_object_bcs().expect("bcs was requested").as_slice();
          let token = bcs::from_bytes::<ControllerCap>(bcs_content)
            .map(ControllerToken::Controller)
            .or_else(|_| bcs::from_bytes::<DelegationToken>(bcs_content).map(ControllerToken::Delegate))
            .expect("object is either a valid ControllerCap or DelegationToken");
          if !identities.insert(token.controller_of()) {
            continue;
          }
          yield IotaDID::new(&token.controller_of().into_bytes(), &self.network);
        } else if page.has_next_page && page.next_cursor.is_some() {
          // The page's content was exhausted, but a new page can be fetched.
          page = self
            .client_adapter()
            .read_api()
            .get_owned_objects(address, Some(query.clone()), page.next_cursor, None)
            .await
            .map_err(|e| QueryControlledDidsError { address, source: e.into() })?;
        } else {
          // End of content: current page is exhausted and no more pages are available.
          break;
        }
      }
    }
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
  pub async fn dids_controlled_by(&self, address: IotaAddress) -> Result<Vec<IotaDID>, QueryControlledDidsError> {
    self.streamed_dids_controlled_by(address).try_collect().await
  }
}

/// Error that might occur when querying an address for its controlled DIDs.
#[derive(Debug, thiserror::Error)]
#[error("failed to query the DIDs controlled by address `{address}`")]
#[non_exhaustive]
pub struct QueryControlledDidsError {
  /// The queried address.
  pub address: IotaAddress,
  source: Box<dyn std::error::Error + Send + Sync>,
}

/// Returns the list of all type ID for a given move type where the package ID is taken from history.
/// # Panics
/// If type parameter T's move_type returns a TypeTag that is not TypeTag::Struct.
fn history_type_tags<T: MoveType>(history: &[ObjectID]) -> impl Iterator<Item = StructTag> + use<'_, T> {
  history.iter().copied().map(|pkg| {
    let TypeTag::Struct(tag) = T::move_type(pkg) else {
      panic!("T must be a Move struct")
    };
    *tag
  })
}

async fn network_id(iota_client: &IotaClientAdapter) -> Result<NetworkName, Error> {
  let network_id = iota_client
    .read_api()
    .get_chain_identifier()
    .await
    .map_err(|e| Error::RpcError(e.to_string()))?;
  Ok(network_id.try_into().expect("chain ID is a valid network name"))
}

async fn resolve_new(client: &IdentityClientReadOnly, object_id: ObjectID) -> Result<Option<Identity>, Error> {
  let onchain_identity = get_identity(client, object_id).await.map_err(|err| {
    Error::DIDResolutionError(format!(
      "could not get identity document for object id {object_id}; {err}"
    ))
  })?;
  Ok(onchain_identity.map(Identity::FullFledged))
}

async fn resolve_migrated(client: &IdentityClientReadOnly, object_id: ObjectID) -> Result<Option<Identity>, Error> {
  let onchain_identity = lookup(client, object_id).await.map_err(|err| {
    Error::DIDResolutionError(format!(
      "failed to look up object_id {object_id} in migration registry; {err}"
    ))
  })?;
  let Some(mut onchain_identity) = onchain_identity else {
    return Ok(None);
  };
  let object_id_str = object_id.to_string();
  let queried_did = IotaDID::from_object_id(&object_id_str, &client.network);
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

async fn resolve_unmigrated(client: &IdentityClientReadOnly, object_id: ObjectID) -> Result<Option<Identity>, Error> {
  let unmigrated_alias = get_alias(client, object_id)
    .await
    .map_err(|err| Error::DIDResolutionError(format!("could not query for object id {object_id}; {err}")))?;
  Ok(unmigrated_alias.map(Identity::Legacy))
}

/// Extracts the object ID from the given `IotaDID`.
///
/// # Arguments
///
/// * `did` - A reference to the `IotaDID` to be converted.
pub fn get_object_id_from_did(did: &IotaDID) -> Result<ObjectID, Error> {
  ObjectID::from_str(did.tag_str())
    .map_err(|err| Error::DIDResolutionError(format!("could not parse object id from did {did}; {err}")))
}

#[cfg_attr(feature = "send-sync", async_trait)]
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
impl CoreClientReadOnly for IdentityClientReadOnly {
  fn package_id(&self) -> ObjectID {
    self.package_id()
  }

  fn network_name(&self) -> &NetworkName {
    &self.network
  }

  fn client_adapter(&self) -> &IotaClientAdapter {
    &self.iota_client
  }

  fn package_history(&self) -> Vec<ObjectID> {
    self.package_history.clone()
  }
}

#[cfg(test)]
mod tests {
  use crate::IotaDID;

  use super::IdentityClientReadOnly;
  use iota_sdk::IotaClientBuilder;

  #[tokio::test]
  async fn resolution_of_a_did_for_a_different_network_fails() -> anyhow::Result<()> {
    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    let identity_client = IdentityClientReadOnly::new(iota_client).await?;

    let did = IotaDID::new(&[1; 32], &"unknown".parse().unwrap());
    let error = identity_client.resolve_did(&did).await.unwrap_err();

    assert!(matches!(error, crate::rebased::Error::DIDResolutionError(_)));

    Ok(())
  }
}
