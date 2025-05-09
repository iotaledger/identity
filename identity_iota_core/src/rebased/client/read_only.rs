// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::str::FromStr;

use crate::rebased::iota;
use crate::rebased::iota::package::Env;
use crate::rebased::iota::package::Metadata;
use crate::rebased::iota::package::PackageRegistry;
use crate::rebased::iota::package::MAINNET_CHAIN_ID;
use crate::IotaDID;
use crate::IotaDocument;
use crate::NetworkName;

use futures::stream::FuturesUnordered;
use identity_iota_interaction::IotaClientTrait;

use crate::iota_interaction_adapter::IotaClientAdapter;
use crate::rebased::migration::get_alias;
use crate::rebased::migration::get_identity;
use crate::rebased::migration::lookup;
use crate::rebased::migration::Identity;
use crate::rebased::Error;
use futures::StreamExt as _;
use identity_core::common::Url;
use identity_did::DID;

use identity_iota_interaction::types::base_types::ObjectID;

#[cfg(not(target_arch = "wasm32"))]
use identity_iota_interaction::IotaClient;

#[cfg(target_arch = "wasm32")]
use iota_interaction_ts::bindings::WasmIotaClient;

use super::CoreClientReadOnly;

/// An [`IotaClient`] enriched with identity-related
/// functionalities.
#[derive(Clone)]
pub struct IdentityClientReadOnly {
  iota_client: IotaClientAdapter,
  iota_identity_pkg_id: ObjectID,
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
  pub const fn package_id(&self) -> ObjectID {
    self.iota_identity_pkg_id
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
    let (network, iota_identity_pkg_id) = {
      let package_registry = iota::package::identity_package_registry().await;
      let package_id = package_registry
        .package_id(&network)
        .ok_or_else(|| {
        Error::InvalidConfig(format!(
          "no information for a published `iota_identity` package on network {network}; try to use `IdentityClientReadOnly::new_with_package_id`"
        ))
      })?;
      let network = match chain_id.as_str() {
        // Replace Mainnet's name with "iota".
        MAINNET_CHAIN_ID => NetworkName::try_from("iota").expect("valid network name"),
        _ => package_registry
          .chain_alias(&chain_id)
          .and_then(|alias| NetworkName::try_from(alias).ok())
          .unwrap_or(network),
      };

      (network, package_id)
    };
    Ok(IdentityClientReadOnly {
      iota_client,
      iota_identity_pkg_id,
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

    // Use the passed pkg_id to add a new env or override the information of an existing one.
    {
      let mut registry = iota::package::identity_package_registry_mut().await;
      registry.insert_env(Env::new(network.as_ref()), Metadata::from_package_id(package_id));
    }

    Self::new_internal(client, network).await
  }

  /// Attempts to create a new [`IdentityClientReadOnly`] from the given IOTA client
  /// and IotaIdentity package's Move.lock file.
  pub async fn new_with_move_lock(
    #[cfg(target_arch = "wasm32")] iota_client: WasmIotaClient,
    #[cfg(not(target_arch = "wasm32"))] iota_client: IotaClient,
    move_lock: &str,
  ) -> Result<Self, Error> {
    let client = IotaClientAdapter::new(iota_client);
    let network = network_id(&client).await?;

    let custom_registry = PackageRegistry::from_move_lock_content(move_lock)?;
    // Update the package's registry with the information coming from the given Move.lock.
    {
      let mut registry = iota::package::identity_package_registry_mut().await;
      registry.join(custom_registry);
    }

    Self::new_internal(client, network).await
  }

  /// Sets the migration registry ID for the current network.
  /// # Notes
  /// This is only needed when automatic retrival of MigrationRegistry's ID fails.
  pub fn set_migration_registry_id(&mut self, id: ObjectID) {
    crate::rebased::migration::set_migration_registry_id(&self.chain_id, id);
  }

  /// Queries an [`IotaDocument`] DID Document through its `did`.
  pub async fn resolve_did(&self, did: &IotaDID) -> Result<IotaDocument, Error> {
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
    .map_err(|err| Error::DIDResolutionError(format!("could  no query for object id {object_id}; {err}")))?;
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

#[async_trait::async_trait]
impl CoreClientReadOnly for IdentityClientReadOnly {
  fn package_id(&self) -> ObjectID {
    self.iota_identity_pkg_id
  }

  fn network_name(&self) -> &NetworkName {
    &self.network
  }

  fn client_adapter(&self) -> &IotaClientAdapter {
    &self.iota_client
  }
}
