// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use crate::rebased::client::FromIotaClientError;
use crate::rebased::client::FromIotaClientErrorKind;
use crate::rebased::client::QueryControlledDidsError;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::migration::get_identity;
use crate::rebased::migration::get_identity_impl;
use crate::rebased::migration::ControllerToken;
use crate::rebased::migration::IdentityResolutionError;
use crate::rebased::migration::InsufficientControllerVotingPower;
use crate::rebased::migration::NotAController;
use crate::rebased::migration::OnChainIdentity;
use crate::IotaDID;
use crate::IotaDocument;
use crate::StateMetadataDocument;
use crate::StateMetadataEncoding;
use iota_sdk::graphql_client::Client as IotaClient;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::Owner;
use iota_sdk::types::TransactionEffects;
use product_core::move_type::MoveType;
use product_core::operation::Operation;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
use product_core::CLOCK_ADDRESS;
use secret_storage::iota::TransactionSigner;
use secret_storage::Signer;
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

use crate::rebased::assets::AuthenticatedAssetBuilder;
use crate::rebased::migration::Identity;
use crate::rebased::migration::IdentityBuilder;
use crate::rebased::Error;

use super::IdentityClientReadOnly;

/// Mirrored types from identity_storage::KeyId
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct KeyId(String);

impl KeyId {
  /// Creates a new key identifier from a string.
  pub fn new(id: impl Into<String>) -> Self {
    Self(id.into())
  }

  /// Returns string representation of the key id.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl std::fmt::Display for KeyId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl From<KeyId> for String {
  fn from(value: KeyId) -> Self {
    value.0
  }
}

/// A marker type indicating the absence of a signer.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct NoSigner;

/// A client for interacting with the IOTA Identity framework.
#[derive(Clone)]
pub struct IdentityClient<S = NoSigner> {
  /// [`IdentityClientReadOnly`] instance, used for read-only operations.
  pub(super) read_client: IdentityClientReadOnly,
  pub(super) signer: S,
}

impl<S> Deref for IdentityClient<S> {
  type Target = IdentityClientReadOnly;
  fn deref(&self) -> &Self::Target {
    &self.read_client
  }
}

impl IdentityClient<NoSigner> {
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
  /// # #[tokio::main]
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
    let read_only_client = if let Some(custom_package_id) = custom_package_id.into() {
      IdentityClientReadOnly::new_with_pkg_id(iota_client, custom_package_id).await
    } else {
      IdentityClientReadOnly::new(iota_client).await
    }
    .map_err(|e| match e {
      Error::InvalidConfig(_) => FromIotaClientErrorKind::MissingPackageId,
      Error::RpcError(msg) => FromIotaClientErrorKind::NetworkResolution(msg.into()),
      _ => unreachable!("'IdentityClientReadOnly::new' has been changed without updating error handling in 'IdentityClient::from_iota_client'"),
    })
    .map_err(|kind| FromIotaClientError { kind })?;

    Ok(Self {
      read_client: read_only_client,
      signer: NoSigner,
    })
  }
}

impl<S> IdentityClient<S>
where
  S: TransactionSigner,
{
  /// Creates a new [`IdentityClient`].
  #[deprecated(since = "1.9.0", note = "Use `IdentityClient::from_iota_client` instead")]
  pub async fn new(client: IdentityClientReadOnly, signer: S) -> Result<Self, Error> {
    let public_key = signer
      .public_key()
      .await
      .map_err(|e| Error::InvalidKey(e.to_string()))?;

    Ok(Self {
      read_client: client,
      signer,
    })
  }

  /// Returns the [Address] wrapped by this client.
  #[inline(always)]
  pub fn address(&self) -> Address {
    self.signer.address()
  }

  /// Returns the list of **all** unique DIDs the address wrapped by this client can access as a controller.
  pub async fn controlled_dids(&self) -> Result<Vec<IotaDID>, QueryControlledDidsError> {
    self.dids_controlled_by(self.address()).await
  }
}

impl<S> IdentityClient<S> {
  /// Returns a new [`IdentityBuilder`] in order to build a new [`crate::rebased::migration::OnChainIdentity`].
  pub fn create_identity(&self, iota_document: IotaDocument) -> IdentityBuilder {
    IdentityBuilder::new(iota_document)
  }

  /// Returns an [Operation] to publish the given DID Document on-chain.
  pub fn publish_did_document(&self, document: IotaDocument) -> OperationBuilder<PublishDidDocument> {
    OperationBuilder::new(PublishDidDocument::new(document, self.sender_address()))
  }

  /// Returns a new [`IdentityBuilder`] in order to build a new [`crate::rebased::migration::OnChainIdentity`].
  pub fn create_authenticated_asset<T>(&self, content: T) -> AuthenticatedAssetBuilder<T>
  where
    T: MoveType + DeserializeOwned + Send + Sync + PartialEq,
  {
    AuthenticatedAssetBuilder::new(content)
  }

  /// Sets a new signer for this client.
  pub fn with_signer<NewS>(self, signer: NewS) -> Result<IdentityClient<NewS>, secret_storage::Error>
  where
    NewS: TransactionSigner,
  {
    Ok(IdentityClient {
      read_client: self.read_client,
      signer,
    })
  }

  /// Deactivates a DID document.
  pub async fn deactivate_did_output(&self, did: &IotaDID, gas_budget: u64) -> Result<(), Error> {
    let mut oci = if let Identity::FullFledged(value) = self.get_identity(did.to_object_id()).await? {
      value
    } else {
      return Err(Error::Identity("only new identities can be deactivated".to_string()));
    };

    let controller_token = oci.get_controller_token(self).await?.ok_or_else(|| {
      Error::Identity(format!(
        "address {} has no control over Identity {}",
        self.sender_address(),
        oci.id()
      ))
    })?;

    oci
      .deactivate_did(&controller_token)
      .finish(self)
      .await?
      .with_gas_budget(gas_budget)
      .build_and_execute(self)
      .await
      .map_err(|e| Error::TransactionUnexpectedResponse(e.to_string()))?;

    Ok(())
  }
}

impl<S> IdentityClient<S>
where
  S: TransactionSigner,
{
  /// Updates a DID Document.
  #[deprecated(note = "use publish_did_update instead")]
  pub async fn publish_did_document_update(
    &self,
    document: IotaDocument,
    gas_budget: u64,
  ) -> Result<IotaDocument, Error> {
    let mut oci = if let Identity::FullFledged(value) = self.get_identity(document.id().to_object_id()).await? {
      value
    } else {
      return Err(Error::Identity("only new identities can be updated".to_string()));
    };

    let controller_token = oci.get_controller_token(self).await?.ok_or_else(|| {
      Error::Identity(format!(
        "address {} has no control over Identity {}",
        self.sender_address(),
        oci.id()
      ))
    })?;

    oci
      .update_did_document(document.clone(), &controller_token)
      .finish(self)
      .await?
      .with_gas_budget(gas_budget)
      .build_and_execute(self)
      .await
      .map_err(|e| Error::TransactionUnexpectedResponse(e.to_string()))?;

    Ok(document)
  }

  /// A shorthand for
  /// [OnChainIdentity::update_did_document](crate::rebased::migration::OnChainIdentity::update_did_document)'s DID
  /// Document.
  ///
  /// This method makes the following assumptions:
  /// - The given `did_document` has already been published on-chain within an Identity.
  /// - This [IdentityClient] is a controller of the corresponding Identity with enough voting power to execute the
  ///   transaction without any other controller approval.
  pub async fn publish_did_update(
    &self,
    did_document: IotaDocument,
  ) -> Result<TransactionBuilder<ShorthandDidUpdate>, MakeUpdateDidDocTxError> {
    use MakeUpdateDidDocTxError as Error;
    use MakeUpdateDidDocTxErrorKind as ErrorKind;

    let make_err = |kind| Error {
      did_document: did_document.clone(),
      kind,
    };

    let identity_id = did_document.id().to_object_id();
    let identity = get_identity_impl(self, identity_id)
      .await
      .map_err(|e| make_err(e.into()))?;

    if identity.has_deleted_did() {
      return Err(make_err(ErrorKind::DeletedIdentityDocument));
    }

    let controller_token = identity
      .get_controller_token(self)
      .await
      .map_err(|e| make_err(ErrorKind::RpcError(e.into())))?
      .ok_or_else(|| {
        make_err(
          NotAController {
            address: self.address(),
            identity: did_document.id().clone(),
          }
          .into(),
        )
      })?;

    let vp = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("is a controller");
    let threshold = identity.threshold();
    if vp < threshold {
      return Err(make_err(
        InsufficientControllerVotingPower {
          controller_token_id: controller_token.controller_id(),
          controller_voting_power: vp,
          required: threshold,
        }
        .into(),
      ));
    }

    Ok(OperationBuilder::new(ShorthandDidUpdate {
      identity: RwLock::new(identity),
      controller_token,
      did_document,
    }))
  }
}

/// Publishes a new DID Document on-chain. An [`OnChainIdentity`](crate::rebased::migration::OnChainIdentity)
/// will be created to contain the provided document.
#[derive(Debug, Clone)]
pub struct PublishDidDocument {
  did_document: IotaDocument,
  controller: Address,
}

impl PublishDidDocument {
  /// Creates a new [PublishDidDocument] transaction.
  pub fn new(did_document: IotaDocument, controller: Address) -> Self {
    Self {
      did_document,
      controller,
    }
  }
}

impl Operation for PublishDidDocument {
  type Output = IotaDocument;
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    mut ptb: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    let package = identity_package_id(client.network()).await?;

    let clock = ptb.apply_argument(CLOCK_ADDRESS);
    let serialized_did_doc = StateMetadataDocument::from(self.did_document.clone())
      .pack(StateMetadataEncoding::Json)
      .map_err(|e| Error::DidDocSerialization(e.to_string()))?;

    let did_doc = ptb.pure(Some(serialized_did_doc));
    ptb.move_call(package, "identity", "new").arguments([did_doc, clock]);

    Ok(ptb)
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = tx_effects.status().error() {
      return Err(tx_error.into());
    }

    let target_did_bytes = StateMetadataDocument::from(self.did_document)
      .pack(StateMetadataEncoding::Json)
      .map_err(|e| Error::DidDocSerialization(e.to_string()))?;

    let is_target_identity = |identity: &OnChainIdentity| -> bool {
      let did_bytes = identity
        .multicontroller()
        .controlled_value()
        .as_deref()
        .unwrap_or_default();
      target_did_bytes == did_bytes && identity.threshold() == 1
    };

    let create_identity_candidates = tx_effects
      .as_v1()
      .changed_objects
      .iter()
      .filter(|obj| obj.id_operation.is_created() && obj.output_state.object_owner_opt().is_some_and(Owner::is_shared))
      .map(|obj| obj.object_id);

    let mut target_identity = None;
    for id in create_identity_candidates {
      let Some(identity) = get_identity(client, id).await? else {
        continue;
      };

      if is_target_identity(&identity) {
        target_identity = Some(identity);
      }
    }

    if let Some(identity) = target_identity {
      tx_effects
        .as_mut_v1()
        .changed_objects
        .retain(|obj| obj.object_id != identity.id().to_object_id());
      Ok(identity.did_doc)
    } else {
      Err(Error::TransactionUnexpectedResponse(
        "failed to find the correct identity in this transaction's effects".to_owned(),
      ))
    }
  }
}

/// The actual Transaction type returned by [IdentityClient::publish_did_update].
#[derive(Debug)]
pub struct ShorthandDidUpdate {
  identity: RwLock<OnChainIdentity>,
  controller_token: ControllerToken,
  did_document: IotaDocument,
}

impl Operation for ShorthandDidUpdate {
  type Error = Error;
  type Output = IotaDocument;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    tx_builder: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    todo!()
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    todo!()
  }
}

/// [IdentityClient::publish_did_update] error.
#[derive(Debug, thiserror::Error)]
#[error("failed to prepare transaction to update DID '{}'", did_document.id())]
#[non_exhaustive]
pub struct MakeUpdateDidDocTxError {
  /// The DID document that was being published.
  pub did_document: IotaDocument,
  /// Specific type of failure for this error.
  pub kind: MakeUpdateDidDocTxErrorKind,
}

/// Types of failure for [MakeUpdateDidDocTxError].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MakeUpdateDidDocTxErrorKind {
  /// Node RPC failure.
  #[error(transparent)]
  RpcError(Box<dyn std::error::Error + Send + Sync>),
  /// Failed to resolve the corresponding [OnChainIdentity].
  #[error(transparent)]
  IdentityResolution(#[from] IdentityResolutionError),
  /// The invoking client is not a controller of the given DID document.
  #[error(transparent)]
  NotAController(#[from] NotAController),
  /// The DID document has been deleted and cannot be updated.
  #[error("Identity's DID Document is deleted")]
  DeletedIdentityDocument,
  /// The invoking client is a controller but doesn't have enough voting power
  /// to perform the update.
  #[error(transparent)]
  InsufficientVotingPower(#[from] InsufficientControllerVotingPower),
}
