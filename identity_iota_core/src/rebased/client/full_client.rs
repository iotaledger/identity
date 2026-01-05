// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use crate::iota_interaction_adapter::IotaClientAdapter;
use crate::rebased::client::QueryControlledDidsError;
use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::migration::CreateIdentity;
use crate::IotaDID;
use crate::IotaDocument;
use crate::StateMetadataDocument;
use crate::StateMetadataEncoding;
use async_trait::async_trait;
use identity_verification::jwk::Jwk;
use iota_interaction::move_types::language_storage::StructTag;
use iota_interaction::rpc_types::IotaObjectData;
use iota_interaction::rpc_types::IotaObjectDataFilter;
use iota_interaction::rpc_types::IotaObjectResponseQuery;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectRef;
use iota_interaction::types::crypto::PublicKey;
use iota_interaction::types::transaction::ProgrammableTransaction;
use product_common::core_client::CoreClient;
use product_common::core_client::CoreClientReadOnly;
use product_common::network_name::NetworkName;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use secret_storage::Signer;
use serde::de::DeserializeOwned;
use tokio::sync::OnceCell;

use super::get_object_id_from_did;
use crate::rebased::assets::AuthenticatedAssetBuilder;
use crate::rebased::migration::Identity;
use crate::rebased::migration::IdentityBuilder;
use crate::rebased::Error;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::IotaClientTrait;
use iota_interaction::IotaKeySignature;
use iota_interaction::MoveType;
use iota_interaction::OptionalSync;

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

/// A client for interacting with the IOTA Identity framework.
#[derive(Clone)]
pub struct IdentityClient<S = ()> {
  /// [`IdentityClientReadOnly`] instance, used for read-only operations.
  pub(super) read_client: IdentityClientReadOnly,
  /// The public key of the client.
  /// # Safety
  /// `public_key` is always `Some` when `S: Signer<IotaKeySignature>`.
  /// Developers MUST uphold this invariant.
  pub(super) public_key: Option<PublicKey>,
  /// The signer of the client.
  pub(super) signer: S,
}

impl<S> Deref for IdentityClient<S> {
  type Target = IdentityClientReadOnly;
  fn deref(&self) -> &Self::Target {
    &self.read_client
  }
}

impl<S> IdentityClient<S>
where
  S: Signer<IotaKeySignature>,
{
  /// Create a new [`IdentityClient`].
  #[deprecated(since = "1.9.0", note = "Use IdentityClientBuilder instead")]
  pub async fn new(client: IdentityClientReadOnly, signer: S) -> Result<Self, Error> {
    let public_key = signer
      .public_key()
      .await
      .map_err(|e| Error::InvalidKey(e.to_string()))?;

    Ok(Self {
      public_key: Some(public_key),
      read_client: client,
      signer,
    })
  }

  /// Returns a reference to the [PublicKey] wrapped by this client.
  pub fn public_key(&self) -> &PublicKey {
    self.public_key.as_ref().expect("public_key is set")
  }

  /// Returns the [IotaAddress] wrapped by this client.
  #[inline(always)]
  pub fn address(&self) -> IotaAddress {
    IotaAddress::from(self.public_key())
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

  /// Returns a new [`IdentityBuilder`] in order to build a new [`crate::rebased::migration::OnChainIdentity`].
  pub fn create_authenticated_asset<T>(&self, content: T) -> AuthenticatedAssetBuilder<T>
  where
    T: MoveType + DeserializeOwned + Send + Sync + PartialEq,
  {
    AuthenticatedAssetBuilder::new(content)
  }
}

impl<S> IdentityClient<S>
where
  S: Signer<IotaKeySignature> + OptionalSync,
{
  /// Returns a [PublishDidDocument] transaction wrapped by a [TransactionBuilder].
  pub fn publish_did_document(&self, document: IotaDocument) -> TransactionBuilder<PublishDidDocument> {
    TransactionBuilder::new(PublishDidDocument::new(document, self.sender_address()))
  }

  // TODO: define what happens for (legacy|migrated|new) documents
  /// Updates a DID Document.
  pub async fn publish_did_document_update(
    &self,
    document: IotaDocument,
    gas_budget: u64,
  ) -> Result<IotaDocument, Error> {
    let mut oci =
      if let Identity::FullFledged(value) = self.get_identity(get_object_id_from_did(document.id())?).await? {
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

  /// Deactivates a DID document.
  pub async fn deactivate_did_output(&self, did: &IotaDID, gas_budget: u64) -> Result<(), Error> {
    let mut oci = if let Identity::FullFledged(value) = self.get_identity(get_object_id_from_did(did)?).await? {
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

  /// Query the objects owned by the address wrapped by this client to find the object of type `tag`
  /// and that satisfies `predicate`.
  pub async fn find_owned_ref<P>(&self, tag: StructTag, predicate: P) -> Result<Option<ObjectRef>, Error>
  where
    P: Fn(&IotaObjectData) -> bool,
  {
    let filter = IotaObjectResponseQuery::new_with_filter(IotaObjectDataFilter::StructType(tag));

    let mut cursor = None;
    loop {
      let mut page = self
        .read_api()
        .get_owned_objects(self.sender_address(), Some(filter.clone()), cursor, None)
        .await?;
      let obj_ref = std::mem::take(&mut page.data)
        .into_iter()
        .filter_map(|res| res.data)
        .find(|obj| predicate(obj))
        .map(|obj_data| obj_data.object_ref());
      cursor = page.next_cursor;

      if obj_ref.is_some() {
        return Ok(obj_ref);
      }
      if !page.has_next_page {
        break;
      }
    }

    Ok(None)
  }
}

#[cfg_attr(feature = "send-sync", async_trait)]
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
impl<S> CoreClientReadOnly for IdentityClient<S>
where
  S: OptionalSync,
{
  fn client_adapter(&self) -> &IotaClientAdapter {
    &self.read_client
  }

  fn package_id(&self) -> ObjectID {
    self.read_client.package_id()
  }

  fn package_history(&self) -> Vec<ObjectID> {
    self.read_client.package_history()
  }

  fn network_name(&self) -> &NetworkName {
    self.read_client.network()
  }
}

impl<S> CoreClient<S> for IdentityClient<S>
where
  S: Signer<IotaKeySignature> + OptionalSync,
{
  fn sender_address(&self) -> IotaAddress {
    IotaAddress::from(self.public_key())
  }

  fn signer(&self) -> &S {
    &self.signer
  }

  fn sender_public_key(&self) -> &PublicKey {
    self.public_key()
  }
}

/// Utility function that returns the key's bytes of a JWK encoded public ed25519 key.
pub fn get_sender_public_key(sender_public_jwk: &Jwk) -> Result<Vec<u8>, Error> {
  let public_key_base_64 = &sender_public_jwk
    .try_okp_params()
    .map_err(|err| Error::InvalidKey(format!("key not of type `Okp`; {err}")))?
    .x;

  identity_jose::jwu::decode_b64(public_key_base_64)
    .map_err(|err| Error::InvalidKey(format!("could not decode base64 public key; {err}")))
}

/// Publishes a new DID Document on-chain. An [`crate::rebased::migration::OnChainIdentity`] will be created to contain
/// the provided document.
#[derive(Debug, Clone)]
pub struct PublishDidDocument {
  did_document: IotaDocument,
  controller: IotaAddress,
  cached_ptb: OnceCell<ProgrammableTransaction>,
}

impl PublishDidDocument {
  /// Creates a new [PublishDidDocument] transaction.
  pub fn new(did_document: IotaDocument, controller: IotaAddress) -> Self {
    Self {
      did_document,
      controller,
      cached_ptb: OnceCell::new(),
    }
  }

  async fn make_ptb(&self, client: &impl CoreClientReadOnly) -> Result<ProgrammableTransaction, Error> {
    let package = identity_package_id(client).await?;
    let did_doc = StateMetadataDocument::from(self.did_document.clone())
      .pack(StateMetadataEncoding::Json)
      .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;

    let programmable_tx_bcs =
      move_calls::identity::new_with_controllers(Some(&did_doc), [(self.controller, 1, false)], 1, package).await?;
    Ok(bcs::from_bytes(&programmable_tx_bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl Transaction for PublishDidDocument {
  type Output = IotaDocument;
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let tx = {
      let builder = IdentityBuilder::new(self.did_document)
        .threshold(1)
        .controller(self.controller, 1);
      CreateIdentity::new(builder)
    };

    tx.apply(effects, client).await.map(IotaDocument::from)
  }
}
