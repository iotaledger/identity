// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result as FmtResult;
use core::ops::Deref;
use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::convert::SerdeInto;
use identity_core::crypto::KeyPair;
use identity_core::crypto::SecretKey;
use identity_core::crypto::SetSignature;
use identity_core::crypto::Signature;
use identity_core::crypto::TrySignature;
use identity_core::crypto::TrySignatureMut;
use identity_did::did::DID;
use identity_did::document::Document;
use identity_did::verifiable::Properties as VerifiableProperties;
use identity_did::verification::MethodScope;
use identity_did::verification::MethodType;
use identity_did::verification::MethodWrap;
use serde::Serialize;

use crate::client::Client;
use crate::client::Network;
use crate::did::DocumentDiff;
use crate::did::IotaDID;
use crate::did::IotaDocumentBuilder;
use crate::did::Properties as BaseProperties;
use crate::error::Error;
use crate::error::Result;
use crate::tangle::MessageId;
use crate::tangle::TangleRef;
use crate::utils::utf8_to_trytes;

const AUTH_QUERY: (usize, MethodScope) = (0, MethodScope::Authentication);

const ERR_AMMF: &str = "Authentication Method Missing Fragment";
const ERR_AMIM: &str = "Authentication Method Id Mismatch";

type Properties = VerifiableProperties<BaseProperties>;
type __Document = Document<Properties, Object, ()>;

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "Document", into = "__Document")]
pub struct IotaDocument {
  document: __Document,
  message_id: MessageId,
}

impl IotaDocument {
  pub fn generate_ed25519<'a, 'b, T, U>(tag: &str, network: T, shard: U) -> Result<(Self, KeyPair)>
  where
    T: Into<Option<&'a str>>,
    U: Into<Option<&'b str>>,
  {
    let mut builder: IotaDocumentBuilder = IotaDocumentBuilder::new()
      .authentication_tag(tag)
      .authentication_type(MethodType::Ed25519VerificationKey2018);

    if let Some(value) = network.into() {
      builder = builder.did_network(value);
    }

    if let Some(value) = shard.into() {
      builder = builder.did_shard(value);
    }

    builder.build()
  }

  /// Converts a generic DID `Document` to an `IotaDocument`.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the document is not a valid `IotaDocument`.
  pub fn try_from_document(document: Document) -> Result<Self> {
    let did: &IotaDID = IotaDID::try_from_borrowed(document.id())?;
    let key: &DID = document.try_resolve(AUTH_QUERY)?.into_method().id();

    // Ensure the authentication method has an identifying fragment
    if key.fragment().is_none() {
      return Err(Error::InvalidDocument { error: ERR_AMMF });
    }

    // Ensure the authentication method DID matches the document DID
    if key.authority() != did.authority() {
      return Err(Error::InvalidDocument { error: ERR_AMIM });
    }

    Ok(Self {
      document: document.serde_into()?,
      message_id: MessageId::NONE,
    })
  }

  /// Creates a `IotaDocumentBuilder` to configure a new `IotaDocument`.
  ///
  /// This is the same as `IotaDocumentBuilder::new()`.
  pub fn builder() -> IotaDocumentBuilder {
    IotaDocumentBuilder::new()
  }

  /// Returns the DID document `id`.
  pub fn id(&self) -> &IotaDID {
    // SAFETY: We checked the validity of the DID Document ID in the
    // IotaDocument constructors; we don't provide mutable references so
    // the value cannot change with typical "safe" Rust.
    unsafe { IotaDID::new_unchecked_ref(self.document.id()) }
  }

  /// Returns the default authentication method of the DID document.
  pub fn authentication(&self) -> MethodWrap<'_> {
    self.document.resolve(AUTH_QUERY).unwrap()
  }

  /// Returns the key bytes of the default DID document authentication method.
  pub fn authentication_bytes(&self) -> Result<Vec<u8>> {
    self.document.try_resolve_bytes(AUTH_QUERY).map_err(Into::into)
  }

  /// Returns the method type of the default DID document authentication method.
  pub fn authentication_type(&self) -> MethodType {
    self.authentication().key_type()
  }

  /// Returns the timestamp of when the DID document was created.
  pub fn created(&self) -> Timestamp {
    self.document.properties().created
  }

  /// Sets the timestamp of when the DID document was created.
  pub fn set_created(&mut self, value: Timestamp) {
    self.document.properties_mut().created = value;
  }

  /// Sets the DID document "created" timestamp to `Timestamp::now`.
  pub fn set_created_now(&mut self) {
    self.set_created(Timestamp::now());
  }

  /// Returns the timestamp of the last DID document update.
  pub fn updated(&self) -> Timestamp {
    self.document.properties().updated
  }

  /// Sets the timestamp of the last DID document update.
  pub fn set_updated(&mut self, value: Timestamp) {
    self.document.properties_mut().updated = value;
  }

  /// Sets the DID document "updated" timestamp to `Timestamp::now`.
  pub fn set_updated_now(&mut self) {
    self.set_updated(Timestamp::now());
  }

  /// Returns the Tangle message id of the previous DID document, if any.
  pub fn previous_message_id(&self) -> &MessageId {
    &self.document.properties().previous_message_id
  }

  /// Sets the Tangle message id the previous DID document.
  pub fn set_previous_message_id<T>(&mut self, value: T)
  where
    T: Into<MessageId>,
  {
    self.document.properties_mut().previous_message_id = value.into();
  }

  /// Returns true if the `IotaDocument` is flagged as immutable.
  pub fn immutable(&self) -> bool {
    self.document.properties().immutable
  }

  /// Sets the value of the `immutable` flag.
  pub fn set_immutable(&mut self, value: bool) {
    self.document.properties_mut().immutable = value;
  }

  /// Returns a reference to the custom `IotaDocument` properties.
  pub fn properties(&self) -> &Object {
    &self.document.properties().properties
  }

  /// Returns a mutable reference to the custom `IotaDocument` properties.
  pub fn properties_mut(&mut self) -> &mut Object {
    &mut self.document.properties_mut().properties
  }

  /// Returns a reference to the underlying `Document`.
  pub fn as_document(&self) -> &__Document {
    &self.document
  }

  /// Returns a mutable reference to the underlying `Document`.
  ///
  /// # Safety
  ///
  /// This function is unsafe because it does not check that modifications
  /// made to the `Document` maintain a valid `IotaDocument`.
  ///
  /// If this constraint is violated, it may cause issues with future uses of
  /// the `IotaDocument`.
  pub unsafe fn as_document_mut(&mut self) -> &mut __Document {
    &mut self.document
  }

  /// Signs the DID document with the default authentication method.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, document
  /// serialization fails, or the signature operation fails.
  pub fn sign(&mut self, secret: &SecretKey) -> Result<()> {
    self.document.sign_this(AUTH_QUERY, secret.as_ref()).map_err(Into::into)
  }

  /// Verifies the signature of the DID document.
  ///
  /// Note: It is assumed that the signature was created using the default
  /// authentication method.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, document
  /// serialization fails, or the verification operation fails.
  pub fn verify(&self) -> Result<()> {
    self.document.verify_this().map_err(Into::into)
  }

  /// Signs the provided data with the default authentication method.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, document
  /// serialization fails, or the signature operation fails.
  pub fn sign_data<T>(&self, data: &mut T, secret: &SecretKey) -> Result<()>
  where
    T: Serialize + SetSignature,
  {
    self.document.sign_that(data, AUTH_QUERY, secret).map_err(Into::into)
  }

  /// Verfies the signature of the provided data.
  ///
  /// Note: It is assumed that the signature was created using the default
  /// authentication method.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, document
  /// serialization fails, or the verification operation fails.
  pub fn verify_data<T>(&self, data: &T) -> Result<()>
  where
    T: Serialize + TrySignature,
  {
    // FIXME: Merkle Key Collection
    self.document.verify_that(data, ()).map_err(Into::into)
  }

  /// Creates a `DocumentDiff` representing the changes between `self` and `other`.
  ///
  /// The returned `DocumentDiff` will have a digital signature created using the
  /// default authentication method and `secret`.
  ///
  /// # Errors
  ///
  /// Fails if the diff operation or signature operation fails.
  pub fn diff(&self, other: &Self, secret: &SecretKey, previous_message_id: MessageId) -> Result<DocumentDiff> {
    let mut diff: DocumentDiff = DocumentDiff::new(self, other, previous_message_id)?;

    self.sign_data(&mut diff, secret)?;

    Ok(diff)
  }

  /// Verifies a `DocumentDiff` signature and merges the changes into `self`.
  ///
  /// If merging fails `self` remains unmodified, otherwise `self` represents
  /// the merged document state.
  ///
  /// # Errors
  ///
  /// Fails if the merge operation or signature operation fails.
  pub fn merge(&mut self, diff: &DocumentDiff) -> Result<()> {
    self.verify_data(diff)?;

    *self = diff.merge(self)?;

    Ok(())
  }

  /// Publishes the `IotaDocument` to the Tangle using a default `Client`.
  pub async fn publish(&mut self) -> Result<()> {
    let network: Network = Network::from_name(self.id().network());
    let client: Client = Client::from_network(network)?;

    self.publish_with_client(&client).await
  }

  /// Publishes the `IotaDocument` to the Tangle using the provided `Client`.
  pub async fn publish_with_client(&mut self, client: &Client) -> Result<()> {
    let transaction: _ = client.publish_document(self).await?;
    let message_id: String = client.transaction_hash(&transaction);

    self.set_message_id(message_id.into());

    Ok(())
  }

  /// Returns the Tangle address of the DID diff chain.
  pub fn diff_address(message_id: &MessageId) -> Result<String> {
    if message_id.is_none() {
      return Err(Error::InvalidDocument {
        error: "Invalid Message Id",
      });
    }

    let hash: String = IotaDID::encode_key(message_id.as_str().as_bytes());

    let mut trytes: String = utf8_to_trytes(&hash);
    trytes.truncate(iota_constants::HASH_TRYTES_SIZE);
    Ok(trytes)
  }
}

impl Display for IotaDocument {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    Display::fmt(&self.document, f)
  }
}

impl Debug for IotaDocument {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    Debug::fmt(&self.document, f)
  }
}

impl Deref for IotaDocument {
  type Target = __Document;

  fn deref(&self) -> &Self::Target {
    &self.document
  }
}

impl PartialEq<__Document> for IotaDocument {
  fn eq(&self, other: &__Document) -> bool {
    self.document.eq(other)
  }
}

impl From<__Document> for IotaDocument {
  fn from(other: __Document) -> Self {
    Self {
      document: other,
      message_id: MessageId::NONE,
    }
  }
}

impl From<IotaDocument> for __Document {
  fn from(other: IotaDocument) -> Self {
    other.document
  }
}

impl TryFrom<Document> for IotaDocument {
  type Error = Error;

  fn try_from(other: Document) -> Result<Self, Self::Error> {
    Self::try_from_document(other)
  }
}

impl TangleRef for IotaDocument {
  fn message_id(&self) -> &MessageId {
    &self.message_id
  }

  fn set_message_id(&mut self, message_id: MessageId) {
    self.message_id = message_id;
  }

  fn previous_message_id(&self) -> &MessageId {
    IotaDocument::previous_message_id(self)
  }

  fn set_previous_message_id(&mut self, message_id: MessageId) {
    IotaDocument::set_previous_message_id(self, message_id)
  }
}

impl TrySignature for IotaDocument {
  fn signature(&self) -> Option<&Signature> {
    self.document.proof()
  }
}

impl TrySignatureMut for IotaDocument {
  fn signature_mut(&mut self) -> Option<&mut Signature> {
    self.document.proof_mut()
  }
}

impl SetSignature for IotaDocument {
  fn set_signature(&mut self, signature: Signature) {
    self.document.set_proof(signature)
  }
}
