// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use identity_iota::core::Object;
use identity_iota::core::OneOrMany;

use identity_iota::core::OrderedSet;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::Presentation;

use identity_iota::did::DIDUrl;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::StateMetadataEncoding;
use identity_iota::storage::key_storage::KeyType;
use identity_iota::storage::storage::JwkDocumentExt;
use identity_iota::storage::storage::JwsSignatureOptions;
use identity_iota::verification::jose::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_iota::verification::VerificationMethod;
use js_sys::Promise;
use product_common::network_name::NetworkName;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

use crate::common::ArrayService;
use crate::common::ArrayString;
use crate::common::ArrayVerificationMethod;
use crate::common::MapStringAny;
use crate::common::OptionOneOrManyString;
use crate::common::OptionTimestamp;
use crate::common::PromiseString;
use crate::common::PromiseVoid;
use crate::common::RecordStringAny;
use crate::common::UDIDUrlQuery;
use crate::common::UOneOrManyNumber;
use crate::common::WasmTimestamp;
use crate::credential::PromiseJpt;
use crate::credential::UnknownCredential;
use crate::credential::WasmCredential;
use crate::credential::WasmCredentialV2;
use crate::credential::WasmJpt;
use crate::credential::WasmJwpCredentialOptions;
use crate::credential::WasmJwpPresentationOptions;
use crate::credential::WasmJws;
use crate::credential::WasmJwt;
use crate::credential::WasmJwtVcV2;
use crate::credential::WasmPresentation;
use crate::did::CoreDocumentLock;
use crate::did::PromiseJws;
use crate::did::PromiseJwt;
use crate::did::WasmCoreDocument;
use crate::did::WasmDIDUrl;
use crate::did::WasmJwsVerificationOptions;
use crate::did::WasmService;
use crate::error::Result;
use crate::error::WasmResult;
use crate::iota::WasmIotaDID;
use crate::iota::WasmIotaDocumentMetadata;
use crate::iota::WasmStateMetadataEncoding;
use crate::jose::WasmDecodedJws;
use crate::jose::WasmJwsAlgorithm;
use crate::jpt::WasmJptClaims;
use crate::jpt::WasmProofAlgorithm;
use crate::jpt::WasmSelectiveDisclosurePresentation;
use crate::storage::WasmJwsSignatureOptions;
use crate::storage::WasmJwtPresentationOptions;
use crate::storage::WasmStorage;
use crate::storage::WasmStorageInner;
use crate::verification::IJwsVerifier;
use crate::verification::RefMethodScope;
use crate::verification::WasmJwsVerifier;
use crate::verification::WasmMethodRelationship;
use crate::verification::WasmMethodScope;
use crate::verification::WasmVerificationMethod;
use identity_iota::storage::JwpDocumentExt;

pub(crate) struct IotaDocumentLock(tokio::sync::RwLock<IotaDocument>);

impl IotaDocumentLock {
  pub(crate) fn new(value: IotaDocument) -> Self {
    Self(tokio::sync::RwLock::new(value))
  }

  pub(crate) fn try_read(&self) -> Result<tokio::sync::RwLockReadGuard<'_, IotaDocument>> {
    self.0.try_read().wasm_result()
  }

  pub(crate) fn try_write(&self) -> Result<tokio::sync::RwLockWriteGuard<'_, IotaDocument>> {
    self.0.try_write().wasm_result()
  }

  pub(crate) async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, IotaDocument> {
    self.0.read().await
  }

  pub(crate) async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, IotaDocument> {
    self.0.write().await
  }
}
// =============================================================================
// =============================================================================

/// A DID Document adhering to the IOTA DID method specification.
///
/// Note: All methods that involve reading from this class may potentially raise an error
/// if the object is being concurrently modified.
#[wasm_bindgen(js_name = IotaDocument, inspectable)]
#[derive(Clone)]
pub struct WasmIotaDocument(pub(crate) Rc<IotaDocumentLock>);

#[wasm_bindgen(js_class = IotaDocument)]
impl WasmIotaDocument {
  // ===========================================================================
  // Constructors
  // ===========================================================================

  /// Constructs an empty IOTA DID Document with a {@link IotaDID.placeholder} identifier
  /// for the given `network`.
  #[wasm_bindgen(constructor)]
  pub fn new(network: String) -> Result<WasmIotaDocument> {
    let network_name: NetworkName = NetworkName::try_from(network).wasm_result()?;
    Ok(WasmIotaDocument::from(IotaDocument::new(&network_name)))
  }

  /// Constructs an empty DID Document with the given identifier.
  #[wasm_bindgen(js_name = newWithId)]
  pub fn new_with_id(id: &WasmIotaDID) -> WasmIotaDocument {
    let did: IotaDID = id.0.clone();
    WasmIotaDocument::from(IotaDocument::new_with_id(did))
  }

  // ===========================================================================
  // Properties
  // ===========================================================================

  /// Returns a copy of the DID Document `id`.
  #[wasm_bindgen]
  pub fn id(&self) -> Result<WasmIotaDID> {
    Ok(WasmIotaDID::from(self.0.try_read()?.id().clone()))
  }

  /// Returns a copy of the list of document controllers.
  ///
  /// NOTE: controllers are determined by the `state_controller` unlock condition of the output
  /// during resolution and are omitted when publishing.
  #[wasm_bindgen]
  pub fn controller(&self) -> Result<ArrayIotaDID> {
    Ok(
      self
        .0
        .try_read()?
        .controller()
        .cloned()
        .map(WasmIotaDID::from)
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayIotaDID>(),
    )
  }

  /// Sets the controllers of the document.
  ///
  /// Note: Duplicates will be ignored.
  /// Use `null` to remove all controllers.
  #[wasm_bindgen(js_name = setController)]
  pub fn set_controller(&mut self, controller: &OptionArrayIotaDID) -> Result<()> {
    let controller: Option<Vec<IotaDID>> = controller.into_serde().wasm_result()?;
    match controller {
      Some(controller) => self.0.try_write()?.set_controller(controller),
      None => self.0.try_write()?.set_controller([]),
    };
    Ok(())
  }

  /// Returns a copy of the document's `alsoKnownAs` set.
  #[wasm_bindgen(js_name = alsoKnownAs)]
  pub fn also_known_as(&self) -> Result<ArrayString> {
    Ok(
      self
        .0
        .try_read()?
        .also_known_as()
        .iter()
        .map(|url| url.to_string())
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayString>(),
    )
  }

  /// Sets the `alsoKnownAs` property in the DID document.
  #[wasm_bindgen(js_name = setAlsoKnownAs)]
  pub fn set_also_known_as(&mut self, urls: &OptionOneOrManyString) -> Result<()> {
    let urls: Option<OneOrMany<String>> = urls.into_serde().wasm_result()?;
    let mut urls_set: OrderedSet<Url> = OrderedSet::new();
    if let Some(urls) = urls {
      for url in urls.into_vec() {
        urls_set.append(Url::parse(url).wasm_result()?);
      }
    }
    *self.0.try_write()?.also_known_as_mut() = urls_set;
    Ok(())
  }

  /// Returns a copy of the custom DID Document properties.
  #[wasm_bindgen]
  pub fn properties(&self) -> Result<MapStringAny> {
    MapStringAny::try_from(self.0.try_read()?.properties())
  }

  /// Sets a custom property in the DID Document.
  /// If the value is set to `null`, the custom property will be removed.
  ///
  /// ### WARNING
  ///
  /// This method can overwrite existing properties like `id` and result in an invalid document.
  #[wasm_bindgen(js_name = setPropertyUnchecked)]
  pub fn set_property_unchecked(&mut self, key: String, value: &JsValue) -> Result<()> {
    let value: Option<serde_json::Value> = value.into_serde().wasm_result()?;
    match value {
      Some(value) => {
        self.0.try_write()?.properties_mut_unchecked().insert(key, value);
      }
      None => {
        self.0.try_write()?.properties_mut_unchecked().remove(&key);
      }
    }
    Ok(())
  }

  // ===========================================================================
  // Services
  // ===========================================================================

  /// Return a set of all {@link Service} in the document.
  #[wasm_bindgen]
  pub fn service(&self) -> Result<ArrayService> {
    Ok(
      self
        .0
        .try_read()?
        .service()
        .iter()
        .cloned()
        .map(WasmService)
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayService>(),
    )
  }

  /// Add a new {@link Service} to the document.
  ///
  /// Returns `true` if the service was added.
  #[wasm_bindgen(js_name = insertService)]
  pub fn insert_service(&mut self, service: &WasmService) -> Result<()> {
    self.0.try_write()?.insert_service(service.0.clone()).wasm_result()
  }

  /// Remove a {@link Service} identified by the given {@link DIDUrl} from the document.
  ///
  /// Returns `true` if a service was removed.
  #[wasm_bindgen(js_name = removeService)]
  pub fn remove_service(&mut self, did: &WasmDIDUrl) -> Result<Option<WasmService>> {
    Ok(self.0.try_write()?.remove_service(&did.0).map(Into::into))
  }

  /// Returns the first {@link Service} with an `id` property matching the provided `query`,
  /// if present.
  #[wasm_bindgen(js_name = resolveService)]
  pub fn resolve_service(&self, query: &UDIDUrlQuery) -> Result<Option<WasmService>> {
    let service_query: String = query.into_serde().wasm_result()?;
    Ok(
      self
        .0
        .try_read()?
        .resolve_service(&service_query)
        .cloned()
        .map(WasmService::from),
    )
  }

  // ===========================================================================
  // Verification Methods
  // ===========================================================================

  /// Returns a list of all {@link VerificationMethod} in the DID Document,
  /// whose verification relationship matches `scope`.
  ///
  /// If `scope` is not set, a list over the **embedded** methods is returned.
  #[wasm_bindgen]
  pub fn methods(&self, scope: Option<RefMethodScope>) -> Result<ArrayVerificationMethod> {
    let scope: Option<MethodScope> = scope.map(|js| js.into_serde().wasm_result()).transpose()?;
    let methods = self
      .0
      .try_read()?
      .methods(scope)
      .into_iter()
      .cloned()
      .map(WasmVerificationMethod::from)
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayVerificationMethod>();
    Ok(methods)
  }

  /// Adds a new `method` to the document in the given `scope`.
  #[wasm_bindgen(js_name = insertMethod)]
  pub fn insert_method(&mut self, method: &WasmVerificationMethod, scope: &WasmMethodScope) -> Result<()> {
    self
      .0
      .try_write()?
      .insert_method(method.0.clone(), scope.0)
      .wasm_result()?;
    Ok(())
  }

  /// Removes all references to the specified Verification Method.
  #[wasm_bindgen(js_name = removeMethod)]
  pub fn remove_method(&mut self, did: &WasmDIDUrl) -> Result<Option<WasmVerificationMethod>> {
    Ok(self.0.try_write()?.remove_method(&did.0).map(Into::into))
  }

  /// Returns a copy of the first verification method with an `id` property
  /// matching the provided `query` and the verification relationship
  /// specified by `scope`, if present.
  #[wasm_bindgen(js_name = resolveMethod)]
  pub fn resolve_method(
    &self,
    query: &UDIDUrlQuery,
    scope: Option<RefMethodScope>,
  ) -> Result<Option<WasmVerificationMethod>> {
    let method_query: String = query.into_serde().wasm_result()?;
    let method_scope: Option<MethodScope> = scope.map(|js| js.into_serde().wasm_result()).transpose()?;

    let guard = self.0.try_read()?;
    let method: Option<&VerificationMethod> = guard.resolve_method(&method_query, method_scope);
    Ok(method.cloned().map(WasmVerificationMethod))
  }

  /// Attaches the relationship to the given method, if the method exists.
  ///
  /// Note: The method needs to be in the set of verification methods,
  /// so it cannot be an embedded one.
  #[allow(non_snake_case)]
  #[wasm_bindgen(js_name = attachMethodRelationship)]
  pub fn attach_method_relationship(
    &mut self,
    didUrl: &WasmDIDUrl,
    relationship: WasmMethodRelationship,
  ) -> Result<bool> {
    self
      .0
      .try_write()?
      .attach_method_relationship(&didUrl.0, relationship.into())
      .wasm_result()
  }

  /// Detaches the given relationship from the given method, if the method exists.
  #[allow(non_snake_case)]
  #[wasm_bindgen(js_name = detachMethodRelationship)]
  pub fn detach_method_relationship(
    &mut self,
    didUrl: &WasmDIDUrl,
    relationship: WasmMethodRelationship,
  ) -> Result<bool> {
    self
      .0
      .try_write()?
      .detach_method_relationship(&didUrl.0, relationship.into())
      .wasm_result()
  }

  // ===========================================================================
  // Verification
  // ===========================================================================

  /// Decodes and verifies the provided JWS according to the passed `options` and `signatureVerifier`.
  /// If a `signatureVerifier` is provided it will be used when
  /// verifying decoded JWS signatures, otherwise a default verifier capable of handling the `EdDSA`, `ES256`, `ES256K`
  /// algorithms will be used.
  ///
  /// Regardless of which options are passed the following conditions must be met in order for a verification attempt to
  /// take place.
  /// - The JWS must be encoded according to the JWS compact serialization.
  /// - The `kid` value in the protected header must be an identifier of a verification method in this DID document.
  #[wasm_bindgen(js_name = verifyJws)]
  #[allow(non_snake_case)]
  pub fn verify_jws(
    &self,
    jws: &WasmJws,
    options: &WasmJwsVerificationOptions,
    signatureVerifier: Option<IJwsVerifier>,
    detachedPayload: Option<String>,
  ) -> Result<WasmDecodedJws> {
    let jws_verifier = WasmJwsVerifier::new(signatureVerifier);
    self
      .0
      .try_read()?
      .verify_jws(
        &jws.0,
        detachedPayload.as_deref().map(|detached| detached.as_bytes()),
        &jws_verifier,
        &options.0,
      )
      .map(WasmDecodedJws::from)
      .wasm_result()
  }

  // ===========================================================================
  // Publishing
  // ===========================================================================

  /// Serializes the document for inclusion in an identity's metadata
  /// with the default {@link StateMetadataEncoding}.
  #[wasm_bindgen]
  pub fn pack(&self) -> Result<Vec<u8>> {
    self.0.try_read()?.clone().pack().wasm_result()
  }

  /// Serializes the document for inclusion in an identity's metadata.
  #[wasm_bindgen(js_name = packWithEncoding)]
  pub fn pack_with_encoding(&self, encoding: WasmStateMetadataEncoding) -> Result<Vec<u8>> {
    self
      .0
      .try_read()?
      .clone()
      .pack_with_encoding(StateMetadataEncoding::from(encoding))
      .wasm_result()
  }

  // ===========================================================================
  // Metadata
  // ===========================================================================

  /// Returns a copy of the metadata associated with this document.
  ///
  /// NOTE: Copies all the metadata. See also `metadataCreated`, `metadataUpdated`,
  /// `metadataPreviousMessageId`, `metadataProof` if only a subset of the metadata required.
  #[wasm_bindgen]
  pub fn metadata(&self) -> Result<WasmIotaDocumentMetadata> {
    Ok(WasmIotaDocumentMetadata::from(self.0.try_read()?.metadata.clone()))
  }

  /// Returns a copy of the timestamp of when the DID document was created.
  #[wasm_bindgen(js_name = metadataCreated)]
  pub fn metadata_created(&self) -> Result<Option<WasmTimestamp>> {
    Ok(self.0.try_read()?.metadata.created.map(WasmTimestamp::from))
  }

  /// Sets the timestamp of when the DID document was created.
  #[wasm_bindgen(js_name = setMetadataCreated)]
  pub fn set_metadata_created(&mut self, timestamp: OptionTimestamp) -> Result<()> {
    let timestamp: Option<Timestamp> = timestamp.into_serde().wasm_result()?;
    self.0.try_write()?.metadata.created = timestamp;
    Ok(())
  }

  /// Returns a copy of the timestamp of the last DID document update.
  #[wasm_bindgen(js_name = metadataUpdated)]
  pub fn metadata_updated(&self) -> Result<Option<WasmTimestamp>> {
    Ok(self.0.try_read()?.metadata.updated.map(WasmTimestamp::from))
  }

  /// Sets the timestamp of the last DID document update.
  #[wasm_bindgen(js_name = setMetadataUpdated)]
  pub fn set_metadata_updated(&mut self, timestamp: OptionTimestamp) -> Result<()> {
    let timestamp: Option<Timestamp> = timestamp.into_serde().wasm_result()?;
    self.0.try_write()?.metadata.updated = timestamp;
    Ok(())
  }

  /// Returns a copy of the deactivated status of the DID document.
  #[wasm_bindgen(js_name = metadataDeactivated)]
  pub fn metadata_deactivated(&self) -> Result<Option<bool>> {
    Ok(self.0.try_read()?.metadata.deactivated)
  }

  /// Sets the deactivated status of the DID document.
  #[wasm_bindgen(js_name = setMetadataDeactivated)]
  pub fn set_metadata_deactivated(&mut self, deactivated: Option<bool>) -> Result<()> {
    self.0.try_write()?.metadata.deactivated = deactivated;
    Ok(())
  }

  /// Sets a custom property in the document metadata.
  /// If the value is set to `null`, the custom property will be removed.
  #[wasm_bindgen(js_name = setMetadataPropertyUnchecked)]
  pub fn set_metadata_property_unchecked(&mut self, key: String, value: &JsValue) -> Result<()> {
    let value: Option<serde_json::Value> = value.into_serde().wasm_result()?;
    match value {
      Some(value) => {
        self.0.try_write()?.metadata.properties_mut().insert(key, value);
      }
      None => {
        self.0.try_write()?.metadata.properties_mut().remove(&key);
      }
    }
    Ok(())
  }

  // ===========================================================================
  // Revocation
  // ===========================================================================

  /// If the document has a {@link RevocationBitmap} service identified by `serviceQuery`,
  /// revoke all specified `indices`.
  #[wasm_bindgen(js_name = revokeCredentials)]
  #[allow(non_snake_case)]
  pub fn revoke_credentials(&mut self, serviceQuery: &UDIDUrlQuery, indices: UOneOrManyNumber) -> Result<()> {
    let query: String = serviceQuery.into_serde().wasm_result()?;
    let indices: OneOrMany<u32> = indices.into_serde().wasm_result()?;

    self
      .0
      .try_write()?
      .revoke_credentials(&query, indices.as_slice())
      .wasm_result()
  }

  /// If the document has a {@link RevocationBitmap} service identified by `serviceQuery`,
  /// unrevoke all specified `indices`.
  #[wasm_bindgen(js_name = unrevokeCredentials)]
  #[allow(non_snake_case)]
  pub fn unrevoke_credentials(&mut self, serviceQuery: &UDIDUrlQuery, indices: UOneOrManyNumber) -> Result<()> {
    let query: String = serviceQuery.into_serde().wasm_result()?;
    let indices: OneOrMany<u32> = indices.into_serde().wasm_result()?;

    self
      .0
      .try_write()?
      .unrevoke_credentials(&query, indices.as_slice())
      .wasm_result()
  }

  // ===========================================================================
  // Cloning
  // ===========================================================================

  #[wasm_bindgen(js_name = clone)]
  /// Returns a deep clone of the {@link IotaDocument}.
  pub fn deep_clone(&self) -> Result<WasmIotaDocument> {
    Ok(WasmIotaDocument(Rc::new(IotaDocumentLock::new(
      self.0.try_read()?.clone(),
    ))))
  }

  /// ### Warning
  /// This is for internal use only. Do not rely on or call this method.
  #[wasm_bindgen(js_name = _shallowCloneInternal)]
  pub fn shallow_clone(&self) -> WasmIotaDocument {
    WasmIotaDocument(self.0.clone())
  }

  /// ### Warning
  /// This is for internal use only. Do not rely on or call this method.
  #[wasm_bindgen(js_name = _strongCountInternal)]
  pub fn strong_count(&self) -> usize {
    Rc::strong_count(&self.0)
  }

  // ===========================================================================
  // Serialization
  // ===========================================================================

  /// Serializes to a plain JS representation.
  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<JsValue> {
    let read_guard = self.0.try_read()?;
    let iota_document: &IotaDocument = &read_guard;
    JsValue::from_serde(&iota_document).wasm_result()
  }

  /// Deserializes an instance from a plain JS representation.
  #[wasm_bindgen(js_name = fromJSON)]
  pub fn from_json(json: &JsValue) -> Result<WasmIotaDocument> {
    json
      .into_serde()
      .map(|value| Self(Rc::new(IotaDocumentLock::new(value))))
      .wasm_result()
  }

  // ===========================================================================
  // "AsRef<CoreDocument>"
  // ===========================================================================
  /// Transforms the {@link IotaDocument} to its {@link CoreDocument} representation.
  #[wasm_bindgen(js_name = toCoreDocument)]
  pub fn as_core_document(&self) -> Result<WasmCoreDocument> {
    Ok(WasmCoreDocument(Rc::new(CoreDocumentLock::new(
      self.0.try_read()?.core_document().clone(),
    ))))
  }

  // ===========================================================================
  // Storage
  // ===========================================================================

  /// Generate new key material in the given `storage` and insert a new verification method with the corresponding
  /// public key material into the DID document.
  ///
  /// - If no fragment is given the `kid` of the generated JWK is used, if it is set, otherwise an error is returned.
  /// - The `keyType` must be compatible with the given `storage`. `Storage`s are expected to export key type constants
  /// for that use case.
  ///
  /// The fragment of the generated method is returned.
  #[wasm_bindgen(js_name = generateMethod)]
  #[allow(non_snake_case)]
  pub fn generate_method(
    &self,
    storage: &WasmStorage,
    keyType: String,
    alg: WasmJwsAlgorithm,
    fragment: Option<String>,
    scope: WasmMethodScope,
  ) -> Result<PromiseString> {
    let alg: JwsAlgorithm = alg.into_serde().wasm_result()?;
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let scope: MethodScope = scope.0;
    let promise: Promise = future_to_promise(async move {
      let method_fragment: String = document_lock_clone
        .write()
        .await
        .generate_method(&storage_clone, KeyType::from(keyType), alg, fragment.as_deref(), scope)
        .await
        .wasm_result()?;
      Ok(JsValue::from(method_fragment))
    });
    Ok(promise.unchecked_into())
  }

  /// Remove the method identified by the given fragment from the document and delete the corresponding key material in
  /// the given `storage`.
  #[wasm_bindgen(js_name = purgeMethod)]
  pub fn purge_method(&mut self, storage: &WasmStorage, id: &WasmDIDUrl) -> Result<PromiseVoid> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let id: DIDUrl = id.0.clone();
    let promise: Promise = future_to_promise(async move {
      document_lock_clone
        .write()
        .await
        .purge_method(&storage_clone, &id)
        .await
        .wasm_result()
        .map(|_| JsValue::UNDEFINED)
    });
    Ok(promise.unchecked_into())
  }

  /// Sign the `payload` according to `options` with the storage backed private key corresponding to the public key
  /// material in the verification method identified by the given `fragment.
  ///
  /// Upon success a string representing a JWS encoded according to the Compact JWS Serialization format is returned.
  /// See [RFC7515 section 3.1](https://www.rfc-editor.org/rfc/rfc7515#section-3.1).
  ///
  /// @deprecated Use `createJws()` instead.
  #[deprecated]
  #[wasm_bindgen(js_name = createJwt)]
  pub fn create_jwt(
    &self,
    storage: &WasmStorage,
    fragment: String,
    payload: String,
    options: &WasmJwsSignatureOptions,
  ) -> Result<PromiseJws> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let options_clone: JwsSignatureOptions = options.0.clone();
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let promise: Promise = future_to_promise(async move {
      document_lock_clone
        .read()
        .await
        .create_jws(&storage_clone, &fragment, payload.as_bytes(), &options_clone)
        .await
        .wasm_result()
        .map(WasmJws::new)
        .map(JsValue::from)
    });
    Ok(promise.unchecked_into())
  }

  /// Sign the `payload` according to `options` with the storage backed private key corresponding to the public key
  /// material in the verification method identified by the given `fragment.
  ///
  /// Upon success a string representing a JWS encoded according to the Compact JWS Serialization format is returned.
  /// See [RFC7515 section 3.1](https://www.rfc-editor.org/rfc/rfc7515#section-3.1).
  #[wasm_bindgen(js_name = createJws)]
  pub fn create_jws(
    &self,
    storage: &WasmStorage,
    fragment: String,
    payload: String,
    options: &WasmJwsSignatureOptions,
  ) -> Result<PromiseJws> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let options_clone: JwsSignatureOptions = options.0.clone();
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let promise: Promise = future_to_promise(async move {
      document_lock_clone
        .read()
        .await
        .create_jws(&storage_clone, &fragment, payload.as_bytes(), &options_clone)
        .await
        .wasm_result()
        .map(WasmJws::new)
        .map(JsValue::from)
    });
    Ok(promise.unchecked_into())
  }

  /// Produces a JWS where the payload is produced from the given `credential`
  /// in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  ///
  /// The `custom_claims` can be used to set additional claims on the resulting JWT.
  #[wasm_bindgen(js_name = createCredentialJwt)]
  pub fn create_credential_jwt(
    &self,
    storage: &WasmStorage,
    fragment: String,
    credential: &WasmCredential,
    options: &WasmJwsSignatureOptions,
    custom_claims: Option<RecordStringAny>,
  ) -> Result<PromiseJwt> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let options_clone: JwsSignatureOptions = options.0.clone();
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let credential_clone = credential.0.clone();
    let custom: Option<Object> = custom_claims
      .map(|claims| claims.into_serde().wasm_result())
      .transpose()?;
    let promise: Promise = future_to_promise(async move {
      document_lock_clone
        .read()
        .await
        .create_credential_jwt(&credential_clone, &storage_clone, &fragment, &options_clone, custom)
        .await
        .wasm_result()
        .map(WasmJwt::new)
        .map(JsValue::from)
    });
    Ok(promise.unchecked_into())
  }

  /// Produces a JWS where the payload is produced from the given `credential`
  /// in accordance with [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/#securing-with-jose).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  #[wasm_bindgen(js_name = createCredentialV2Jwt)]
  pub async fn create_credential_v2_jwt(
    &self,
    storage: &WasmStorage,
    fragment: String,
    credential: &WasmCredentialV2,
    options: &WasmJwsSignatureOptions,
  ) -> Result<WasmJwtVcV2> {
    self
      .0
      .read()
      .await
      .create_credential_v2_jwt(&credential.0, &storage.0, fragment.as_str(), &options.0)
      .await
      .wasm_result()
      .map(WasmJwtVcV2)
  }

  /// Produces a JWT where the payload is produced from the given presentation.
  /// in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  #[wasm_bindgen(js_name = createPresentationJwt)]
  pub fn create_presentation_jwt(
    &self,
    storage: &WasmStorage,
    fragment: String,
    presentation: &WasmPresentation,
    signature_options: &WasmJwsSignatureOptions,
    presentation_options: &WasmJwtPresentationOptions,
  ) -> Result<PromiseJwt> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let options_clone: JwsSignatureOptions = signature_options.0.clone();
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let presentation_clone: Presentation<UnknownCredential> = presentation.0.clone();
    let presentation_options_clone: JwtPresentationOptions = presentation_options.0.clone();
    let promise: Promise = future_to_promise(async move {
      document_lock_clone
        .read()
        .await
        .create_presentation_jwt(
          &presentation_clone,
          &storage_clone,
          &fragment,
          &options_clone,
          &presentation_options_clone,
        )
        .await
        .wasm_result()
        .map(WasmJwt::new)
        .map(JsValue::from)
    });
    Ok(promise.unchecked_into())
  }

  #[wasm_bindgen(js_name = generateMethodJwp)]
  pub fn generate_method_jwp(
    &self,
    storage: &WasmStorage,
    alg: WasmProofAlgorithm,
    fragment: Option<String>,
    scope: WasmMethodScope,
  ) -> Result<PromiseString> {
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let promise: Promise = future_to_promise(async move {
      let method_fragment: String = document_lock_clone
        .write()
        .await
        .generate_method_jwp(
          &storage_clone,
          KeyType::from_static_str("BLS12381"),
          alg.into(),
          fragment.as_deref(),
          scope.0,
        )
        .await
        .wasm_result()?;
      Ok(JsValue::from(method_fragment))
    });

    Ok(promise.unchecked_into())
  }

  #[wasm_bindgen(js_name = createIssuedJwp)]
  pub fn create_issued_jwp(
    &self,
    storage: &WasmStorage,
    fragment: String,
    jpt_claims: WasmJptClaims,
    options: WasmJwpCredentialOptions,
  ) -> Result<PromiseString> {
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let jpt_claims = jpt_claims.into_serde().wasm_result()?;
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let options = options.into();
    let promise: Promise = future_to_promise(async move {
      let jwp: String = document_lock_clone
        .write()
        .await
        .create_issued_jwp(&storage_clone, fragment.as_str(), &jpt_claims, &options)
        .await
        .wasm_result()?;
      Ok(JsValue::from(jwp))
    });

    Ok(promise.unchecked_into())
  }

  #[wasm_bindgen(js_name = createPresentedJwp)]
  pub fn create_presented_jwp(
    &self,
    presentation: WasmSelectiveDisclosurePresentation,
    method_id: String,
    options: WasmJwpPresentationOptions,
  ) -> Result<PromiseString> {
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let options = options.try_into()?;
    let promise: Promise = future_to_promise(async move {
      let mut presentation = presentation.0;
      let jwp: String = document_lock_clone
        .write()
        .await
        .create_presented_jwp(&mut presentation, method_id.as_str(), &options)
        .await
        .wasm_result()?;
      Ok(JsValue::from(jwp))
    });

    Ok(promise.unchecked_into())
  }

  #[wasm_bindgen(js_name = createCredentialJpt)]
  pub fn create_credential_jpt(
    &self,
    credential: WasmCredential,
    storage: &WasmStorage,
    fragment: String,
    options: WasmJwpCredentialOptions,
    custom_claims: Option<MapStringAny>,
  ) -> Result<PromiseJpt> {
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let options = options.into();
    let custom_claims = custom_claims.and_then(|claims| claims.into_serde().ok());
    let promise: Promise = future_to_promise(async move {
      let jpt = document_lock_clone
        .write()
        .await
        .create_credential_jpt(
          &credential.0,
          &storage_clone,
          fragment.as_str(),
          &options,
          custom_claims,
        )
        .await
        .map(WasmJpt)
        .wasm_result()?;
      Ok(JsValue::from(jpt))
    });

    Ok(promise.unchecked_into())
  }

  #[wasm_bindgen(js_name = createPresentationJpt)]
  pub fn create_presentation_jpt(
    &self,
    presentation: WasmSelectiveDisclosurePresentation,
    method_id: String,
    options: WasmJwpPresentationOptions,
  ) -> Result<PromiseJpt> {
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let options = options.try_into()?;
    let promise: Promise = future_to_promise(async move {
      let mut presentation = presentation.0;
      let jpt = document_lock_clone
        .write()
        .await
        .create_presentation_jpt(&mut presentation, method_id.as_str(), &options)
        .await
        .map(WasmJpt)
        .wasm_result()?;
      Ok(JsValue::from(jpt))
    });

    Ok(promise.unchecked_into())
  }
}

impl From<IotaDocument> for WasmIotaDocument {
  fn from(document: IotaDocument) -> Self {
    Self(Rc::new(IotaDocumentLock::new(document)))
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IotaDID[] | null")]
  pub type OptionArrayIotaDID;

  #[wasm_bindgen(typescript_type = "IotaDID[]")]
  pub type ArrayIotaDID;

  #[wasm_bindgen(typescript_type = "Promise<IotaDocument>")]
  pub type PromiseIotaDocument;

  #[wasm_bindgen(typescript_type = "IotaDocument[]")]
  pub type ArrayIotaDocument;
}
