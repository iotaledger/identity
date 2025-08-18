// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use super::WasmCoreDID;
use super::WasmJwsVerificationOptions;
use crate::common::ArrayCoreMethodRef;
use crate::common::ArrayService;
use crate::common::ArrayString;
use crate::common::ArrayVerificationMethod;
use crate::common::MapStringAny;
use crate::common::OptionOneOrManyString;
use crate::common::PromiseString;
use crate::common::PromiseVoid;
use crate::common::RecordStringAny;
use crate::common::UDIDUrlQuery;
use crate::common::UOneOrManyNumber;
use crate::credential::ArrayCoreDID;
use crate::credential::UnknownCredential;
use crate::credential::WasmCredential;
use crate::credential::WasmJws;
use crate::credential::WasmJwt;
use crate::credential::WasmPresentation;
use crate::did::service::WasmService;
use crate::did::wasm_did_url::WasmDIDUrl;
use crate::did::WasmDIDCompositeJwk;
use crate::did::WasmDIDJwk;
use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmDecodedJws;
use crate::jose::WasmJwsAlgorithm;
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
use identity_iota::core::Object;
use identity_iota::core::OneOrMany;
use identity_iota::core::OneOrSet;
use identity_iota::core::OrderedSet;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::Presentation;
use identity_iota::credential::RevocationDocumentExt;
use identity_iota::did::CoreDID;
use identity_iota::did::DIDUrl;
use identity_iota::document::CoreDocument;
use identity_iota::document::Service;
use identity_iota::storage::key_storage::KeyType;
use identity_iota::storage::storage::JwkDocumentExt;
use identity_iota::storage::storage::JwsSignatureOptions;
use identity_iota::verification::jose::jws::JwsAlgorithm;
use identity_iota::verification::MethodRef;
use identity_iota::verification::MethodScope;
use identity_iota::verification::VerificationMethod;

use js_sys::Promise;
use proc_typescript::typescript;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

pub(crate) struct CoreDocumentLock(tokio::sync::RwLock<CoreDocument>);

impl CoreDocumentLock {
  pub(crate) fn new(input: CoreDocument) -> Self {
    Self(tokio::sync::RwLock::new(input))
  }

  pub(crate) fn try_read(&self) -> Result<tokio::sync::RwLockReadGuard<'_, CoreDocument>> {
    self.0.try_read().wasm_result()
  }

  pub(crate) fn try_write(&self) -> Result<tokio::sync::RwLockWriteGuard<'_, CoreDocument>> {
    self.0.try_write().wasm_result()
  }

  pub(crate) async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, CoreDocument> {
    self.0.read().await
  }

  pub(crate) async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, CoreDocument> {
    self.0.write().await
  }
}

/// A method-agnostic DID Document.
///
/// Note: All methods that involve reading from this class may potentially raise an error
/// if the object is being concurrently modified.
#[wasm_bindgen(js_name = CoreDocument, inspectable)]
pub struct WasmCoreDocument(pub(crate) Rc<CoreDocumentLock>);

#[wasm_bindgen(js_class = CoreDocument)]
impl WasmCoreDocument {
  /// Creates a new {@link CoreDocument} with the given properties.
  #[wasm_bindgen(constructor)]
  pub fn new(values: ICoreDocument) -> Result<WasmCoreDocument> {
    let core_doc: CoreDocument = values.into_serde().wasm_result()?;
    Ok(WasmCoreDocument(Rc::new(CoreDocumentLock::new(core_doc))))
  }

  /// Returns a copy of the DID Document `id`.
  #[wasm_bindgen]
  pub fn id(&self) -> Result<WasmCoreDID> {
    Ok(WasmCoreDID::from(self.0.try_read()?.id().clone()))
  }

  /// Sets the DID of the document.
  ///
  /// ### Warning
  ///
  /// Changing the identifier can drastically alter the results of
  /// `resolve_method`, `resolve_service` and the related
  /// [DID URL dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing) algorithm.
  #[wasm_bindgen(js_name = setId)]
  pub fn set_id(&mut self, id: &WasmCoreDID) -> Result<()> {
    *self.0.try_write()?.id_mut_unchecked() = id.0.clone();
    Ok(())
  }

  /// Returns a copy of the document controllers.
  #[wasm_bindgen]
  pub fn controller(&self) -> Result<ArrayCoreDID> {
    let controller = match self.0.try_read()?.controller() {
      Some(controllers) => controllers
        .iter()
        .cloned()
        .map(WasmCoreDID::from)
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreDID>(),
      None => js_sys::Array::new().unchecked_into::<ArrayCoreDID>(),
    };
    Ok(controller)
  }

  /// Sets the controllers of the DID Document.
  ///
  /// Note: Duplicates will be ignored.
  /// Use `null` to remove all controllers.
  #[wasm_bindgen(js_name = setController)]
  pub fn set_controller(&mut self, controllers: &OptionOneOrManyCoreDID) -> Result<()> {
    let controllers: Option<OneOrMany<CoreDID>> = controllers.into_serde().wasm_result()?;
    let controller_set: Option<OneOrSet<CoreDID>> = if let Some(controllers) = controllers.map(OneOrMany::into_vec) {
      if controllers.is_empty() {
        None
      } else {
        Some(OneOrSet::try_from(OrderedSet::from_iter(controllers)).wasm_result()?)
      }
    } else {
      None
    };
    *self.0.try_write()?.controller_mut() = controller_set;
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

  /// Returns a copy of the document's `verificationMethod` set.
  #[wasm_bindgen(js_name = verificationMethod)]
  pub fn verification_method(&self) -> Result<ArrayVerificationMethod> {
    Ok(
      self
        .0
        .try_read()?
        .verification_method()
        .iter()
        .cloned()
        .map(WasmVerificationMethod::from)
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayVerificationMethod>(),
    )
  }

  /// Returns a copy of the document's `authentication` set.
  #[wasm_bindgen]
  pub fn authentication(&self) -> Result<ArrayCoreMethodRef> {
    Ok(
      self
        .0
        .try_read()?
        .authentication()
        .iter()
        .cloned()
        .map(|method_ref| match method_ref {
          MethodRef::Embed(verification_method) => JsValue::from(WasmVerificationMethod(verification_method)),
          MethodRef::Refer(did_url) => JsValue::from(WasmDIDUrl(did_url)),
        })
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreMethodRef>(),
    )
  }

  /// Returns a copy of the document's `assertionMethod` set.
  #[wasm_bindgen(js_name = assertionMethod)]
  pub fn assertion_method(&self) -> Result<ArrayCoreMethodRef> {
    Ok(
      self
        .0
        .try_read()?
        .assertion_method()
        .iter()
        .cloned()
        .map(|method_ref| match method_ref {
          MethodRef::Embed(verification_method) => JsValue::from(WasmVerificationMethod(verification_method)),
          MethodRef::Refer(did_url) => JsValue::from(WasmDIDUrl(did_url)),
        })
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreMethodRef>(),
    )
  }

  /// Returns a copy of the document's `keyAgreement` set.
  #[wasm_bindgen(js_name = keyAgreement)]
  pub fn key_agreement(&self) -> Result<ArrayCoreMethodRef> {
    Ok(
      self
        .0
        .try_read()?
        .key_agreement()
        .iter()
        .cloned()
        .map(|method_ref| match method_ref {
          MethodRef::Embed(verification_method) => JsValue::from(WasmVerificationMethod(verification_method)),
          MethodRef::Refer(did_url) => JsValue::from(WasmDIDUrl(did_url)),
        })
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreMethodRef>(),
    )
  }

  /// Returns a copy of the document's `capabilityDelegation` set.
  #[wasm_bindgen(js_name = capabilityDelegation)]
  pub fn capability_delegation(&self) -> Result<ArrayCoreMethodRef> {
    Ok(
      self
        .0
        .try_read()?
        .capability_delegation()
        .iter()
        .cloned()
        .map(|method_ref| match method_ref {
          MethodRef::Embed(verification_method) => JsValue::from(WasmVerificationMethod(verification_method)),
          MethodRef::Refer(did_url) => JsValue::from(WasmDIDUrl(did_url)),
        })
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreMethodRef>(),
    )
  }

  /// Returns a copy of the document's `capabilityInvocation` set.
  #[wasm_bindgen(js_name = capabilityInvocation)]
  pub fn capability_invocation(&self) -> Result<ArrayCoreMethodRef> {
    Ok(
      self
        .0
        .try_read()?
        .capability_invocation()
        .iter()
        .cloned()
        .map(|method_ref| match method_ref {
          MethodRef::Embed(verification_method) => JsValue::from(WasmVerificationMethod(verification_method)),
          MethodRef::Refer(did_url) => JsValue::from(WasmDIDUrl(did_url)),
        })
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreMethodRef>(),
    )
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
  // ===========================================================sdfs================

  /// Returns a set of all {@link Service} in the document.
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
  /// Errors if there already exists a service or verification method with the same id.
  #[wasm_bindgen(js_name = insertService)]
  pub fn insert_service(&mut self, service: &WasmService) -> Result<()> {
    self.0.try_write()?.insert_service(service.0.clone()).wasm_result()
  }

  /// Remove a {@link Service} identified by the given {@link DIDUrl} from the document.
  ///
  /// Returns `true` if the service was removed.
  #[wasm_bindgen(js_name = removeService)]
  #[allow(non_snake_case)]
  pub fn remove_service(&mut self, didUrl: &WasmDIDUrl) -> Result<Option<WasmService>> {
    Ok(self.0.try_write()?.remove_service(&didUrl.0.clone()).map(Into::into))
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

  /// Returns an array of all verification relationships.
  #[wasm_bindgen(js_name = verificationRelationships)]
  pub fn verification_relationships(&self) -> Result<ArrayCoreMethodRef> {
    Ok(
      self
        .0
        .try_read()?
        .verification_relationships()
        .cloned()
        .map(|method_ref| match method_ref {
          MethodRef::Embed(verification_method) => JsValue::from(WasmVerificationMethod(verification_method)),
          MethodRef::Refer(did_url) => JsValue::from(WasmDIDUrl(did_url)),
        })
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreMethodRef>(),
    )
  }

  /// Adds a new `method` to the document in the given `scope`.
  #[wasm_bindgen(js_name = insertMethod)]
  pub fn insert_method(&mut self, method: &WasmVerificationMethod, scope: &WasmMethodScope) -> Result<()> {
    self
      .0
      .try_write()?
      .insert_method(method.0.clone(), scope.0)
      .wasm_result()
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
  /// - The `kid` value in the protected header must be an identifier of a verification method in this DID document,
  /// or set explicitly in the `options`.
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
        jws.0.as_str(),
        detachedPayload.as_deref().map(|detached| detached.as_bytes()),
        &jws_verifier,
        &options.0,
      )
      .map(WasmDecodedJws::from)
      .wasm_result()
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

  /// Deep clones the {@link CoreDocument}.
  #[wasm_bindgen(js_name = clone)]
  pub fn deep_clone(&self) -> Result<WasmCoreDocument> {
    Ok(WasmCoreDocument(Rc::new(CoreDocumentLock::new(
      self.0.try_read()?.clone(),
    ))))
  }

  /// ### Warning
  /// This is for internal use only. Do not rely on or call this method.
  #[wasm_bindgen(js_name = _shallowCloneInternal)]
  pub fn shallow_clone(&self) -> WasmCoreDocument {
    WasmCoreDocument(self.0.clone())
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
    JsValue::from_serde(&self.0.try_read()?.as_ref()).wasm_result()
  }

  /// Deserializes an instance from a plain JS representation.
  #[wasm_bindgen(js_name = fromJSON)]
  pub fn from_json(json: &JsValue) -> Result<WasmCoreDocument> {
    json
      .into_serde()
      .map(|value| Self(Rc::new(CoreDocumentLock::new(value))))
      .wasm_result()
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
    let document_lock_clone: Rc<CoreDocumentLock> = self.0.clone();
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

  /// Remove the method identified by the `fragment` from the document and delete the corresponding key material in
  /// the `storage`.
  #[wasm_bindgen(js_name = purgeMethod)]
  pub fn purge_method(&mut self, storage: &WasmStorage, id: &WasmDIDUrl) -> Result<PromiseVoid> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let document_lock_clone: Rc<CoreDocumentLock> = self.0.clone();
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
    let document_lock_clone: Rc<CoreDocumentLock> = self.0.clone();
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

  /// Produces a JWT where the payload is produced from the given `credential`
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
    let document_lock_clone: Rc<CoreDocumentLock> = self.0.clone();
    let credential_clone: Credential = credential.0.clone();
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
    let document_lock_clone: Rc<CoreDocumentLock> = self.0.clone();
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

  /// Creates a {@link CoreDocument} from the given {@link DIDJwk}.
  #[wasm_bindgen(js_name = expandDIDJwk)]
  pub fn expand_did_jwk(did: WasmDIDJwk) -> Result<WasmCoreDocument> {
    CoreDocument::expand_did_jwk(did.0).wasm_result().map(Self::from)
  }

  /// Creates a {@link CoreDocument} from the given {@link DIDCompositeJwk}.
  #[wasm_bindgen(js_name = expandDIDCompositeJwk)]
  pub fn expand_did_compositejwk(did: WasmDIDCompositeJwk) -> Result<WasmCoreDocument> {
    CoreDocument::expand_did_compositejwk(did.0)
      .wasm_result()
      .map(Self::from)
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "ICoreDocument")]
  pub type ICoreDocument;

  #[wasm_bindgen(typescript_type = "CoreDID | CoreDID[] | null")]
  pub type OptionOneOrManyCoreDID;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[typescript(name = "ICoreDocument", readonly, optional)]
#[allow(non_snake_case, dead_code)]
struct ICoreDocumentHelper {
  #[typescript(optional = false, type = "string | CoreDID | IotaDID")]
  id: Option<CoreDID>,

  #[typescript(type = "(string | CoreDID | IotaDID)[]")]
  controller: Option<OneOrSet<CoreDID>>,

  #[typescript(type = "string[]")]
  alsoKnownAs: Option<OrderedSet<Url>>,

  #[typescript(type = "(VerificationMethod)[]")]
  verificationMethod: Option<OrderedSet<VerificationMethod>>,

  #[typescript(type = "(VerificationMethod | DIDUrl)[]")]
  authentication: Option<OrderedSet<VerificationMethod>>,

  #[typescript(type = "(VerificationMethod | DIDUrl)[]")]
  assertionMethod: Option<OrderedSet<VerificationMethod>>,

  #[typescript(type = "(VerificationMethod | DIDUrl)[]")]
  keyAgreement: Option<OrderedSet<VerificationMethod>>,

  #[typescript(type = "(VerificationMethod | DIDUrl)[]")]
  capabilityDelegation: Option<OrderedSet<VerificationMethod>>,

  #[typescript(type = "(VerificationMethod | DIDUrl)[]")]
  capabilityInvocation: Option<OrderedSet<VerificationMethod>>,

  #[typescript(type = "(Service)[]")]
  service: Option<OrderedSet<Service>>,

  #[serde(flatten)]
  #[typescript(optional = false, name = "[properties: string]", type = "unknown")]
  properties: Object,
}

impl From<CoreDocument> for WasmCoreDocument {
  fn from(doc: CoreDocument) -> Self {
    Self(Rc::new(CoreDocumentLock::new(doc)))
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "CoreDocument | IToCoreDocument")]
  pub type IToCoreDocument;

  #[wasm_bindgen(typescript_type = "Array<CoreDocument | IToCoreDocument>")]
  pub type ArrayIToCoreDocument;

  #[wasm_bindgen(typescript_type = "Promise<Jws>")]
  pub type PromiseJws;

  #[wasm_bindgen(typescript_type = "Promise<Jwt>")]
  pub type PromiseJwt;

  #[wasm_bindgen(typescript_type = "Promise<Jpt>")]
  pub type PromiseJpt;
}

#[wasm_bindgen(typescript_custom_section)]
pub const TS_AS_REF_CORE_Document: &'static str = r#"
interface IToCoreDocument {

  /** Returns a {@link CoreDocument} representation of this Document. */
  toCoreDocument(): CoreDocument;
}"#;
