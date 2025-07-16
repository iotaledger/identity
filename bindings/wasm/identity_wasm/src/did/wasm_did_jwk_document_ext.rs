// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use super::CoreDocumentLock;
use super::WasmCoreDocument;
use crate::common::RecordStringAny;
use crate::credential::PromiseJpt;
use crate::credential::UnknownCredential;
use crate::credential::WasmCredential;
use crate::credential::WasmJpt;
use crate::credential::WasmJwpPresentationOptions;
use crate::credential::WasmJws;
use crate::credential::WasmJwt;
use crate::credential::WasmPresentation;
use crate::did::PromiseJws;
use crate::did::PromiseJwt;
use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmCompositeAlgId;
use crate::jose::WasmJwsAlgorithm;
use crate::jpt::WasmProofAlgorithm;
use crate::jpt::WasmSelectiveDisclosurePresentation;
use crate::storage::WasmJwsSignatureOptions;
use crate::storage::WasmJwtPresentationOptions;
use crate::storage::WasmStorage;
use crate::storage::WasmStorageInner;
use identity_iota::core::Object;
use identity_iota::credential::Credential;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::Presentation;
use identity_iota::document::CoreDocument;
use identity_iota::storage::key_storage::KeyType;
use identity_iota::storage::storage::JwkDocumentExtHybrid;
use identity_iota::storage::storage::JwsDocumentExtPQC;
use identity_iota::storage::DidJwkDocumentExt;
use identity_iota::storage::JwpDocumentExt;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::verification::jwk::CompositeAlgId;
use identity_iota::verification::jws::JwsAlgorithm;
use js_sys::Promise;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen(js_class = CoreDocument)]
impl WasmCoreDocument {
  /// Creates a new DID Document with the given `key_type` and `alg` with the JWK did method.
  #[wasm_bindgen(js_name = newDidJwk)]
  pub async fn _new_did_jwk(
    storage: &WasmStorage,
    key_type: String,
    alg: WasmJwsAlgorithm,
  ) -> Result<WasmCoreDocument> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let alg: JwsAlgorithm = alg.into_serde().wasm_result()?;
    CoreDocument::new_did_jwk(&storage_clone, KeyType::from(key_type), alg)
      .await
      .map(|doc| WasmCoreDocument(Rc::new(CoreDocumentLock::new(doc.0))))
      .wasm_result()
  }

  /// Creates a new PQ DID Document with the given `key_type` and `alg` with the JWK did method.
  #[wasm_bindgen(js_name = newDidJwkPq)]
  pub async fn _new_did_jwk_pqc(
    storage: &WasmStorage,
    key_type: String,
    alg: WasmJwsAlgorithm,
  ) -> Result<WasmCoreDocument> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let alg: JwsAlgorithm = alg.into_serde().wasm_result()?;
    CoreDocument::new_did_jwk_pqc(&storage_clone, KeyType::from(key_type), alg)
      .await
      .map(|doc| WasmCoreDocument(Rc::new(CoreDocumentLock::new(doc.0))))
      .wasm_result()
  }

  /// Creates a new hybrid DID Document with the given `key_type` and `alg`with the compositeJWK did method.
  #[wasm_bindgen(js_name = newDidCompositeJwk)]
  pub async fn _new_did_compositejwk(storage: &WasmStorage, alg: WasmCompositeAlgId) -> Result<WasmCoreDocument> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let alg: CompositeAlgId = alg.into_serde().wasm_result()?;
    CoreDocument::new_did_compositejwk(&storage_clone, alg)
      .await
      .map(|doc| WasmCoreDocument(Rc::new(CoreDocumentLock::new(doc.0))))
      .wasm_result()
  }

  /// Creates a new zk DID Document with the given `key_type` and `alg` with the JWK did method.
  #[wasm_bindgen(js_name = newDidJwkZk)]
  pub async fn _new_did_jwk_zk(storage: &WasmStorage, alg: WasmProofAlgorithm) -> Result<WasmCoreDocument> {
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let alg: ProofAlgorithm = alg.into();
    CoreDocument::new_did_jwk_zk(&storage_clone, KeyType::from_static_str("BLS12381"), alg)
      .await
      .map(|doc| WasmCoreDocument(Rc::new(CoreDocumentLock::new(doc.0))))
      .wasm_result()
  }

  #[wasm_bindgen(js_name = fragmentJwk)]
  pub fn _fragment(self) -> String {
    "0".to_string()
  }
  /// Produces a PQ JWS, from a document with a PQ method, where the payload is produced from the given `fragment` and
  /// `payload`.
  #[wasm_bindgen(js_name = createPqJws)]
  pub fn _create_pq_jws(
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
        .create_jws_pqc(&storage_clone, &fragment, payload.as_bytes(), &options_clone)
        .await
        .wasm_result()
        .map(WasmJws::new)
        .map(JsValue::from)
    });
    Ok(promise.unchecked_into())
  }

  /// Produces an hybrid JWS, from a document with an hybrid method, where the payload is produced from the given
  /// `fragment` and `payload`.
  #[wasm_bindgen(js_name = createHybridJws)]
  pub fn create_hybrid_jws(
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

  /// Produces a PQ JWT, from a document with a PQ method, where the payload is produced from the given `credential`
  /// in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  ///
  /// The `custom_claims` can be used to set additional claims on the resulting JWT.
  #[wasm_bindgen(js_name = createCredentialJwtPqc)]
  pub fn _create_credential_jwt_pqc(
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
        .create_credential_jwt_pqc(&credential_clone, &storage_clone, &fragment, &options_clone, custom)
        .await
        .wasm_result()
        .map(WasmJwt::new)
        .map(JsValue::from)
    });
    Ok(promise.unchecked_into())
  }

  /// Produces an hybrid JWT, from a document with an hybrid method, where the payload is produced from the given
  /// `credential` in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  ///
  /// The `custom_claims` can be used to set additional claims on the resulting JWT.
  #[wasm_bindgen(js_name = createCredentialJwtHybrid)]
  pub fn _create_credential_jwt_hybrid(
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
        .create_credential_jwt_hybrid(&credential_clone, &storage_clone, &fragment, &options_clone, custom)
        .await
        .wasm_result()
        .map(WasmJwt::new)
        .map(JsValue::from)
    });
    Ok(promise.unchecked_into())
  }

  /// Produces a PQ JWT, from a document with a PQ method, where the payload is produced from the given presentation.
  /// in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  #[wasm_bindgen(js_name = createPresentationJwtPqc)]
  pub fn _create_presentation_jwt_pqc(
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
        .create_presentation_jwt_pqc(
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

  /// Produces an hybrid JWT, from a document with an hybrid method, where the payload is produced from the given
  /// presentation. in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  #[wasm_bindgen(js_name = createPresentationJwtHybrid)]
  pub fn _create_presentation_jwt_hybrid(
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
        .create_presentation_jwt_hybrid(
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

  #[wasm_bindgen(js_name = createPresentationJpt)]
  pub fn create_presentation_jpt(
    &self,
    presentation: WasmSelectiveDisclosurePresentation,
    method_id: String,
    options: WasmJwpPresentationOptions,
  ) -> Result<PromiseJpt> {
    let document_lock_clone: Rc<CoreDocumentLock> = self.0.clone();
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
