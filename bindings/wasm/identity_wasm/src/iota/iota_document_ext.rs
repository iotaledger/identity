// Copyright 2020-2025 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use identity_iota::core::Object;

use crate::common::PromiseString;
use crate::common::RecordStringAny;
use crate::credential::UnknownCredential;
use crate::credential::WasmCredential;
use crate::credential::WasmJws;
use crate::credential::WasmJwt;
use crate::credential::WasmPresentation;
use crate::did::PromiseJws;
use crate::did::PromiseJwt;
use crate::error::Result;
use crate::error::WasmResult;
use crate::iota::IotaDocumentLock;
use crate::iota::WasmIotaDocument;
use crate::jose::WasmCompositeAlgId;
use crate::jose::WasmJwsAlgorithm;
use crate::storage::WasmJwsSignatureOptions;
use crate::storage::WasmJwtPresentationOptions;
use crate::storage::WasmStorage;
use crate::storage::WasmStorageInner;
use crate::verification::WasmMethodScope;
use identity_iota::credential::Credential;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::Presentation;
use identity_iota::storage::key_storage::KeyType;
use identity_iota::storage::storage::JwsSignatureOptions;
use identity_iota::storage::JwkDocumentExtHybrid;
use identity_iota::storage::JwsDocumentExtPQC;
use identity_iota::verification::jose::jws::JwsAlgorithm;
use identity_iota::verification::jwk::CompositeAlgId;
use identity_iota::verification::MethodScope;
use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen(js_class = IotaDocument)]
impl WasmIotaDocument {
  /// Generate new PQ key material in the given `storage` and insert a new verification method with the corresponding
  /// public key material into the DID document.
  ///
  /// - If no fragment is given the `kid` of the generated JWK is used, if it is set, otherwise an error is returned.
  /// - The `keyType` must be compatible with the given `storage`. `Storage`s are expected to export key type constants
  /// for that use case.
  ///
  /// The fragment of the generated method is returned.
  #[wasm_bindgen(js_name = generateMethodPQC)]
  #[allow(non_snake_case)]
  pub fn generate_method_pqc(
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
        .generate_method_pqc(&storage_clone, KeyType::from(keyType), alg, fragment.as_deref(), scope)
        .await
        .wasm_result()?;
      Ok(JsValue::from(method_fragment))
    });
    Ok(promise.unchecked_into())
  }

  /// Generate new hybrid key material in the given `storage` and insert a new verification method with the
  /// corresponding public key material into the DID document.
  ///
  /// - If no fragment is given the `kid` of the generated JWK is used, if it is set, otherwise an error is returned.
  /// - The `keyType` must be compatible with the given `storage`. `Storage`s are expected to export key type constants
  /// for that use case.
  ///
  /// The fragment of the generated method is returned.
  #[wasm_bindgen(js_name = generateMethodHybrid)]
  #[allow(non_snake_case)]
  pub fn generate_method_hybrid(
    &self,
    storage: &WasmStorage,
    alg: WasmCompositeAlgId,
    fragment: Option<String>,
    scope: WasmMethodScope,
  ) -> Result<PromiseString> {
    let alg: CompositeAlgId = alg.into_serde().wasm_result()?;
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
    let storage_clone: Rc<WasmStorageInner> = storage.0.clone();
    let scope: MethodScope = scope.0;

    let promise: Promise = future_to_promise(async move {
      let method_fragment: String = document_lock_clone
        .write()
        .await
        .generate_method_hybrid(&storage_clone, alg, fragment.as_deref(), scope)
        .await
        .wasm_result()?;
      Ok(JsValue::from(method_fragment))
    });
    Ok(promise.unchecked_into())
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
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
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
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
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
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
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
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
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
    let document_lock_clone: Rc<IotaDocumentLock> = self.0.clone();
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
}
