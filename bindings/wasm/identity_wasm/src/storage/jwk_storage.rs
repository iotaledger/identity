// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::PromiseBool;
use crate::common::PromiseString;
use crate::common::PromiseUint8Array;
use crate::common::PromiseVoid;
use crate::error::JsValueResult;
use crate::jose::WasmJwk;

use identity_iota::storage::key_storage::JwkGenOutput;
use identity_iota::storage::key_storage::JwkStorage;
use identity_iota::storage::key_storage::KeyId;
use identity_iota::storage::key_storage::KeyStorageError;
use identity_iota::storage::key_storage::KeyStorageErrorKind;
use identity_iota::storage::key_storage::KeyStorageResult;
use identity_iota::storage::key_storage::KeyType;
use identity_iota::verification::jose::jwk::Jwk;
use identity_iota::verification::jose::jws::JwsAlgorithm;
use js_sys::Array;
use js_sys::Promise;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Promise<JwkGenOutput>")]
  pub type PromiseJwkGenOutput;
  #[wasm_bindgen(typescript_type = "Promise<Jwk>")]
  pub type PromiseJwk;
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "JwkStorage")]
  pub type WasmJwkStorage;

  #[wasm_bindgen(method)]
  pub fn generate(this: &WasmJwkStorage, key_type: String, algorithm: String) -> PromiseJwkGenOutput;

  #[wasm_bindgen(method)]
  pub fn insert(this: &WasmJwkStorage, jwk: WasmJwk) -> PromiseString;

  #[wasm_bindgen(method)]
  pub fn sign(this: &WasmJwkStorage, key_id: String, data: Vec<u8>, public_key: WasmJwk) -> PromiseUint8Array;

  #[wasm_bindgen(method)]
  pub fn delete(this: &WasmJwkStorage, key_id: String) -> PromiseVoid;

  #[wasm_bindgen(method)]
  pub fn exists(this: &WasmJwkStorage, key_id: String) -> PromiseBool;

  #[wasm_bindgen(method)]
  pub(crate) fn _get_key(this: &WasmJwkStorage, key_id: &str) -> Option<WasmJwk>;
}

#[async_trait::async_trait(?Send)]
impl JwkStorage for WasmJwkStorage {
  async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    let promise: Promise = Promise::resolve(&WasmJwkStorage::generate(self, key_type.into(), alg.name().to_owned()));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }

  async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId> {
    let promise: Promise = Promise::resolve(&WasmJwkStorage::insert(self, WasmJwk::from(jwk)));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }

  async fn sign(&self, key_id: &KeyId, data: &[u8], public_key: &Jwk) -> KeyStorageResult<Vec<u8>> {
    let promise: Promise = Promise::resolve(&WasmJwkStorage::sign(
      self,
      key_id.clone().into(),
      data.to_owned(),
      WasmJwk(public_key.clone()),
    ));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.to_key_storage_error().map(uint8array_to_bytes)?
  }

  async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
    let promise: Promise = Promise::resolve(&WasmJwkStorage::delete(self, key_id.clone().into()));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }

  async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
    let promise: Promise = Promise::resolve(&WasmJwkStorage::exists(self, key_id.clone().into()));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }
}

#[wasm_bindgen(typescript_custom_section)]
const JWK_STORAGE: &'static str = r#"
/** Secure storage for cryptographic keys represented as JWKs. */
interface JwkStorage {
  /** Generate a new key represented as a JSON Web Key.
   * 
   * It's recommend that the implementer exposes constants for the supported key type string. */
  generate: (keyType: string, algorithm: JwsAlgorithm) => Promise<JwkGenOutput>;
  /** Insert an existing JSON Web Key into the storage.
   * 
   * All private key components of the `jwk` must be set. */
  insert: (jwk: Jwk) => Promise<string>;
  /** Sign the provided `data` using the private key identified by `keyId` according to the requirements of the given `public_key` corresponding to `keyId`. */
  sign: (keyId: string, data: Uint8Array, publicKey: Jwk) => Promise<Uint8Array>;
  /** Deletes the key identified by `keyId`.
   * 
   * # Warning
   * 
   * This operation cannot be undone. The keys are purged permanently. */
  delete: (keyId: string) => Promise<void>;
  /** Returns `true` if the key with the given `keyId` exists in storage, `false` otherwise. */
  exists: (keyId: string) => Promise<boolean>;
}"#;

fn uint8array_to_bytes(value: JsValue) -> KeyStorageResult<Vec<u8>> {
  if !JsCast::is_instance_of::<Uint8Array>(&value) {
    return Err(
      KeyStorageError::new(KeyStorageErrorKind::SerializationError)
        .with_custom_message("expected Uint8Array".to_owned()),
    );
  }
  let array_js_value = JsValue::from(Array::from(&value));
  array_js_value
    .into_serde()
    .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::SerializationError).with_custom_message(e.to_string()))
}
