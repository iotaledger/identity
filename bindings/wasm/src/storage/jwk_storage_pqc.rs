// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use super::WasmJwkStorage;
use identity_iota::storage::JwkGenOutput;
use identity_iota::storage::JwkStoragePQ;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageResult;
use identity_iota::storage::KeyType;
use identity_iota::verification::jwk::PostQuantumJwk;
use wasm_bindgen::prelude::*;
use crate::error::JsValueResult;
use js_sys::Promise;
use identity_iota::storage::KeyStorageErrorKind;
use identity_iota::verification::jose::jws::JwsAlgorithm;
use identity_iota::storage::KeyStorageError;
use wasm_bindgen_futures::JsFuture;
use super::jwk_storage::PromiseJwkGenOutput;
use crate::jose::WasmJwk;
use js_sys::Uint8Array;

use crate::common::PromiseUint8Array;

#[wasm_bindgen]
extern "C" {

  #[wasm_bindgen(method, js_name = generatePQKey)]
  pub fn _generate_pq_key(this: &WasmJwkStorage, key_type: String, alg: String) -> PromiseJwkGenOutput;

  #[wasm_bindgen(method, js_name = signPQ)]
  pub fn _pq_sign(this: &WasmJwkStorage, key_id: String, data: Vec<u8>, public_key: WasmJwk, ctx: Option<&[u8]>) -> PromiseUint8Array;

}


#[async_trait::async_trait(?Send)]
impl JwkStoragePQ for WasmJwkStorage {
  async fn generate_pq_key(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    let promise: Promise = Promise::resolve(&WasmJwkStorage::_generate_pq_key(self, key_type.into(), alg.name().to_owned()));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }

  async fn pq_sign(&self, key_id: &KeyId, data: &[u8], public_key: &PostQuantumJwk, ctx: Option<&[u8]>) -> KeyStorageResult<Vec<u8>> {
    let promise: Promise = Promise::resolve(&WasmJwkStorage::_pq_sign(
      self,
      key_id.clone().into(),
      data.to_owned(),
      WasmJwk(public_key.clone().into()),
      ctx
    ));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.to_key_storage_error().map(uint8array_to_bytes)?
  }

}

#[wasm_bindgen(typescript_custom_section)]
const JWK_STORAGE_PQ: &'static str = r#"
/** Secure storage for cryptographic keys represented as JWKs. */
interface JwkStoragePQ {
  /** Generate a new PQ key represented as a JSON Web Key.
   * 
   * It's recommend that the implementer exposes constants for the supported key type string. */
  generatePQKey: (keyType: string, algorithm: JwsAlgorithm) => Promise<JwkGenOutput>;

  signPQ: (keyId: string, data: Uint8Array, publicKey: Jwk, ctx: Uint8Array|undefined ) => Promise<Uint8Array>;
}"#;

fn uint8array_to_bytes(value: JsValue) -> KeyStorageResult<Vec<u8>> {
  if !JsCast::is_instance_of::<Uint8Array>(&value) {
    return Err(
      KeyStorageError::new(KeyStorageErrorKind::SerializationError)
        .with_custom_message("expected Uint8Array".to_owned()),
    );
  }
  Ok(Uint8Array::new(&value).to_vec())
}