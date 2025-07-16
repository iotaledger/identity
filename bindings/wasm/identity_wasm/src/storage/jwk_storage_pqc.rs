// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use super::WasmJwkStorage;
use crate::jose::WasmJwk;
use identity_iota::storage::JwkGenOutput;
use identity_iota::storage::JwkStoragePQ;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageError;
use identity_iota::storage::KeyStorageErrorKind;
use identity_iota::storage::KeyStorageResult;
use identity_iota::storage::KeyType;
use identity_iota::verification::jose::jws::JwsAlgorithm;
use identity_iota::verification::jwk::PostQuantumJwk;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {

  #[wasm_bindgen(method, js_name = generatePQKey)]
  pub async fn _generate_pq_key(this: &WasmJwkStorage, key_type: String, alg: String) -> JsValue;

  #[wasm_bindgen(method, js_name = signPQ)]
  pub async fn _pq_sign(
    this: &WasmJwkStorage,
    key_id: String,
    data: Vec<u8>,
    public_key: WasmJwk,
    ctx: Option<&[u8]>,
  ) -> JsValue;

}

#[async_trait::async_trait(?Send)]
impl JwkStoragePQ for WasmJwkStorage {
  async fn generate_pq_key(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    WasmJwkStorage::_generate_pq_key(self, key_type.into(), alg.name().to_owned())
      .await
      .into_serde()
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::SerializationError).with_source(e))
  }

  async fn pq_sign(
    &self,
    key_id: &KeyId,
    data: &[u8],
    public_key: &PostQuantumJwk,
    ctx: Option<&[u8]>,
  ) -> KeyStorageResult<Vec<u8>> {
    let value = WasmJwkStorage::_pq_sign(
      self,
      key_id.clone().into(),
      data.to_owned(),
      WasmJwk(public_key.clone().into()),
      ctx,
    )
    .await;

    uint8array_to_bytes(value)
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
