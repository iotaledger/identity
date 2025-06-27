// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyIdStorage;
use identity_iota::storage::KeyType;
use iota_interaction_ts::bindings::keytool::WasmKeytoolStorage;
use wasm_bindgen::prelude::wasm_bindgen;

use super::WasmJwkGenOutput;
use super::WasmMethodDigest;
use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use crate::jose::WasmJwk;

/// Implementation of {@link JwkStorage} for {@link KeytoolStorage}.
#[wasm_bindgen(js_name = JwkKeytoolStore)]
pub struct WasmJwkKeytoolStore(pub(crate) WasmKeytoolStorage);

#[wasm_bindgen(js_class = JwkKeytoolStore)]
impl WasmJwkKeytoolStore {
  #[wasm_bindgen(constructor)]
  pub fn new(keytool: &WasmKeytoolStorage) -> Self {
    Self(keytool.clone())
  }

  // JwkStorage implementation

  #[wasm_bindgen]
  pub async fn generate(&self, key_type: &str, algorithm: &str) -> Result<WasmJwkGenOutput> {
    let key_type = KeyType::new(key_type);
    let jws_alg = algorithm.parse().wasm_result()?;
    self
      .0
      .as_ref()
      .generate(key_type, jws_alg)
      .await
      .wasm_result()
      .map(WasmJwkGenOutput)
  }

  #[wasm_bindgen]
  pub async fn insert(&self, jwk: WasmJwk) -> Result<String> {
    self
      .0
      .as_ref()
      .insert(jwk.0.clone())
      .await
      .wasm_result()
      .map(|key_id| key_id.to_string())
  }

  #[wasm_bindgen]
  pub async fn sign(&self, key_id: &str, data: &[u8], public_key: &WasmJwk) -> Result<Vec<u8>> {
    let key_id = KeyId::new(key_id);
    self.0.as_ref().sign(&key_id, data, &public_key.0).await.wasm_result()
  }

  #[wasm_bindgen]
  pub async fn delete(&self, key_id: &str) -> Result<()> {
    let key_id = KeyId::new(key_id);
    self.0.as_ref().delete(&key_id).await.wasm_result()
  }

  #[wasm_bindgen]
  pub async fn exists(&self, key_id: &str) -> Result<bool> {
    let key_id = KeyId::new(key_id);
    self.0.as_ref().exists(&key_id).await.wasm_result()
  }
}

/// Implementation of interface {@link KeyIdStorage} for {@link KeytoolStorage}.
#[wasm_bindgen(js_name = KeyIdKeytoolStore)]
pub struct WasmKeyIdKeytoolStore(pub(crate) WasmKeytoolStorage);

#[wasm_bindgen(js_class = KeyIdKeytoolStore)]
impl WasmKeyIdKeytoolStore {
  #[wasm_bindgen(constructor)]
  pub fn new(keytool: &WasmKeytoolStorage) -> Self {
    Self(keytool.clone())
  }

  // KeyIdStorage implementation

  #[wasm_bindgen(js_name = insertKeyId)]
  pub async fn insert_key_id(&self, method_digest: WasmMethodDigest, key_id: &str) -> Result<()> {
    let key_id = KeyId::new(key_id);
    self
      .0
      .as_ref()
      .insert_key_id(method_digest.0, key_id)
      .await
      .wasm_result()
  }

  #[wasm_bindgen(js_name = getKeyId)]
  pub async fn get_key_id(&self, method_digest: &WasmMethodDigest) -> Result<String> {
    self
      .0
      .as_ref()
      .get_key_id(&method_digest.0)
      .await
      .wasm_result()
      .map(|key_id| key_id.to_string())
  }

  #[wasm_bindgen(js_name = deleteKeyId)]
  pub async fn delete_key_id(&self, method_digest: &WasmMethodDigest) -> Result<()> {
    self.0.as_ref().delete_key_id(&method_digest.0).await.wasm_result()
  }
}
