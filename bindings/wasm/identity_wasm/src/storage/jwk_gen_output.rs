// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::storage::key_storage::JwkGenOutput;
use identity_iota::storage::key_storage::KeyId;
use wasm_bindgen::prelude::*;

use crate::jose::WasmJwk;

/// The result of a key generation in `JwkStorage`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[wasm_bindgen(js_name = JwkGenOutput, inspectable)]
pub struct WasmJwkGenOutput(pub(crate) JwkGenOutput);

#[wasm_bindgen(js_class = JwkGenOutput)]
impl WasmJwkGenOutput {
  #[wasm_bindgen(constructor)]
  pub fn new(key_id: String, jwk: &WasmJwk) -> Self {
    Self(JwkGenOutput::new(KeyId::new(key_id), jwk.clone().into()))
  }

  /// Returns the generated public {@link Jwk}.
  #[wasm_bindgen]
  pub fn jwk(&self) -> WasmJwk {
    WasmJwk(self.0.jwk.clone())
  }

  /// Returns the key id of the generated {@link Jwk}.
  #[wasm_bindgen(js_name = keyId)]
  pub fn key_id(&self) -> String {
    self.0.key_id.clone().into()
  }
}

impl From<WasmJwkGenOutput> for JwkGenOutput {
  fn from(value: WasmJwkGenOutput) -> Self {
    value.0
  }
}

impl From<JwkGenOutput> for WasmJwkGenOutput {
  fn from(value: JwkGenOutput) -> Self {
    WasmJwkGenOutput(value)
  }
}

impl_wasm_json!(WasmJwkGenOutput, JwkGenOutput);
impl_wasm_clone!(WasmJwkGenOutput, JwkGenOutput);
