// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::OnceLock;

use identity_iota::sd_jwt_rework::Hasher;
use identity_iota::sd_jwt_rework::Sha256Hasher;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const I_HASHER: &str = r#"
interface Hasher {
  digest: (input: Uint8Array) => Uint8Array;
  algName: () => string;
  encodedDigest: (data: string) => string;
}
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Hasher")]
  pub type WasmHasher;

  #[wasm_bindgen(structural, method)]
  pub fn digest(this: &WasmHasher, input: &[u8]) -> Vec<u8>;

  #[wasm_bindgen(structural, method, js_name = "algName")]
  pub fn alg_name(this: &WasmHasher) -> String;

  #[wasm_bindgen(structural, method, js_name = "encodedDigest")]
  pub fn encoded_digest(this: &WasmHasher, data: &str) -> String;
}

impl Hasher for WasmHasher {
  fn alg_name(&self) -> &str {
    static ALG: OnceLock<String> = OnceLock::new();
    ALG.get_or_init(|| self.alg_name())
  }

  fn digest(&self, input: &[u8]) -> Vec<u8> {
    self.digest(input)
  }

  fn encoded_digest(&self, disclosure: &str) -> String {
    self.encoded_digest(disclosure)
  }
}

#[wasm_bindgen(js_name = Sha256Hasher)]
pub struct WasmSha256Hasher(pub(crate) Sha256Hasher);

#[wasm_bindgen(js_class = Sha256Hasher)]
impl WasmSha256Hasher {
  #[allow(clippy::new_without_default)]
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
    Self(Sha256Hasher)
  }

  #[wasm_bindgen(js_name = algName)]
  pub fn alg_name(&self) -> String {
    self.0.alg_name().to_owned()
  }

  #[wasm_bindgen]
  pub fn digest(&self, input: &[u8]) -> Vec<u8> {
    self.0.digest(input)
  }

  #[wasm_bindgen(js_name = encodedDigest)]
  pub fn encoded_digest(&self, data: &str) -> String {
    self.0.encoded_digest(data)
  }
}
