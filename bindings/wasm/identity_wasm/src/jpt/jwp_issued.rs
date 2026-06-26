// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use jsonprooftoken::jwp::issued::JwpIssued;
use wasm_bindgen::prelude::*;

use super::WasmPayloads;
use super::WasmSerializationType;
use crate::error::Result;
use crate::error::WasmResult;
use crate::jpt::WasmIssuerProtectedHeader;

#[wasm_bindgen(js_name = JwpIssued)]
pub struct WasmJwpIssued(pub(crate) JwpIssued);

impl_wasm_json!(WasmJwpIssued, JwpIssued);
impl_wasm_clone!(WasmJwpIssued, JwpIssued);

#[wasm_bindgen(js_class = JwpIssued)]
impl WasmJwpIssued {
  #[wasm_bindgen]
  pub fn encode(&self, serialization: WasmSerializationType) -> Result<String> {
    self.0.encode(serialization.into()).wasm_result()
  }

  #[wasm_bindgen(js_name = "setProof")]
  pub fn set_proof(&mut self, proof: &[u8]) {
    self.0.set_proof(proof)
  }

  #[wasm_bindgen(js_name = "getProof")]
  pub fn get_proof(&self) -> Vec<u8> {
    self.0.get_proof().to_owned()
  }

  #[wasm_bindgen(js_name = "getPayloads")]
  pub fn get_payloads(&self) -> WasmPayloads {
    self.0.get_payloads().clone().into()
  }

  #[wasm_bindgen(js_name = "setPayloads")]
  pub fn set_payloads(&mut self, payloads: WasmPayloads) {
    self.0.set_payloads(payloads.into())
  }

  #[wasm_bindgen(js_name = getIssuerProtectedHeader)]
  pub fn get_issuer_protected_header(&self) -> WasmIssuerProtectedHeader {
    self.0.get_issuer_protected_header().clone().into()
  }
}
