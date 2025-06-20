// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::jose::jwk::CompositeJwk;

use wasm_bindgen::prelude::*;
use crate::jose::WasmCompositeAlgId;
use crate::jose::WasmJwk;
use crate::jose::IJwkParams;
use crate::error::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[wasm_bindgen(js_name = CompositeJwk)]
pub struct WasmCompositeJwk(pub(crate) CompositeJwk);

#[wasm_bindgen(js_class = CompositeJwk)]
impl WasmCompositeJwk {
  #[wasm_bindgen(constructor)]
  pub fn new(jwk: IJwkParams) -> Result<Self> {
    let jwk = jwk.into_serde()
      .map_err(|e| JsValue::from_str(&format!("Failed to deserialize CompositeJwk: {}", e)))?;
    Ok(Self(jwk))
  }

  #[wasm_bindgen]
  /// Get the `algId` value.
  pub fn alg_id(&self) -> WasmCompositeAlgId {
    //let alg: CompositeAlgId = alg.into_serde().wasm_result()?;
    //JsValue::from(self.0.alg_id()).unchecked_into()
    JsValue::from_serde(&self.0.alg_id()).unwrap()
    .unchecked_into()

    
  }

  /// Get the post-quantum public key in Jwk format.
  #[wasm_bindgen]
  pub fn pq_public_key(&self) -> WasmJwk {
    //JsValue::from(self.0.pq_public_key()).unchecked_into()
    todo!()
  }

  #[wasm_bindgen]
  /// Get the traditional public key in Jwk format.
  pub fn traditional_public_key(&self) -> WasmJwk {
    //self.0.traditional_public_key().map(JsValue::from)
    todo!()
  }

}

impl From<WasmCompositeJwk> for CompositeJwk {
    fn from(value: WasmCompositeJwk) -> Self {
      value.0
    }
}
  

impl From<CompositeJwk> for WasmCompositeJwk {
    fn from(value: CompositeJwk) -> Self {
        WasmCompositeJwk(value)
    }
}