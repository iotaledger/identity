// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Object;
use identity_iota::credential::Proof;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult;

/// Represents a cryptographic proof that can be used to validate verifiable credentials and
/// presentations.
///
/// This representation does not inherently implement any standard; instead, it
/// can be utilized to implement standards or user-defined proofs. The presence of the
/// `type` field is necessary to accommodate different types of cryptographic proofs.
///
/// Note that this proof is not related to JWT and can be used in combination or as an alternative
/// to it.
#[wasm_bindgen(js_name = Proof)]
pub struct WasmProof(pub(crate) Proof);

#[wasm_bindgen(js_class = Proof)]
impl WasmProof {
  #[wasm_bindgen(constructor)]
  pub fn constructor(type_: String, properties: JsValue) -> Result<WasmProof> {
    let properties: Object = properties.into_serde().wasm_result()?;
    Ok(WasmProof(Proof::new(type_, properties)))
  }

  /// Returns the type of proof.
  #[wasm_bindgen(js_name = "type")]
  pub fn type_(&self) -> String {
    self.0.type_.clone()
  }

  /// Returns the properties of the proof.
  #[wasm_bindgen]
  pub fn properties(&self) -> Result<JsValue> {
    JsValue::from_serde(&self.0.properties).wasm_result()
  }
}

impl_wasm_json!(WasmProof, Proof);
impl_wasm_clone!(WasmProof, Proof);
