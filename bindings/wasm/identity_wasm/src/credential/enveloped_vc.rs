// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::EnvelopedVc;
use identity_iota::credential::VcDataUrl;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::JsError;
use wasm_bindgen::JsValue;

use crate::credential::ArrayContext;
use crate::error::WasmResult;

/// An Enveloped Verifiable Credential as defined in
/// [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials).
#[wasm_bindgen(js_name = EnvelopedVc)]
pub struct WasmEnvelopedVc(pub(crate) EnvelopedVc);

#[wasm_bindgen(js_class = EnvelopedVc)]
impl WasmEnvelopedVc {
  /// Creates a new {@link EnvelopedVc} from the given Data URL-encoded VC.
  #[wasm_bindgen(constructor)]
  pub fn new(vc_data_url: String) -> Result<Self, JsError> {
    let enveloped_vc = EnvelopedVc::new(VcDataUrl::parse(&vc_data_url)?);
    Ok(Self(enveloped_vc))
  }

  /// Data URL-encoded VC.
  #[wasm_bindgen(getter)]
  pub fn id(&self) -> String {
    self.0.id.to_string()
  }

  /// This {@link EnvelopedVc}'s JSON-LD context.
  #[wasm_bindgen(getter)]
  pub fn context(&self) -> Result<ArrayContext, JsValue> {
    self
      .0
      .context()
      .iter()
      .map(serde_wasm_bindgen::to_value)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayContext>())
  }

  #[wasm_bindgen(js_name = "type", getter)]
  pub fn type_(&self) -> String {
    self.0.type_().to_owned()
  }
}

impl_wasm_json!(WasmEnvelopedVc, EnvelopedVc);
