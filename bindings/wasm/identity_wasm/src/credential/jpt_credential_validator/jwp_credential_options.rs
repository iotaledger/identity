// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::JwpCredentialOptions;
use serde::Deserialize;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = JwpCredentialOptions, getter_with_clone, inspectable)]
#[derive(Serialize, Deserialize, Default)]
pub struct WasmJwpCredentialOptions {
  pub kid: Option<String>,
}

#[wasm_bindgen(js_class = JwpCredentialOptions)]
impl WasmJwpCredentialOptions {
  #[wasm_bindgen(constructor)]
  pub fn new() -> WasmJwpCredentialOptions {
    WasmJwpCredentialOptions::default()
  }

  #[wasm_bindgen(js_name = fromJSON)]
  pub fn from_json(value: JsValue) -> Result<WasmJwpCredentialOptions> {
    value.into_serde().wasm_result()
  }

  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<JsValue> {
    JsValue::from_serde(self).wasm_result()
  }
}

impl From<WasmJwpCredentialOptions> for JwpCredentialOptions {
  fn from(value: WasmJwpCredentialOptions) -> Self {
    let WasmJwpCredentialOptions { kid } = value;
    let mut jwp_options = JwpCredentialOptions::default();
    jwp_options.kid = kid;

    jwp_options
  }
}

impl From<JwpCredentialOptions> for WasmJwpCredentialOptions {
  fn from(value: JwpCredentialOptions) -> Self {
    WasmJwpCredentialOptions { kid: value.kid }
  }
}
