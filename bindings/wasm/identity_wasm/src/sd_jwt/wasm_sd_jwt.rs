// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ArrayString;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::sd_jwt_payload::SdJwt;
use js_sys::Array;
use js_sys::JsString;
use wasm_bindgen::prelude::*;

/// Representation of an SD-JWT of the format
/// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>`.
#[wasm_bindgen(js_name = SdJwt, inspectable)]
pub struct WasmSdJwt(pub(crate) SdJwt);

#[wasm_bindgen(js_class = SdJwt)]
impl WasmSdJwt {
  /// Creates a new `SdJwt` from its components.
  #[wasm_bindgen(constructor)]
  pub fn new(jwt: String, disclosures: ArrayString, key_binding_jwt: Option<String>) -> Result<WasmSdJwt> {
    let disclosures: Vec<String> = disclosures
      .dyn_into::<Array>()?
      .iter()
      .map(|item| item.dyn_into::<JsString>().map(String::from))
      .collect::<Result<Vec<String>>>()?;
    let sd_jwt = SdJwt::new(jwt, disclosures, key_binding_jwt);
    Ok(WasmSdJwt(sd_jwt))
  }

  /// Serializes the components into the final SD-JWT.
  #[wasm_bindgen]
  pub fn presentation(&self) -> String {
    self.0.presentation()
  }

  /// Parses an SD-JWT into its components as [`SdJwt`].
  ///
  /// ## Error
  /// Returns `DeserializationError` if parsing fails.
  #[wasm_bindgen]
  pub fn parse(sd_jwt: String) -> Result<WasmSdJwt> {
    let sd_jwt = SdJwt::parse(&sd_jwt).wasm_result()?;
    Ok(WasmSdJwt(sd_jwt))
  }

  /// Serializes the components into the final SD-JWT.
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string_clone(&self) -> String {
    self.0.presentation()
  }

  /// The JWT part.
  #[wasm_bindgen]
  pub fn jwt(&self) -> String {
    self.0.jwt.clone()
  }

  /// The disclosures part.
  #[wasm_bindgen]
  pub fn disclosures(&self) -> ArrayString {
    self
      .0
      .disclosures
      .clone()
      .iter()
      .map(|url| url.to_string())
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// The optional key binding JWT.
  #[wasm_bindgen(js_name = keyBindingJwt)]
  pub fn key_binding_jwt(&self) -> Option<String> {
    self.0.key_binding_jwt.clone()
  }
}

impl_wasm_clone!(WasmSdJwt, SdJwt);
