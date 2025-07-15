// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::sd_jwt_payload::Disclosure;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

/// Represents an elements constructing a disclosure.
/// Object properties and array elements disclosures are supported.
///
/// See: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-disclosures
#[wasm_bindgen(js_name = Disclosure, inspectable)]
pub struct WasmDisclosure(pub(crate) Disclosure);

#[wasm_bindgen(js_class = Disclosure)]
impl WasmDisclosure {
  #[wasm_bindgen(constructor)]
  pub fn new(salt: String, claim_name: Option<String>, claim_value: JsValue) -> Result<WasmDisclosure> {
    Ok(Self(Disclosure::new(
      salt,
      claim_name,
      claim_value.into_serde().wasm_result()?,
    )))
  }

  /// Parses a Base64 encoded disclosure into a `Disclosure`.
  ///
  /// ## Error
  ///
  /// Returns an `InvalidDisclosure` if input is not a valid disclosure.
  #[wasm_bindgen]
  pub fn parse(disclosure: String) -> Result<WasmDisclosure> {
    Ok(WasmDisclosure(Disclosure::parse(disclosure).wasm_result()?))
  }

  /// Returns a copy of the base64url-encoded string.
  #[wasm_bindgen(js_name = disclosure)]
  pub fn disclosure(&self) -> String {
    self.0.disclosure.clone()
  }

  /// Returns a copy of the base64url-encoded string.
  #[wasm_bindgen(js_name = toEncodedString)]
  pub fn to_encoded_string(&self) -> String {
    self.0.disclosure.clone()
  }

  /// Returns a copy of the base64url-encoded string.
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string_clone(&self) -> String {
    self.0.disclosure.clone()
  }

  /// Returns a copy of the salt value.
  #[wasm_bindgen(js_name = salt)]
  pub fn salt(&self) -> String {
    self.0.salt.clone()
  }

  /// Returns a copy of the claim name, optional for array elements.
  #[wasm_bindgen(js_name = claimName)]
  pub fn claim_name(&self) -> Option<String> {
    self.0.claim_name.clone()
  }

  /// Returns a copy of the claim Value which can be of any type.
  #[wasm_bindgen(js_name = claimValue)]
  pub fn claim_value(&self) -> Result<JsValue> {
    JsValue::from_serde(&self.0.claim_value.clone()).wasm_result()
  }
}
impl_wasm_json!(WasmDisclosure, Disclosure);
