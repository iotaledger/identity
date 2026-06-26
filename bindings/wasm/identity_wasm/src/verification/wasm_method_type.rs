// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::MethodType;
use wasm_bindgen::prelude::*;

/// Supported verification method types.
#[wasm_bindgen(js_name = MethodType, inspectable)]
pub struct WasmMethodType(pub(crate) MethodType);

#[wasm_bindgen(js_class = MethodType)]
impl WasmMethodType {
  #[wasm_bindgen(js_name = Ed25519VerificationKey2018)]
  pub fn ed25519_verification_key_2018() -> WasmMethodType {
    WasmMethodType(MethodType::ED25519_VERIFICATION_KEY_2018)
  }

  #[wasm_bindgen(js_name = X25519KeyAgreementKey2019)]
  pub fn x25519_key_agreement_key_2019() -> WasmMethodType {
    WasmMethodType(MethodType::X25519_KEY_AGREEMENT_KEY_2019)
  }

  /// @deprecated Use {@link JsonWebKey2020} instead.
  #[wasm_bindgen(js_name = JsonWebKey, skip_jsdoc)]
  pub fn json_web_key() -> WasmMethodType {
    WasmMethodType(MethodType::JSON_WEB_KEY)
  }

  /// A verification method for use with JWT verification as prescribed by the {@link Jwk}
  /// in the `publicKeyJwk` entry.
  #[wasm_bindgen(js_name = JsonWebKey2020)]
  pub fn json_web_key_2020() -> WasmMethodType {
    WasmMethodType(MethodType::JSON_WEB_KEY_2020)
  }

  /// A custom method.
  pub fn custom(type_: String) -> WasmMethodType {
    WasmMethodType(MethodType::custom(type_))
  }

  /// Returns the {@link MethodType} as a string.
  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> String {
    // Prevents the automatically derived toString which adds quotation marks due to using toJSON.
    self.0.to_string()
  }
}

impl_wasm_json!(WasmMethodType, MethodType);
impl_wasm_clone!(WasmMethodType, MethodType);

impl From<WasmMethodType> for MethodType {
  fn from(wasm_method_type: WasmMethodType) -> Self {
    wasm_method_type.0
  }
}

impl From<MethodType> for WasmMethodType {
  fn from(method_type: MethodType) -> Self {
    WasmMethodType(method_type)
  }
}
