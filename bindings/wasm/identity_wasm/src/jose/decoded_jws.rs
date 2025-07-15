// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmJwsHeader;
use identity_iota::verification::jws::DecodedJws;
use wasm_bindgen::prelude::*;

/// A cryptographically verified decoded token from a JWS.
///
/// Contains the decoded headers and the raw claims.
#[wasm_bindgen(js_name = DecodedJws, inspectable)]
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WasmDecodedJws {
  // We don't include the unprotected header for now as the bindings only support the compact JWS serialization format
  // for now.
  pub(crate) protected_header: WasmJwsHeader,
  pub(crate) claims: Vec<u8>,
}

#[wasm_bindgen(js_class = DecodedJws)]
impl WasmDecodedJws {
  /// Returns a copy of the parsed claims represented as a string.
  ///
  /// # Errors
  /// An error is thrown if the claims cannot be represented as a string.
  ///
  /// This error can only occur if the Token was decoded from a detached payload.  
  #[wasm_bindgen]
  pub fn claims(&self) -> Result<String> {
    String::from_utf8(self.claims.clone()).map_err(|error| JsError::new(&error.to_string()).into())
  }

  /// Return a copy of the parsed claims represented as an array of bytes.
  #[wasm_bindgen(js_name = claimsBytes)]
  pub fn claims_bytes(&self) -> Vec<u8> {
    self.claims.clone()
  }

  /// Returns a copy of the protected header.
  #[wasm_bindgen(js_name = protectedHeader)]
  pub fn protected_header(&self) -> WasmJwsHeader {
    self.protected_header.clone()
  }

  /// Deep clones the object.
  #[wasm_bindgen(js_name = clone)]
  pub fn deep_clone(&self) -> WasmDecodedJws {
    self.clone()
  }

  /// Serializes this to a JSON object.
  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<JsValue> {
    JsValue::from_serde(&self).wasm_result()
  }
}

impl<'a> From<DecodedJws<'a>> for WasmDecodedJws {
  fn from(decoded_jws: DecodedJws<'a>) -> Self {
    let DecodedJws { protected, claims, .. } = decoded_jws;
    Self {
      protected_header: WasmJwsHeader(protected),
      claims: claims.into(),
    }
  }
}
