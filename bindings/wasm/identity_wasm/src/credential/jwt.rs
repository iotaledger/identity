// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::Jwt;
use wasm_bindgen::prelude::*;

/// A wrapper around a JSON Web Token (JWK).
#[wasm_bindgen(js_name = Jwt)]
pub struct WasmJwt(pub(crate) Jwt);

#[wasm_bindgen(js_class = Jwt)]
impl WasmJwt {
  pub(crate) fn new(jwt: Jwt) -> Self {
    WasmJwt(jwt)
  }

  /// Creates a new {@link Jwt} from the given string.
  #[wasm_bindgen(constructor)]
  pub fn constructor(jwt_string: String) -> Self {
    Self(Jwt::new(jwt_string))
  }

  /// Returns a clone of the JWT string.
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string_clone(&self) -> String {
    self.0.as_str().to_owned()
  }
}

impl_wasm_json!(WasmJwt, Jwt);
impl_wasm_clone!(WasmJwt, Jwt);

impl From<Jwt> for WasmJwt {
  fn from(value: Jwt) -> Self {
    WasmJwt(value)
  }
}

impl From<WasmJwt> for Jwt {
  fn from(value: WasmJwt) -> Self {
    value.0
  }
}
