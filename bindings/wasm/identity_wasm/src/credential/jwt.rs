// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::Jwt;
use identity_iota::credential::JwtVcV2;
use wasm_bindgen::prelude::*;

use crate::credential::WasmEnvelopedVc;

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

/// A wrapper around a JWT Verifiable Credential V2.
#[wasm_bindgen(js_name = JwtVcV2)]
pub struct WasmJwtVcV2(pub(crate) JwtVcV2);

#[wasm_bindgen(js_class = JwtVcV2)]
impl WasmJwtVcV2 {
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> String {
    self.0.as_str().to_owned()
  }

  /// Attempts to create a {@link JwtVcV2} from the given {@link EnvelopedVc}.
  /// # Errors
  /// This function fails if the media type of the given {@link EnvelopedVc}
  /// is not `application/vc+jwt`.
  #[wasm_bindgen(js_name = fromEnvelopedVc)]
  pub fn try_from_enveloped_vc(enveloped_vc: WasmEnvelopedVc) -> Result<Self, JsError> {
    let jwt_vc = JwtVcV2::try_from(enveloped_vc.0)?;
    Ok(Self(jwt_vc))
  }

  /// Converts this {@link JwtVcV2} into an {@link EnvelopedVc} for use in verifiable
  /// presentations.
  #[wasm_bindgen(js_name = intoEnvelopedVc)]
  pub fn into_enveloped_vc(self) -> WasmEnvelopedVc {
    WasmEnvelopedVc(self.0.into_enveloped_vc())
  }
}

impl_wasm_clone!(WasmJwtVcV2, JwtVcV2);

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Jwt | JwtVcV2")]
  pub type AnyJwt;

  #[wasm_bindgen(method, js_name = toString)]
  pub fn to_string(this: &AnyJwt) -> String;
}
