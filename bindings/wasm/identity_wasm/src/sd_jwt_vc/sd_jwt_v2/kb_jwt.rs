// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential;
use identity_iota::credential::sd_jwt_vc;
use identity_iota::sd_jwt_rework::KeyBindingJwt;
use identity_iota::sd_jwt_rework::KeyBindingJwtBuilder;
use identity_iota::sd_jwt_rework::Sha256Hasher;
use js_sys::Object;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::common::WasmTimestamp;
use crate::error::Result;
use crate::error::WasmResult;

use super::WasmJwsSigner;
use super::WasmSdJwt;

#[wasm_bindgen(typescript_custom_section)]
const T_REQUIRED_KB: &str = r#"
type RequiredKeyBinding = { jwk: Jwk }
  | { jwe: string }
  | { kid: string }
  | { jwu: { jwu: string, kid: string }}
  | unknown;
"#;

#[wasm_bindgen(typescript_custom_section)]
const I_KB_JWT_CLAIMS: &str = r#"
interface KeyBindingJwtClaimsV2 {
  iat: number;
  aud: string;
  nonce: string;
  sd_hash: string;
  [properties: string]: unknown;
}
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "RequiredKeyBinding")]
  pub type WasmRequiredKeyBinding;

  #[wasm_bindgen(typescript_type = "KeyBindingJwtClaimsV2")]
  pub type WasmKeyBindingJwtClaims;
}

#[wasm_bindgen(js_name = KeyBindingJwt)]
pub struct WasmKeyBindingJwt(pub(crate) KeyBindingJwt);

#[wasm_bindgen(js_class = KeyBindingJwt)]
impl WasmKeyBindingJwt {
  #[wasm_bindgen]
  pub fn parse(s: &str) -> Result<WasmKeyBindingJwt> {
    s.parse::<KeyBindingJwt>()
      .map_err(sd_jwt_vc::Error::from)
      .map(WasmKeyBindingJwt)
      .wasm_result()
  }

  #[wasm_bindgen]
  pub fn claims(&self) -> WasmKeyBindingJwtClaims {
    serde_wasm_bindgen::to_value(self.0.claims()).unwrap().unchecked_into()
  }

  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = "toString")]
  pub fn to_string(&self) -> String {
    self.0.to_string()
  }

  #[wasm_bindgen(js_name = "toJSON")]
  pub fn to_json(&self) -> JsValue {
    JsValue::from_str(&self.to_string())
  }
}

#[wasm_bindgen(js_name = KeyBindingJwtBuilder)]
pub struct WasmKeyBindingJwtBuilder(pub(crate) KeyBindingJwtBuilder);

#[wasm_bindgen(js_class = KeyBindingJwtBuilder)]
impl WasmKeyBindingJwtBuilder {
  #[allow(clippy::new_without_default)]
  #[wasm_bindgen(constructor)]
  pub fn new() -> WasmKeyBindingJwtBuilder {
    Self(KeyBindingJwtBuilder::default())
  }

  #[wasm_bindgen(js_name = "fromObject")]
  pub fn from_object(obj: Object) -> Result<Self> {
    serde_wasm_bindgen::from_value(obj.into())
      .map(KeyBindingJwtBuilder::from_object)
      .map(Self)
      .wasm_result()
  }

  #[wasm_bindgen]
  pub fn header(self, header: Object) -> Result<Self> {
    serde_wasm_bindgen::from_value(header.into())
      .map(|obj| self.0.header(obj))
      .map(Self)
      .wasm_result()
  }

  #[wasm_bindgen]
  pub fn iat(self, iat: WasmTimestamp) -> Self {
    let iat = iat.0.to_unix();
    Self(self.0.iat(iat))
  }

  #[wasm_bindgen]
  pub fn aud(self, aud: String) -> Self {
    Self(self.0.aud(aud))
  }

  #[wasm_bindgen]
  pub fn nonce(self, nonce: String) -> Self {
    Self(self.0.nonce(nonce))
  }

  #[wasm_bindgen(js_name = "insertProperty")]
  pub fn insert_property(self, name: String, value: JsValue) -> Result<Self> {
    let value = serde_wasm_bindgen::from_value(value).wasm_result()?;
    Ok(Self(self.0.insert_property(&name, value)))
  }

  #[wasm_bindgen]
  pub async fn finish(self, sd_jwt: &WasmSdJwt, alg: &str, signer: &WasmJwsSigner) -> Result<WasmKeyBindingJwt> {
    self
      .0
      .finish(&sd_jwt.0, &Sha256Hasher, alg, signer)
      .await
      .map(WasmKeyBindingJwt)
      .map_err(|e| credential::Error::from(sd_jwt_vc::Error::SdJwt(e)))
      .wasm_result()
  }
}
