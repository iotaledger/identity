// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Url;
use identity_iota::credential::sd_jwt_vc::metadata::IssuerMetadata;
use serde::Serialize;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::error::WasmResult;
use crate::sd_jwt_vc::WasmSdJwtVc;

#[wasm_bindgen(typescript_custom_section)]
pub const I_JWKS: &str = r#"
type Jwks = { jwks_uri: string } | { jwks: { keys: IJwk[] }};
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = Jwks)]
  pub type WasmJwks;
}

#[wasm_bindgen(js_name = IssuerMetadata)]
pub struct WasmIssuerMetadata(pub(crate) IssuerMetadata);

#[wasm_bindgen(js_class = IssuerMetadata)]
impl WasmIssuerMetadata {
  #[wasm_bindgen(constructor)]
  pub fn new(issuer: String, jwks: WasmJwks) -> Result<Self> {
    let issuer = Url::parse(&issuer).wasm_result()?;
    let jwks = serde_wasm_bindgen::from_value(jwks.into()).wasm_result()?;

    Ok(Self(IssuerMetadata { issuer, jwks }))
  }

  #[wasm_bindgen]
  pub fn issuer(&self) -> String {
    self.0.issuer.to_string()
  }

  #[wasm_bindgen]
  pub fn jwks(&self) -> Result<WasmJwks> {
    serde_wasm_bindgen::to_value(&self.0.jwks)
      .wasm_result()
      .map(JsCast::unchecked_into)
  }

  /// Checks the validity of this {@link IssuerMetadata}.
  /// {@link IssuerMetadata.issuer} must match `sd_jwt_vc`'s `iss` claim.
  #[wasm_bindgen]
  pub fn validate(&self, sd_jwt_vc: &WasmSdJwtVc) -> Result<()> {
    self.0.validate(&sd_jwt_vc.0).wasm_result()
  }

  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<JsValue> {
    let js_serializer = serde_wasm_bindgen::Serializer::default().serialize_maps_as_objects(true);
    self.0.serialize(&js_serializer).wasm_result()
  }
}
