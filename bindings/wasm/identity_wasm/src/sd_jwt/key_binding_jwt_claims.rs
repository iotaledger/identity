// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ArrayString;
use crate::common::RecordStringAny;
use crate::common::WasmTimestamp;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::sd_jwt_payload::KeyBindingJwtClaims;
use identity_iota::sd_jwt_payload::Sha256Hasher;
use js_sys::Array;
use js_sys::JsString;
use serde_json::Value;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

/// Claims set for key binding JWT.
#[wasm_bindgen(js_name = KeyBindingJwtClaims, inspectable)]
pub struct WasmKeyBindingJwtClaims(pub(crate) KeyBindingJwtClaims);

#[wasm_bindgen(js_class = KeyBindingJwtClaims)]
impl WasmKeyBindingJwtClaims {
  /// Creates a new [`KeyBindingJwtClaims`].
  /// When `issued_at` is left as None, it will automatically default to the current time.
  ///
  /// # Error
  /// When `issued_at` is set to `None` and the system returns time earlier than `SystemTime::UNIX_EPOCH`.
  #[wasm_bindgen(constructor)]
  pub fn new(
    jwt: String,
    disclosures: ArrayString,
    nonce: String,
    aud: String,
    issued_at: Option<WasmTimestamp>,
    custom_properties: Option<RecordStringAny>,
  ) -> Result<WasmKeyBindingJwtClaims> {
    let disclosures: Vec<String> = disclosures
      .dyn_into::<Array>()?
      .iter()
      .map(|item| item.dyn_into::<JsString>().map(String::from))
      .collect::<Result<Vec<String>>>()?;
    let mut claims = KeyBindingJwtClaims::new(
      &Sha256Hasher::new(),
      jwt,
      disclosures,
      nonce,
      aud,
      issued_at
        .map(|value| value.0.to_unix())
        .unwrap_or(Timestamp::now_utc().to_unix()),
    );
    if let Some(custom_properties) = custom_properties {
      let custom_properties: BTreeMap<String, Value> = custom_properties.into_serde().wasm_result()?;
      claims.properties = custom_properties
    }
    Ok(WasmKeyBindingJwtClaims(claims))
  }

  /// Returns a string representation of the claims.
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> Result<String> {
    self.0.to_json().wasm_result()
  }

  /// Returns a copy of the issued at `iat` property.
  #[wasm_bindgen]
  pub fn iat(&self) -> i64 {
    self.0.iat
  }

  /// Returns a copy of the audience `aud` property.
  #[wasm_bindgen]
  pub fn aud(&self) -> String {
    self.0.aud.clone()
  }

  /// Returns a copy of the `nonce` property.
  #[wasm_bindgen]
  pub fn nonce(&self) -> String {
    self.0.nonce.clone()
  }

  /// Returns a copy of the `sd_hash` property.
  #[wasm_bindgen(js_name = sdHash)]
  pub fn sd_hash(&self) -> String {
    self.0.sd_hash.clone()
  }

  /// Returns a copy of the custom properties.
  #[wasm_bindgen(js_name = customProperties)]
  pub fn custom_properties(&self) -> Result<RecordStringAny> {
    Ok(
      JsValue::from_serde(&self.0.properties.clone())
        .wasm_result()?
        .unchecked_into::<RecordStringAny>(),
    )
  }

  /// Returns the value of the `typ` property of the JWT header according to
  /// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-key-binding-jwt
  #[wasm_bindgen(js_name = keyBindingJwtHeaderTyp)]
  pub fn header_type() -> String {
    KeyBindingJwtClaims::KB_JWT_HEADER_TYP.to_string()
  }
}

impl_wasm_json!(WasmKeyBindingJwtClaims, KeyBindingJwtClaims);
impl_wasm_clone!(WasmKeyBindingJwtClaims, KeyBindingJwtClaims);
