// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::ops::DerefMut;

use identity_iota::core::Url;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::jws::JwsHeader;
use js_sys::Array;
use js_sys::JsString;
use wasm_bindgen::prelude::*;

use crate::common::ArrayString;
use crate::common::RecordStringAny;
use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmJwk;
use crate::jose::WasmJwsAlgorithm;

#[wasm_bindgen(js_name = JwsHeader)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WasmJwsHeader(pub(crate) JwsHeader);

#[wasm_bindgen(js_class = JwsHeader)]
impl WasmJwsHeader {
  /// Create a new empty {@link JwsHeader}.
  #[wasm_bindgen(constructor)]
  #[allow(clippy::new_without_default)]
  pub fn new() -> WasmJwsHeader {
    WasmJwsHeader(JwsHeader::new())
  }

  /// Returns the value for the algorithm claim (alg).
  #[wasm_bindgen]
  pub fn alg(&self) -> Option<WasmJwsAlgorithm> {
    self
      .0
      .alg()
      .map(|alg| alg.name())
      .map(JsValue::from)
      .map(JsValue::unchecked_into)
  }

  /// Sets a value for the algorithm claim (alg).
  #[wasm_bindgen(js_name = setAlg)]
  pub fn set_alg(&mut self, value: WasmJwsAlgorithm) -> Result<()> {
    self.0.set_alg(JwsAlgorithm::try_from(value)?);
    Ok(())
  }

  /// Returns the value of the base64url-encode payload claim (b64).
  pub fn b64(&self) -> Option<bool> {
    self.0.b64()
  }

  /// Sets a value for the base64url-encode payload claim (b64).
  #[wasm_bindgen(js_name = setB64)]
  pub fn set_b64(&mut self, value: bool) {
    self.0.set_b64(value);
  }

  /// Additional header parameters.
  #[wasm_bindgen(js_name = custom)]
  pub fn custom(&self) -> Option<RecordStringAny> {
    match self.0.custom() {
      Some(claims) => JsValue::from_serde(claims)
        .map(|js_val| js_val.unchecked_into::<RecordStringAny>())
        .ok(),
      None => None,
    }
  }

  // ===========================================================================
  // ===========================================================================

  #[wasm_bindgen]
  pub fn has(&self, claim: &str) -> bool {
    self.0.has(claim)
  }

  /// Returns `true` if none of the fields are set in both `self` and `other`.
  #[wasm_bindgen(js_name = isDisjoint)]
  pub fn is_disjoint(&self, other: &WasmJwsHeader) -> bool {
    self.0.is_disjoint(&other.0)
  }

  // ===========================================================================
  // Common JWT parameters
  // ===========================================================================

  /// Returns the value of the JWK Set URL claim (jku).
  #[wasm_bindgen]
  pub fn jku(&self) -> Option<String> {
    self.0.deref().jku().map(|url| url.to_string())
  }

  /// Sets a value for the JWK Set URL claim (jku).
  #[wasm_bindgen(js_name = setJku)]
  pub fn set_jku(&mut self, value: String) -> Result<()> {
    let url = Url::parse(value).wasm_result()?;
    self.0.deref_mut().set_jku(url);
    Ok(())
  }

  /// Returns the value of the JWK claim (jwk).
  #[wasm_bindgen]
  pub fn jwk(&self) -> Option<WasmJwk> {
    self.0.deref().jwk().map(ToOwned::to_owned).map(WasmJwk)
  }

  /// Sets a value for the JWK claim (jwk).
  #[wasm_bindgen(js_name = setJwk)]
  pub fn set_jwk(&mut self, value: &WasmJwk) {
    self.0.deref_mut().set_jwk(value.0.clone())
  }

  /// Returns the value of the key ID claim (kid).
  #[wasm_bindgen]
  pub fn kid(&self) -> Option<String> {
    self.0.deref().kid().map(ToOwned::to_owned)
  }

  /// Sets a value for the key ID claim (kid).
  #[wasm_bindgen(js_name = setKid)]
  pub fn set_kid(&mut self, value: String) {
    self.0.deref_mut().set_kid(value);
  }

  /// Returns the value of the X.509 URL claim (x5u).
  #[wasm_bindgen]
  pub fn x5u(&self) -> Option<String> {
    self.0.deref().x5u().map(|url| url.to_string())
  }

  /// Sets a value for the X.509 URL claim (x5u).
  #[wasm_bindgen(js_name = setX5u)]
  pub fn set_x5u(&mut self, value: String) -> Result<()> {
    let url = Url::parse(value).wasm_result()?;
    self.0.deref_mut().set_x5u(url);
    Ok(())
  }

  /// Returns the value of the X.509 certificate chain claim (x5c).
  #[wasm_bindgen]
  pub fn x5c(&self) -> ArrayString {
    self
      .0
      .x5c()
      .unwrap_or_default()
      .iter()
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// Sets values for the X.509 certificate chain claim (x5c).
  #[wasm_bindgen(js_name = setX5c)]
  pub fn set_x5c(&mut self, value: ArrayString) -> Result<()> {
    let array: Array = value.dyn_into()?;
    let values: Result<Vec<String>> = array
      .iter()
      .map(|item| item.dyn_into::<JsString>().map(String::from))
      .collect();
    self.0.deref_mut().set_x5c(values?);
    Ok(())
  }

  /// Returns the value of the X.509 certificate SHA-1 thumbprint claim (x5t).
  #[wasm_bindgen]
  pub fn x5t(&self) -> Option<String> {
    self.0.deref().x5t().map(ToOwned::to_owned)
  }

  /// Sets a value for the X.509 certificate SHA-1 thumbprint claim (x5t).
  #[wasm_bindgen(js_name = setX5t)]
  pub fn set_x5t(&mut self, value: String) {
    self.0.deref_mut().set_x5t(value);
  }

  /// Returns the value of the X.509 certificate SHA-256 thumbprint claim
  /// (x5t#S256).
  #[wasm_bindgen(js_name = x5tS256)]
  pub fn x5t_s256(&self) -> Option<String> {
    self.0.deref().x5t_s256().map(ToOwned::to_owned)
  }

  /// Sets a value for the X.509 certificate SHA-256 thumbprint claim
  /// (x5t#S256).
  #[wasm_bindgen(js_name = setX5tS256)]
  pub fn set_x5t_s256(&mut self, value: String) {
    self.0.deref_mut().set_x5t_s256(value);
  }

  /// Returns the value of the token type claim (typ).
  #[wasm_bindgen]
  pub fn typ(&self) -> Option<String> {
    self.0.deref().typ().map(ToOwned::to_owned)
  }

  /// Sets a value for the token type claim (typ).
  #[wasm_bindgen(js_name = setTyp)]
  pub fn set_typ(&mut self, value: String) {
    self.0.deref_mut().set_typ(value);
  }

  /// Returns the value of the content type claim (cty).
  #[wasm_bindgen]
  pub fn cty(&self) -> Option<String> {
    self.0.deref().cty().map(ToOwned::to_owned)
  }

  /// Sets a value for the content type claim (cty).
  #[wasm_bindgen(js_name = setCty)]
  pub fn set_cty(&mut self, value: String) {
    self.0.deref_mut().set_cty(value);
  }

  /// Returns the value of the critical claim (crit).
  #[wasm_bindgen]
  pub fn crit(&self) -> ArrayString {
    self
      .0
      .x5c()
      .unwrap_or_default()
      .iter()
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// Sets values for the critical claim (crit).
  #[wasm_bindgen(js_name = setCrit)]
  pub fn set_crit(&mut self, value: ArrayString) -> Result<()> {
    let array: Array = value.dyn_into()?;
    let values: Result<Vec<String>> = array
      .iter()
      .map(|item| item.dyn_into::<JsString>().map(String::from))
      .collect();
    self.0.deref_mut().set_crit(values?);
    Ok(())
  }

  /// Returns the value of the url claim (url).
  #[wasm_bindgen]
  pub fn url(&self) -> Option<String> {
    self.0.deref().url().map(|url| url.to_string())
  }

  /// Sets a value for the url claim (url).
  #[wasm_bindgen(js_name = setUrl)]
  pub fn set_url(&mut self, value: String) -> Result<()> {
    let url = Url::parse(value).wasm_result()?;
    self.0.deref_mut().set_url(url);
    Ok(())
  }

  /// Returns the value of the nonce claim (nonce).
  #[wasm_bindgen]
  pub fn nonce(&self) -> Option<String> {
    self.0.deref().nonce().map(ToOwned::to_owned)
  }

  /// Sets a value for the nonce claim (nonce).
  #[wasm_bindgen(js_name = setNonce)]
  pub fn set_nonce(&mut self, value: String) {
    self.0.deref_mut().set_nonce(value);
  }
}

impl_wasm_json!(WasmJwsHeader, JwsHeader);
impl_wasm_clone!(WasmJwsHeader, JwsHeader);
