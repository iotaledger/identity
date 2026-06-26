// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Url;
use identity_iota::credential::JwpPresentationOptions;
use wasm_bindgen::prelude::*;

/// Options to be set in the JWT claims of a verifiable presentation.
#[wasm_bindgen(js_name = JwpPresentationOptions, inspectable, getter_with_clone)]
#[derive(Default, Clone)]
pub struct WasmJwpPresentationOptions {
  /// Sets the audience for presentation (`aud` property in JWP Presentation Header).
  pub audience: Option<String>,
  /// The nonce to be placed in the Presentation Protected Header.
  pub nonce: Option<String>,
}

#[wasm_bindgen(js_class = JwpPresentationOptions)]
impl WasmJwpPresentationOptions {
  #[wasm_bindgen(constructor)]
  pub fn new() -> WasmJwpPresentationOptions {
    Self::default()
  }
}

impl TryFrom<WasmJwpPresentationOptions> for JwpPresentationOptions {
  type Error = JsError;
  fn try_from(value: WasmJwpPresentationOptions) -> Result<Self, Self::Error> {
    let WasmJwpPresentationOptions { audience, nonce } = value;
    let audience = audience
      .map(Url::parse)
      .transpose()
      .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(JwpPresentationOptions { audience, nonce })
  }
}
