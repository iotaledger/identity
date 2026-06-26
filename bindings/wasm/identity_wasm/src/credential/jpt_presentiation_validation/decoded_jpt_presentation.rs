// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Object;
use identity_iota::credential::DecodedJptPresentation;
use wasm_bindgen::prelude::*;

use crate::common::MapStringAny;
use crate::credential::WasmCredential;
use crate::error::Result;

#[wasm_bindgen(js_name = DecodedJptPresentation)]
pub struct WasmDecodedJptPresentation(pub(crate) DecodedJptPresentation<Object>);

impl_wasm_clone!(WasmDecodedJptPresentation, DecodedJptPresentation);

#[wasm_bindgen(js_class = DecodedJptPresentation)]
impl WasmDecodedJptPresentation {
  /// Returns the {@link Credential} embedded into this JPT.
  #[wasm_bindgen]
  pub fn credential(&self) -> WasmCredential {
    WasmCredential(self.0.credential.clone())
  }

  /// Returns the custom claims parsed from the JPT.
  #[wasm_bindgen(js_name = "customClaims")]
  pub fn custom_claims(&self) -> Result<MapStringAny> {
    match self.0.custom_claims.clone() {
      Some(obj) => MapStringAny::try_from(obj),
      None => Ok(MapStringAny::default()),
    }
  }

  /// Returns the `aud` property parsed from the JWT claims.
  #[wasm_bindgen]
  pub fn aud(&self) -> Option<String> {
    self.0.aud.as_ref().map(ToString::to_string)
  }
}

impl From<DecodedJptPresentation> for WasmDecodedJptPresentation {
  fn from(value: DecodedJptPresentation) -> Self {
    WasmDecodedJptPresentation(value)
  }
}

impl From<WasmDecodedJptPresentation> for DecodedJptPresentation {
  fn from(value: WasmDecodedJptPresentation) -> Self {
    value.0
  }
}
