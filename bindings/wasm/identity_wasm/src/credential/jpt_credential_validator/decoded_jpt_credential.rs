// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Object;
use identity_iota::credential::DecodedJptCredential;
use wasm_bindgen::prelude::*;

use crate::common::MapStringAny;
use crate::credential::WasmCredential;
use crate::error::Result;
use crate::jpt::WasmJwpIssued;

#[wasm_bindgen(js_name = DecodedJptCredential)]
pub struct WasmDecodedJptCredential(pub(crate) DecodedJptCredential<Object>);

impl_wasm_clone!(WasmDecodedJptCredential, DecodedJptCredential);

#[wasm_bindgen(js_class = DecodedJptCredential)]
impl WasmDecodedJptCredential {
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

  // The decoded and verified issued JWP, will be used to construct the presented JWP.
  #[wasm_bindgen(js_name = decodedJwp)]
  pub fn decoded_jwp(&self) -> WasmJwpIssued {
    WasmJwpIssued(self.0.decoded_jwp.clone())
  }
}

impl From<DecodedJptCredential> for WasmDecodedJptCredential {
  fn from(value: DecodedJptCredential) -> Self {
    WasmDecodedJptCredential(value)
  }
}

impl From<WasmDecodedJptCredential> for DecodedJptCredential {
  fn from(value: WasmDecodedJptCredential) -> Self {
    value.0
  }
}
