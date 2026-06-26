// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::DecodedJwtPresentation;
use wasm_bindgen::prelude::*;

use crate::common::RecordStringAny;
use crate::common::WasmTimestamp;
use crate::credential::UnknownCredential;
use crate::credential::WasmPresentation;
use crate::jose::WasmJwsHeader;

/// A cryptographically verified and decoded presentation.
///
/// Note that having an instance of this type only means the JWS it was constructed from was verified.
/// It does not imply anything about a potentially present proof property on the presentation itself.
#[wasm_bindgen(js_name = DecodedJwtPresentation)]
pub struct WasmDecodedJwtPresentation(pub(crate) DecodedJwtPresentation<UnknownCredential>);

#[wasm_bindgen(js_class = DecodedJwtPresentation)]
impl WasmDecodedJwtPresentation {
  #[wasm_bindgen]
  pub fn presentation(&self) -> WasmPresentation {
    WasmPresentation(self.0.presentation.clone())
  }

  /// Returns a copy of the protected header parsed from the decoded JWS.
  #[wasm_bindgen(js_name = protectedHeader)]
  pub fn protected_header(&self) -> WasmJwsHeader {
    WasmJwsHeader(self.0.header.as_ref().clone())
  }

  /// Consumes the object and returns the decoded presentation.
  ///
  /// ### Warning
  /// This destroys the {@link DecodedJwtPresentation} object.
  #[wasm_bindgen(js_name = intoPresentation)]
  pub fn into_presentation(self) -> WasmPresentation {
    WasmPresentation(self.0.presentation)
  }

  /// The expiration date parsed from the JWT claims.
  #[wasm_bindgen(js_name = expirationDate)]
  pub fn expiration_date(&self) -> Option<WasmTimestamp> {
    self.0.expiration_date.map(WasmTimestamp::from)
  }

  /// The issuance date parsed from the JWT claims.
  #[wasm_bindgen(js_name = "issuanceDate")]
  pub fn issuance_date(&self) -> Option<WasmTimestamp> {
    self.0.issuance_date.map(WasmTimestamp::from)
  }

  /// The `aud` property parsed from JWT claims.
  #[wasm_bindgen]
  pub fn audience(&self) -> Option<String> {
    self.0.aud.clone().map(|aud| aud.to_string())
  }

  /// The custom claims parsed from the JWT.
  #[wasm_bindgen(js_name = customClaims)]
  pub fn custom_claims(&self) -> Option<RecordStringAny> {
    match &self.0.custom_claims {
      Some(claims) => JsValue::from_serde(&claims.clone())
        .map(|js_val| js_val.unchecked_into::<RecordStringAny>())
        .ok(),

      None => None,
    }
  }
}

impl From<DecodedJwtPresentation<UnknownCredential>> for WasmDecodedJwtPresentation {
  fn from(decoded_presentation: DecodedJwtPresentation<UnknownCredential>) -> Self {
    Self(decoded_presentation)
  }
}
