// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtCredentialV2;
use wasm_bindgen::prelude::*;

use crate::common::RecordStringAny;
use crate::credential::WasmCredential;
use crate::credential::WasmCredentialV2;
use crate::jose::WasmJwsHeader;

/// A cryptographically verified and decoded Credential.
///
/// Note that having an instance of this type only means the JWS it was constructed from was verified.
/// It does not imply anything about a potentially present proof property on the credential itself.
#[wasm_bindgen(js_name = DecodedJwtCredential)]
pub struct WasmDecodedJwtCredential(pub(crate) DecodedJwtCredential);

#[wasm_bindgen(js_class = DecodedJwtCredential)]
impl WasmDecodedJwtCredential {
  /// Returns a copy of the credential parsed to the [Verifiable Credentials Data model](https://www.w3.org/TR/vc-data-model/).
  #[wasm_bindgen]
  pub fn credential(&self) -> WasmCredential {
    WasmCredential(self.0.credential.clone())
  }

  /// Returns a copy of the protected header parsed from the decoded JWS.
  #[wasm_bindgen(js_name = protectedHeader)]
  pub fn protected_header(&self) -> WasmJwsHeader {
    WasmJwsHeader(self.0.header.as_ref().clone())
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

  /// Consumes the object and returns the decoded credential.
  ///
  /// ### Warning
  ///
  /// This destroys the {@link DecodedJwtCredential} object.
  #[wasm_bindgen(js_name = intoCredential)]
  pub fn into_credential(self) -> WasmCredential {
    WasmCredential(self.0.credential)
  }
}

impl From<DecodedJwtCredential> for WasmDecodedJwtCredential {
  fn from(credential: DecodedJwtCredential) -> Self {
    Self(credential)
  }
}

/// A cryptographically verified and decoded {@link CredentialV2}.
///
/// Note that having an instance of this type only means the JWS it was constructed from was verified.
/// It does not imply anything about a potentially present proof property on the credential itself.
#[wasm_bindgen(js_name = DecodedJwtCredentialV2)]
pub struct WasmDecodedJwtCredentialV2(pub(crate) DecodedJwtCredentialV2);

#[wasm_bindgen(js_class = DecodedJwtCredentialV2)]
impl WasmDecodedJwtCredentialV2 {
  /// Returns a copy of the credential parsed to the [Verifiable Credentials Data model](https://www.w3.org/TR/vc-data-model/).
  #[wasm_bindgen]
  pub fn credential(&self) -> WasmCredentialV2 {
    WasmCredentialV2(self.0.credential.clone())
  }

  /// Returns a copy of the protected header parsed from the decoded JWS.
  #[wasm_bindgen(js_name = protectedHeader)]
  pub fn protected_header(&self) -> WasmJwsHeader {
    WasmJwsHeader(self.0.header.as_ref().clone())
  }

  /// Consumes the object and returns the decoded credential.
  ///
  /// ### Warning
  ///
  /// This destroys the {@link DecodedJwtCredential} object.
  #[wasm_bindgen(js_name = intoCredential)]
  pub fn into_credential(self) -> WasmCredentialV2 {
    WasmCredentialV2(self.0.credential)
  }
}

impl From<DecodedJwtCredentialV2> for WasmDecodedJwtCredentialV2 {
  fn from(credential: DecodedJwtCredentialV2) -> Self {
    Self(credential)
  }
}
