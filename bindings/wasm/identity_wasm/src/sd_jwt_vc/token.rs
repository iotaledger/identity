// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use identity_iota::core::Url;
use identity_iota::credential::sd_jwt_vc::metadata::ClaimMetadata;
use identity_iota::credential::sd_jwt_vc::vct_to_url as vct_to_url_impl;
use identity_iota::credential::sd_jwt_vc::SdJwtVc;
use wasm_bindgen::prelude::*;

use crate::credential::WasmKeyBindingJWTValidationOptions;
use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmJwk;
use crate::sd_jwt_vc::metadata::WasmTypeMetadata;
use crate::verification::IJwsVerifier;
use crate::verification::WasmJwsVerifier;

use super::metadata::WasmClaimMetadata;
use super::metadata::WasmIssuerMetadata;
use super::resolver::ResolverStringToUint8Array;
use super::sd_jwt_v2::WasmHasher;
use super::sd_jwt_v2::WasmSdJwt;
use super::WasmSdJwtVcClaims;
use super::WasmSdJwtVcPresentationBuilder;

#[derive(Clone)]
#[wasm_bindgen(js_name = SdJwtVc)]
pub struct WasmSdJwtVc(pub(crate) SdJwtVc);

impl_wasm_clone!(WasmSdJwtVc, SdJwtVc);

#[wasm_bindgen(js_class = "SdJwtVc")]
impl WasmSdJwtVc {
  /// Parses a `string` into an {@link SdJwtVc}.
  #[wasm_bindgen]
  pub fn parse(s: &str) -> Result<Self> {
    SdJwtVc::parse(s).map(WasmSdJwtVc).wasm_result()
  }

  #[wasm_bindgen]
  pub fn claims(&self) -> Result<WasmSdJwtVcClaims> {
    serde_wasm_bindgen::to_value(self.0.claims())
      .map(JsCast::unchecked_into)
      .wasm_result()
  }

  #[wasm_bindgen(js_name = "asSdJwt")]
  pub fn as_sd_jwt(&self) -> WasmSdJwt {
    WasmSdJwt(self.0.deref().clone())
  }

  #[wasm_bindgen(js_name = "issuerJwk")]
  pub async fn issuer_jwk(&self, resolver: &ResolverStringToUint8Array) -> Result<WasmJwk> {
    self.0.issuer_jwk(resolver).await.map(WasmJwk).wasm_result()
  }

  #[wasm_bindgen(js_name = "issuerMetadata")]
  pub async fn issuer_metadata(&self, resolver: &ResolverStringToUint8Array) -> Result<Option<WasmIssuerMetadata>> {
    self
      .0
      .issuer_metadata(resolver)
      .await
      .map(|maybe_metadata| maybe_metadata.map(WasmIssuerMetadata))
      .wasm_result()
  }

  #[wasm_bindgen(js_name = "typeMetadata")]
  pub async fn type_metadata(&self, resolver: &ResolverStringToUint8Array) -> Result<WasmTypeMetadata> {
    self
      .0
      .type_metadata(resolver)
      .await
      .map(|(metadata, _)| WasmTypeMetadata(metadata))
      .wasm_result()
  }

  /// Verifies this {@link SdJwtVc} JWT's signature.
  #[wasm_bindgen(js_name = "verifySignature")]
  pub fn verify_signature(&self, jwk: &WasmJwk, jws_verifier: Option<IJwsVerifier>) -> Result<()> {
    let verifier = WasmJwsVerifier::new(jws_verifier);
    self.0.verify_signature(&verifier, &jwk.0).wasm_result()
  }

  /// Checks the disclosability of this {@link SdJwtVc}'s claims against a list of {@link ClaimMetadata}.
  /// ## Notes
  /// This check should be performed by the token's holder in order to assert the issuer's compliance with
  /// the credential's type.
  #[wasm_bindgen(js_name = "validateClaimDisclosability")]
  pub fn validate_claims_disclosability(&self, claims_metadata: Vec<WasmClaimMetadata>) -> Result<()> {
    let claims_metadata = claims_metadata.into_iter().map(ClaimMetadata::from).collect::<Vec<_>>();
    self.0.validate_claims_disclosability(&claims_metadata).wasm_result()
  }

  /// Check whether this {@link SdJwtVc} is valid.
  ///
  /// This method checks:
  /// - JWS signature
  /// - credential's type
  /// - claims' disclosability
  #[wasm_bindgen]
  pub async fn validate(
    &self,
    resolver: &ResolverStringToUint8Array,
    hasher: &WasmHasher,
    jws_verifier: Option<IJwsVerifier>,
  ) -> Result<()> {
    let jws_verifier = WasmJwsVerifier::new(jws_verifier);
    self.0.validate(resolver, &jws_verifier, hasher).await.wasm_result()
  }

  /// Verify the signature of this {@link SdJwtVc}'s {@link KeyBindingJwt}.
  #[wasm_bindgen(js_name = "verifyKeyBinding")]
  pub fn verify_key_binding(&self, jwk: &WasmJwk, jws_verifier: Option<IJwsVerifier>) -> Result<()> {
    let verifier = WasmJwsVerifier::new(jws_verifier);
    self.0.verify_key_binding(&verifier, &jwk.0).wasm_result()
  }

  #[wasm_bindgen(js_name = "validateKeyBinding")]
  pub fn validate_key_binding(
    &self,
    jwk: &WasmJwk,
    hasher: &WasmHasher,
    options: &WasmKeyBindingJWTValidationOptions,
    jws_verifier: Option<IJwsVerifier>,
  ) -> Result<()> {
    let jws_verifier = WasmJwsVerifier::new(jws_verifier);
    self
      .0
      .validate_key_binding(&jws_verifier, &jwk.0, hasher, &options.0)
      .wasm_result()
  }

  #[wasm_bindgen(js_name = "intoSdJwt")]
  pub fn into_sd_jwt(self) -> WasmSdJwt {
    WasmSdJwt(self.0.into())
  }

  #[wasm_bindgen(js_name = "intoDisclosedObject")]
  pub fn into_disclosed_object(&self, hasher: &WasmHasher) -> Result<js_sys::Object> {
    self
      .0
      .clone()
      .into_disclosed_object(hasher)
      .map(|obj| serde_wasm_bindgen::to_value(&obj).expect("JSON object is a valid JS object"))
      .map(JsCast::unchecked_into)
      .wasm_result()
  }

  #[wasm_bindgen(js_name = "intoPresentation")]
  pub fn into_presentation(self, hasher: &WasmHasher) -> Result<WasmSdJwtVcPresentationBuilder> {
    WasmSdJwtVcPresentationBuilder::new(self, hasher)
  }

  #[wasm_bindgen(js_name = "toJSON")]
  pub fn to_json(&self) -> JsValue {
    JsValue::from_str(&self.0.to_string())
  }

  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = "toString")]
  pub fn to_string(&self) -> JsValue {
    JsValue::from_str(&self.0.to_string())
  }
}

#[wasm_bindgen(js_name = "vctToUrl")]
pub fn vct_to_url(resource: &str) -> Option<String> {
  let url = resource.parse::<Url>().ok()?;
  vct_to_url_impl(&url).map(|url| url.to_string())
}
