// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ImportedDocumentLock;
use crate::credential::WasmDomainLinkageConfiguration;
use crate::credential::WasmJwtCredentialValidationOptions;
use crate::did::IToCoreDocument;
use crate::error::Result;
use crate::error::WasmResult;
use crate::verification::IJwsVerifier;
use crate::verification::WasmJwsVerifier;
use identity_iota::core::Url;
use identity_iota::credential::JwtDomainLinkageValidator;
use wasm_bindgen::prelude::wasm_bindgen;

use super::WasmJwt;

/// A validator for a Domain Linkage Configuration and Credentials.
#[wasm_bindgen(js_name = JwtDomainLinkageValidator)]
pub struct WasmJwtDomainLinkageValidator {
  validator: JwtDomainLinkageValidator<WasmJwsVerifier>,
}

#[wasm_bindgen(js_class = JwtDomainLinkageValidator)]
impl WasmJwtDomainLinkageValidator {
  /// Creates a new {@link JwtDomainLinkageValidator}. If a `signatureVerifier` is provided it will be used when
  /// verifying decoded JWS signatures, otherwise a default verifier capable of handling the `EdDSA`, `ES256`, `ES256K`
  /// algorithms will be used.
  #[wasm_bindgen(constructor)]
  #[allow(non_snake_case)]
  pub fn new(signatureVerifier: Option<IJwsVerifier>) -> WasmJwtDomainLinkageValidator {
    let signature_verifier = WasmJwsVerifier::new(signatureVerifier);
    WasmJwtDomainLinkageValidator {
      validator: JwtDomainLinkageValidator::with_signature_verifier(signature_verifier),
    }
  }

  /// Validates the linkage between a domain and a DID.
  /// {@link DomainLinkageConfiguration} is validated according to [DID Configuration Resource Verification](https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification).
  ///
  /// Linkage is valid if no error is thrown.
  ///
  /// # Note:
  /// - Only the [JSON Web Token Proof Format](https://identity.foundation/.well-known/resources/did-configuration/#json-web-token-proof-format)
  ///   is supported.
  /// - Only the Credential issued by `issuer` is verified.
  ///
  /// # Errors
  ///
  ///  - Semantic structure of `configuration` is invalid.
  ///  - `configuration` includes multiple credentials issued by `issuer`.
  ///  - Validation of the matched Domain Linkage Credential fails.
  #[wasm_bindgen(js_name = validateLinkage)]
  pub fn validate_linkage(
    &self,
    issuer: &IToCoreDocument,
    configuration: &WasmDomainLinkageConfiguration,
    domain: &str,
    options: &WasmJwtCredentialValidationOptions,
  ) -> Result<()> {
    let domain = Url::parse(domain).wasm_result()?;
    let doc = ImportedDocumentLock::from(issuer);
    let doc_guard = doc.try_read()?;
    self
      .validator
      .validate_linkage(&doc_guard, &configuration.0, &domain, &options.0)
      .wasm_result()
  }

  /// Validates a [Domain Linkage Credential](https://identity.foundation/.well-known/resources/did-configuration/#domain-linkage-credential).
  ///
  /// Error will be thrown in case the validation fails.
  #[wasm_bindgen(js_name = validateCredential)]
  #[allow(non_snake_case)]
  pub fn validate_credential(
    &self,
    issuer: &IToCoreDocument,
    credentialJwt: &WasmJwt,
    domain: &str,
    options: &WasmJwtCredentialValidationOptions,
  ) -> Result<()> {
    let domain = Url::parse(domain).wasm_result()?;
    let doc = ImportedDocumentLock::from(issuer);
    let doc_guard = doc.try_read()?;
    self
      .validator
      .validate_credential(&doc_guard, &credentialJwt.0, &domain, &options.0)
      .wasm_result()
  }
}
