// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::options::WasmJwtCredentialValidationOptions;
use super::WasmKeyBindingJWTValidationOptions;
use crate::common::ImportedDocumentLock;
use crate::common::ImportedDocumentReadGuard;
use crate::credential::WasmDecodedJwtCredential;
use crate::credential::WasmFailFast;
use crate::did::ArrayIToCoreDocument;
use crate::did::IToCoreDocument;
use crate::did::WasmJwsVerificationOptions;
use crate::error::Result;
use crate::error::WasmResult;
use crate::sd_jwt::WasmKeyBindingJwtClaims;
use crate::sd_jwt::WasmSdJwt;
use crate::verification::IJwsVerifier;
use crate::verification::WasmJwsVerifier;
use identity_iota::credential::SdJwtCredentialValidator;
use identity_iota::sd_jwt_payload::KeyBindingJwtClaims;
use identity_iota::sd_jwt_payload::SdObjectDecoder;

use wasm_bindgen::prelude::*;

/// A type for decoding and validating {@link Credential}.
#[wasm_bindgen(js_name = SdJwtCredentialValidator)]
pub struct WasmSdJwtCredentialValidator(SdJwtCredentialValidator<WasmJwsVerifier>);

#[wasm_bindgen(js_class = SdJwtCredentialValidator)]
impl WasmSdJwtCredentialValidator {
  /// Creates a new `SdJwtCredentialValidator`. If a `signatureVerifier` is provided it will be used when
  /// verifying decoded JWS signatures, otherwise a default verifier capable of handling the `EdDSA`, `ES256`, `ES256K`
  /// algorithms will be used.
  #[wasm_bindgen(constructor)]
  #[allow(non_snake_case)]
  pub fn new(signatureVerifier: Option<IJwsVerifier>) -> WasmSdJwtCredentialValidator {
    let signature_verifier = WasmJwsVerifier::new(signatureVerifier);
    WasmSdJwtCredentialValidator(SdJwtCredentialValidator::with_signature_verifier(
      signature_verifier,
      SdObjectDecoder::new_with_sha256(),
    ))
  }

  /// Decodes and validates a `Credential` issued as an SD-JWT. A `DecodedJwtCredential` is returned upon success.
  /// The credential is constructed by replacing disclosures following the
  /// [`Selective Disclosure for JWTs (SD-JWT)`](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html) standard.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// * The key binding JWT is not validated. If needed, it must be validated separately using
  /// `SdJwtValidator::validate_key_binding_jwt`.
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
  /// trusted. This section contains more information on additional checks that should be carried out before and after
  /// calling this method.
  ///
  /// ## The state of the issuer's DID Document
  /// The caller must ensure that `issuer` represents an up-to-date DID Document.
  ///
  /// ## Properties that are not validated
  ///  There are many properties defined in [The Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) that are **not** validated, such as:
  /// `proof`, `credentialStatus`, `type`, `credentialSchema`, `refreshService` **and more**.
  /// These should be manually checked after validation, according to your requirements.
  ///
  /// # Errors
  /// An error is returned whenever a validated condition is not satisfied.
  #[wasm_bindgen(js_name = validateCredential)]
  pub fn validate_credential(
    &self,
    sd_jwt: &WasmSdJwt,
    issuer: &IToCoreDocument,
    options: &WasmJwtCredentialValidationOptions,
    fail_fast: WasmFailFast,
  ) -> Result<WasmDecodedJwtCredential> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock.try_read()?;

    self
      .0
      .validate_credential(&sd_jwt.0, &issuer_guard, &options.0, fail_fast.into())
      .wasm_result()
      .map(WasmDecodedJwtCredential)
  }

  /// Decode and verify the JWS signature of a `Credential` issued as an SD-JWT using the DID Document of a trusted
  /// issuer and replaces the disclosures.
  ///
  /// A `DecodedJwtCredential` is returned upon success.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// ## Proofs
  ///  Only the JWS signature is verified. If the `Credential` contains a `proof` property this will not be verified
  /// by this method.
  ///
  /// # Errors
  /// * If the issuer' URL cannot be parsed.
  /// * If Signature verification fails.
  /// * If SD decoding fails.
  #[wasm_bindgen(js_name = verifySignature)]
  #[allow(non_snake_case)]
  pub fn verify_signature(
    &self,
    credential: &WasmSdJwt,
    trustedIssuers: &ArrayIToCoreDocument,
    options: &WasmJwsVerificationOptions,
  ) -> Result<WasmDecodedJwtCredential> {
    let issuer_locks: Vec<ImportedDocumentLock> = trustedIssuers.into();
    let trusted_issuers: Vec<ImportedDocumentReadGuard<'_>> = issuer_locks
      .iter()
      .map(ImportedDocumentLock::try_read)
      .collect::<Result<Vec<ImportedDocumentReadGuard<'_>>>>(
    )?;

    self
      .0
      .verify_signature(&credential.0, &trusted_issuers, &options.0)
      .wasm_result()
      .map(WasmDecodedJwtCredential)
  }

  /// Validates a Key Binding JWT (KB-JWT) according to `https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-key-binding-jwt`.
  /// The Validation process includes:
  ///   * Signature validation using public key materials defined in the `holder` document.
  ///   * `typ` value in KB-JWT header.
  ///   * `sd_hash` claim value in the KB-JWT claim.
  ///   * Optional `nonce`, `aud` and issuance date validation.
  #[wasm_bindgen(js_name = validateKeyBindingJwt)]
  #[allow(non_snake_case)]
  pub fn validate_key_binding_jwt(
    &self,
    sdJwt: &WasmSdJwt,
    holder: &IToCoreDocument,
    options: &WasmKeyBindingJWTValidationOptions,
  ) -> Result<WasmKeyBindingJwtClaims> {
    let holder_lock = ImportedDocumentLock::from(holder);
    let holder_guard = holder_lock.try_read()?;
    let claims: KeyBindingJwtClaims = self
      .0
      .validate_key_binding_jwt(&sdJwt.0, &holder_guard, &options.0)
      .wasm_result()?;
    Ok(WasmKeyBindingJwtClaims(claims))
  }
}
