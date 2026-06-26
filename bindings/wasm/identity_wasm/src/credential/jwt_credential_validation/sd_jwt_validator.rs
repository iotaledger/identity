// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::options::WasmJwtCredentialValidationOptions;
use super::WasmKeyBindingJwtValidationOptions;
use crate::common::ImportedDocumentLock;
use crate::common::ImportedDocumentReadGuard;
use crate::credential::WasmCredential;
use crate::credential::WasmCredentialV2;
use crate::did::ArrayIToCoreDocument;
use crate::did::IToCoreDocument;
use crate::did::WasmJwsVerificationOptions;
use crate::error::Result;
use crate::sd_jwt::WasmHasher;
use crate::sd_jwt::WasmSdJwt;
use crate::verification::IJwsVerifier;
use crate::verification::WasmJwsVerifier;
use identity_iota::credential::SdJwtCredentialValidator;

use wasm_bindgen::prelude::*;

/// A type for decoding and validating SD-JWT credentials.
#[wasm_bindgen(js_name = SdJwtCredentialValidator)]
pub struct WasmSdJwtCredentialValidator(SdJwtCredentialValidator<WasmJwsVerifier>);

#[wasm_bindgen(js_class = SdJwtCredentialValidator)]
impl WasmSdJwtCredentialValidator {
  /// Creates a new `SdJwtCredentialValidator`. If a `signatureVerifier` is provided it will be used when
  /// verifying decoded JWS signatures, otherwise a default verifier capable of handling the `EdDSA`, `ES256`, `ES256K`
  /// algorithms will be used.
  #[wasm_bindgen(constructor)]
  #[allow(non_snake_case)]
  pub fn new(hasher: WasmHasher, signatureVerifier: Option<IJwsVerifier>) -> WasmSdJwtCredentialValidator {
    let signature_verifier = WasmJwsVerifier::new(signatureVerifier);
    WasmSdJwtCredentialValidator(SdJwtCredentialValidator::new(signature_verifier, hasher))
  }

  /// Decodes and validates a [Credential] issued as an SD-JWT.
  /// The credential is constructed by replacing disclosures following the
  /// [Selective Disclosure for JWTs (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html) standard.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// * The key binding JWT is not validated. If needed, it must be validated separately using {@link
  ///   SdJwtCredentialValidator.validateKeyBindingJwt}.
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
  ///   trusted. This section contains more information on additional checks that should be carried out before and after
  ///   calling this method.
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
  ) -> std::result::Result<WasmCredential, JsError> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock
      .try_read()
      .map_err(|_| JsError::new("failed to lock DidDocument for reading"))?;

    Ok(
      self
        .0
        .validate_credential(&sd_jwt.0, std::slice::from_ref(&issuer_guard), &options.0)
        .map(WasmCredential)?,
    )
  }

  /// Decodes and validates a {@link CredentialV2} issued as an SD-JWT.
  /// The credential is constructed by replacing disclosures following the
  /// [Selective Disclosure for JWTs (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html) standard.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// * The key binding JWT is not validated. If needed, it must be validated separately using {@link
  ///   SdJwtCredentialValidator.validate_key_binding_jwt}.
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
  ///   trusted. This section contains more information on additional checks that should be carried out before and after
  ///   calling this method.
  ///
  /// ## The state of the issuer's DID Document
  /// The caller must ensure that `issuer` represents an up-to-date DID Document.
  ///
  /// ## Properties that are not validated
  /// There are many properties defined in [The Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
  /// that are **not** validated, such as:
  /// `proof`, `credentialStatus`, `type`, `credentialSchema`, `refreshService` **and more**.
  /// These should be manually checked after validation, according to your requirements.
  ///
  /// # Errors
  /// An error is returned whenever a validated condition is not satisfied.
  #[wasm_bindgen(js_name = validateCredentialV2)]
  pub fn validate_credential_v2(
    &self,
    sd_jwt: &WasmSdJwt,
    issuer: &IToCoreDocument,
    options: &WasmJwtCredentialValidationOptions,
  ) -> std::result::Result<WasmCredentialV2, JsError> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock
      .try_read()
      .map_err(|_| JsError::new("failed to lock DidDocument for reading"))?;

    Ok(
      self
        .0
        .validate_credential_v2(&sd_jwt.0, std::slice::from_ref(&issuer_guard), &options.0)
        .map(WasmCredentialV2)?,
    )
  }

  /// Decode and verify the JWS signature of an SD-JWT using the DID Document of a trusted issuer.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// # Errors
  /// An error is returned whenever:
  /// - The JWS signature is invalid;
  /// - The issuer's public key could not be determined or is not found within the trusted issuers' documents;
  #[wasm_bindgen(js_name = verifySignature)]
  #[allow(non_snake_case)]
  pub fn verify_signature(
    &self,
    credential: &WasmSdJwt,
    trustedIssuers: &ArrayIToCoreDocument,
    options: &WasmJwsVerificationOptions,
  ) -> std::result::Result<(), JsError> {
    let issuer_locks: Vec<ImportedDocumentLock> = trustedIssuers.into();
    let trusted_issuers: Vec<ImportedDocumentReadGuard<'_>> = issuer_locks
      .iter()
      .map(ImportedDocumentLock::try_read)
      .collect::<Result<Vec<ImportedDocumentReadGuard<'_>>>>()
      .map_err(|_| JsError::new("failed to lock DidDocument for reading"))?;

    self.0.verify_signature(&credential.0, &trusted_issuers, &options.0)?;

    Ok(())
  }

  /// Validates a [Key Binding JWT (KB-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html#name-key-binding-jwt)
  /// according to [RFC9901](https://www.rfc-editor.org/rfc/rfc9901.html#key_binding_security).
  ///
  /// The Validation process includes:
  ///   - Signature validation using public key materials defined in the `holder` document.
  ///   - `sd_hash` claim value in the KB-JWT claim.
  ///   - Optional `nonce`, `aud`, and validity period validation.
  ///
  /// ## Notes
  /// If a KB-JWT is not required by the SD-JWT, this method returns successfully early.
  #[wasm_bindgen(js_name = validateKeyBindingJwt)]
  pub fn validate_key_binding_jwt(
    &self,
    sd_jwt: &WasmSdJwt,
    holder: &IToCoreDocument,
    options: &WasmKeyBindingJwtValidationOptions,
  ) -> std::result::Result<(), JsError> {
    let holder_lock = ImportedDocumentLock::from(holder);
    let holder_guard = holder_lock
      .try_read()
      .map_err(|_| JsError::new("failed to lock DidDocument for reading"))?;

    Ok(self.0.validate_key_binding_jwt(&sd_jwt.0, &holder_guard, &options.0)?)
  }
}
