// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::credential::JwtCredentialValidatorHybrid;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::StatusCheck;
use identity_iota::did::CoreDID;

use super::options::WasmJwtCredentialValidationOptions;
use crate::common::ImportedDocumentLock;
use crate::common::ImportedDocumentReadGuard;
use crate::common::WasmTimestamp;
use crate::credential::options::WasmStatusCheck;
use crate::credential::revocation::status_list_2021::WasmStatusList2021Credential;
use crate::credential::WasmCredential;
use crate::credential::WasmDecodedJwtCredential;
use crate::credential::WasmFailFast;
use crate::credential::WasmJwt;
use crate::credential::WasmSubjectHolderRelationship;
use crate::did::ArrayIToCoreDocument;
use crate::did::IToCoreDocument;
use crate::did::WasmCoreDID;
use crate::did::WasmJwsVerificationOptions;
use crate::error::Result;
use crate::error::WasmResult;
use crate::verification::IJwsVerifier;
use crate::verification::WasmJwsVerifier;

use wasm_bindgen::prelude::*;

/// A type for decoding and validating PQ/T {@link Credential}.
#[wasm_bindgen(js_name = JwtCredentialValidatorHybrid)]
pub struct WasmJwtCredentialValidatorHybrid(JwtCredentialValidatorHybrid<WasmJwsVerifier, WasmJwsVerifier>);

#[wasm_bindgen(js_class = JwtCredentialValidatorHybrid)]
impl WasmJwtCredentialValidatorHybrid {
  /// Creates a new {@link JwtCredentialValidatorHybrid}. 
  #[wasm_bindgen(constructor)]
  #[allow(non_snake_case)]
  pub fn new(traditionalSignatureVerifier: Option<IJwsVerifier>, pqSignatureVerifier: Option<IJwsVerifier>) -> WasmJwtCredentialValidatorHybrid {
    let traditional_signature_verifier = WasmJwsVerifier::new(traditionalSignatureVerifier);
    let pq_signature_verifier = WasmJwsVerifier::new(pqSignatureVerifier);
    WasmJwtCredentialValidatorHybrid(JwtCredentialValidatorHybrid::with_signature_verifiers(traditional_signature_verifier, pq_signature_verifier))
  }

  /// Decodes and validates a {@link Credential} issued as a JWS. A {@link DecodedJwtCredential} is returned upon
  /// success.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
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
  #[wasm_bindgen]
  pub fn validate(
    &self,
    credential_jwt: &WasmJwt,
    issuer: &IToCoreDocument,
    options: &WasmJwtCredentialValidationOptions,
    fail_fast: WasmFailFast,
  ) -> Result<WasmDecodedJwtCredential> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock.try_read()?;

    self
      .0
      .validate(&credential_jwt.0, &issuer_guard, &options.0, fail_fast.into())
      .wasm_result()
      .map(WasmDecodedJwtCredential)
  }

  /// Decode and verify the JWS signature of a {@link Credential} issued as a JWT using the DID Document of a trusted
  /// issuer.
  ///
  /// A {@link DecodedJwtCredential} is returned upon success.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// ## Proofs
  ///  Only the JWS signature is verified. If the {@link Credential} contains a `proof` property this will not be
  /// verified by this method.
  ///
  /// # Errors
  /// This method immediately returns an error if
  /// the credential issuer' url cannot be parsed to a DID belonging to one of the trusted issuers. Otherwise an attempt
  /// to verify the credential's signature will be made and an error is returned upon failure.
  #[wasm_bindgen(js_name = verifySignature)]
  #[allow(non_snake_case)]
  pub fn verify_signature(
    &self,
    credential: &WasmJwt,
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

  /// Validate that the credential expires on or after the specified timestamp.
  #[wasm_bindgen(js_name = checkExpiresOnOrAfter)]
  pub fn check_expires_on_or_after(credential: &WasmCredential, timestamp: &WasmTimestamp) -> Result<()> {
    JwtCredentialValidatorUtils::check_expires_on_or_after(&credential.0, timestamp.0).wasm_result()
  }

  /// Validate that the credential is issued on or before the specified timestamp.
  #[wasm_bindgen(js_name = checkIssuedOnOrBefore)]
  pub fn check_issued_on_or_before(credential: &WasmCredential, timestamp: &WasmTimestamp) -> Result<()> {
    JwtCredentialValidatorUtils::check_issued_on_or_before(&credential.0, timestamp.0).wasm_result()
  }

  /// Validate that the relationship between the `holder` and the credential subjects is in accordance with
  /// `relationship`. The `holder` parameter is expected to be the URL of the holder.
  #[wasm_bindgen(js_name = checkSubjectHolderRelationship)]
  pub fn check_subject_holder_relationship(
    credential: &WasmCredential,
    holder: &str,
    relationship: WasmSubjectHolderRelationship,
  ) -> Result<()> {
    let holder: Url = Url::parse(holder).wasm_result()?;
    JwtCredentialValidatorUtils::check_subject_holder_relationship(&credential.0, &holder, relationship.into())
      .wasm_result()
  }

  /// Checks whether the credential status has been revoked.
  ///
  /// Only supports `RevocationBitmap2022`.
  #[wasm_bindgen(js_name = checkStatus)]
  #[allow(non_snake_case)]
  pub fn check_status(
    credential: &WasmCredential,
    trustedIssuers: &ArrayIToCoreDocument,
    statusCheck: WasmStatusCheck,
  ) -> Result<()> {
    let issuer_locks: Vec<ImportedDocumentLock> = trustedIssuers.into();
    let trusted_issuers: Vec<ImportedDocumentReadGuard<'_>> = issuer_locks
      .iter()
      .map(ImportedDocumentLock::try_read)
      .collect::<Result<Vec<ImportedDocumentReadGuard<'_>>>>(
    )?;
    let status_check: StatusCheck = statusCheck.into();
    JwtCredentialValidatorUtils::check_status(&credential.0, &trusted_issuers, status_check).wasm_result()
  }

  /// Checks wheter the credential status has been revoked using `StatusList2021`.
  #[wasm_bindgen(js_name = checkStatusWithStatusList2021)]
  pub fn check_status_with_status_list_2021(
    credential: &WasmCredential,
    status_list: &WasmStatusList2021Credential,
    status_check: WasmStatusCheck,
  ) -> Result<()> {
    JwtCredentialValidatorUtils::check_status_with_status_list_2021(
      &credential.0,
      &status_list.inner,
      status_check.into(),
    )
    .wasm_result()
  }

  /// Utility for extracting the issuer field of a {@link Credential} as a DID.
  ///
  /// ### Errors
  ///
  /// Fails if the issuer field is not a valid DID.
  #[wasm_bindgen(js_name = extractIssuer)]
  pub fn extract_issuer(credential: &WasmCredential) -> Result<WasmCoreDID> {
    JwtCredentialValidatorUtils::extract_issuer::<CoreDID, Object>(&credential.0)
      .map(WasmCoreDID::from)
      .wasm_result()
  }

  /// Utility for extracting the issuer field of a credential in JWT representation as DID.
  ///
  /// # Errors
  ///
  /// If the JWT decoding fails or the issuer field is not a valid DID.
  #[wasm_bindgen(js_name = extractIssuerFromJwt)]
  pub fn extract_issuer_from_jwt(credential: &WasmJwt) -> Result<WasmCoreDID> {
    JwtCredentialValidatorUtils::extract_issuer_from_jwt::<CoreDID>(&credential.0)
      .map(WasmCoreDID::from)
      .wasm_result()
  }
}
