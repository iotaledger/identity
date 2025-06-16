// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_core::convert::FromJson;
use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use identity_document::verifiable::JwsVerificationOptions;
use identity_verification::jwk::PostQuantumJwk;
use identity_verification::jwk::TraditionalJwk;
use identity_verification::jws::DecodedJws;
use identity_verification::jws::Decoder;
use identity_verification::jws::JwsValidationItem;
use identity_verification::jws::JwsVerifier;
use identity_verification::jwk::CompositeJwk;

use super::CompoundCredentialValidationError;
use super::DecodedJwtCredential;
use super::JwtCredentialValidationOptions;
use super::JwtCredentialValidatorUtils;
use super::JwtValidationError;
use super::SignerContext;
use crate::credential::Credential;
use crate::credential::CredentialJwtClaims;
use crate::credential::Jwt;
use crate::validator::FailFast;

/// A type for decoding and validating [`Credential`]s signed with a PQ/T signature.
pub struct JwtCredentialValidatorHybrid<TRV, PQV>(TRV, PQV);

impl<TRV: JwsVerifier, PQV: JwsVerifier> JwtCredentialValidatorHybrid<TRV, PQV> {
  /// Create a new [`JwtCredentialValidatorHybrid`] that delegates cryptographic signature verification to the given
  /// traditional [`JwsVerifier`] and PQ [`JwsVerifier`].
  pub fn with_signature_verifiers(traditional_signature_verifier: TRV, pq_signature_verifier: PQV) -> Self {
    Self(traditional_signature_verifier, pq_signature_verifier)
  }

  /// Decodes and validates a [`Credential`] issued as a JWT. A [`DecodedJwtCredential`] is returned upon success.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's PQ/T signature on the JWS,
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
  pub fn validate<DOC, T>(
    &self,
    credential_jwt: &Jwt,
    issuer: &DOC,
    options: &JwtCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<DecodedJwtCredential<T>, CompoundCredentialValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let credential_token = self
      .verify_signature(
        credential_jwt,
        std::slice::from_ref(issuer.as_ref()),
        &options.verification_options,
      )
      .map_err(|err| CompoundCredentialValidationError {
        validation_errors: [err].into(),
      })?;

    Self::validate_decoded_credential::<CoreDocument, T>(
      credential_token,
      std::slice::from_ref(issuer.as_ref()),
      options,
      fail_fast,
    )
  }

  /// Decode and verify the PQ/T JWS signature of a [`Credential`] issued as a JWT using the DID Document of a trusted
  /// issuer.
  ///
  /// A [`DecodedJwtCredential`] is returned upon success.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// ## Proofs
  ///  Only the PQ/T JWS signature is verified. If the [`Credential`] contains a `proof` property this will not be verified
  /// by this method.
  ///
  /// # Errors
  /// This method immediately returns an error if
  /// the credential issuer' url cannot be parsed to a DID belonging to one of the trusted issuers. Otherwise an attempt
  /// to verify the credential's signature will be made and an error is returned upon failure.
  pub fn verify_signature<DOC, T>(
    &self,
    credential: &Jwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DecodedJwtCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    Self::verify_signature_with_verifiers(&self.0, &self.1, credential, trusted_issuers, options)
  }

  // This method takes a slice of issuer's instead of a single issuer in order to better accommodate presentation
  // validation. It also validates the relationship between a holder and the credential subjects when
  // `relationship_criterion` is Some.
  pub(crate) fn validate_decoded_credential<DOC, T>(
    credential_token: DecodedJwtCredential<T>,
    issuers: &[DOC],
    options: &JwtCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<DecodedJwtCredential<T>, CompoundCredentialValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let credential: &Credential<T> = &credential_token.credential;
    // Run all single concern Credential validations in turn and fail immediately if `fail_fast` is true.

    let expiry_date_validation = std::iter::once_with(|| {
      JwtCredentialValidatorUtils::check_expires_on_or_after(
        &credential_token.credential,
        options.earliest_expiry_date.unwrap_or_default(),
      )
    });

    let issuance_date_validation = std::iter::once_with(|| {
      JwtCredentialValidatorUtils::check_issued_on_or_before(
        credential,
        options.latest_issuance_date.unwrap_or_default(),
      )
    });

    let structure_validation = std::iter::once_with(|| JwtCredentialValidatorUtils::check_structure(credential));

    let subject_holder_validation = std::iter::once_with(|| {
      options
        .subject_holder_relationship
        .as_ref()
        .map(|(holder, relationship)| {
          JwtCredentialValidatorUtils::check_subject_holder_relationship(credential, holder, *relationship)
        })
        .unwrap_or(Ok(()))
    });

    let validation_units_iter = issuance_date_validation
      .chain(expiry_date_validation)
      .chain(structure_validation)
      .chain(subject_holder_validation);

    #[cfg(feature = "revocation-bitmap")]
    let validation_units_iter = {
      let revocation_validation =
        std::iter::once_with(|| JwtCredentialValidatorUtils::check_status(credential, issuers, options.status));
      validation_units_iter.chain(revocation_validation)
    };

    let validation_units_error_iter = validation_units_iter.filter_map(|result| result.err());
    let validation_errors: Vec<JwtValidationError> = match fail_fast {
      FailFast::FirstError => validation_units_error_iter.take(1).collect(),
      FailFast::AllErrors => validation_units_error_iter.collect(),
    };

    if validation_errors.is_empty() {
      Ok(credential_token)
    } else {
      Err(CompoundCredentialValidationError { validation_errors })
    }
  }

  pub(crate) fn parse_composite_pk<'a, 'i, DOC>(
    jws: &JwsValidationItem<'a>,
    trusted_issuers: &'i [DOC],
    options: &JwsVerificationOptions,
  ) -> Result<(&'a CompositeJwk, DIDUrl), JwtValidationError>
  where
    DOC: AsRef<CoreDocument>,
    'i: 'a,
  {
    let nonce: Option<&str> = options.nonce.as_deref();
    // Validate the nonce
    if jws.nonce() != nonce {
      return Err(JwtValidationError::JwsDecodingError(
        identity_verification::jose::error::Error::InvalidParam("invalid nonce value"),
      ));
    }

    // If no method_url is set, parse the `kid` to a DID Url which should be the identifier
    // of a verification method in a trusted issuer's DID document.
    let method_id: DIDUrl =
      match &options.method_id {
        Some(method_id) => method_id.clone(),
        None => {
          let kid: &str = jws.protected_header().and_then(|header| header.kid()).ok_or(
            JwtValidationError::MethodDataLookupError {
              source: None,
              message: "could not extract kid from protected header",
              signer_ctx: SignerContext::Issuer,
            },
          )?;

          // Convert kid to DIDUrl
          DIDUrl::parse(kid).map_err(|err| JwtValidationError::MethodDataLookupError {
            source: Some(err.into()),
            message: "could not parse kid as a DID Url",
            signer_ctx: SignerContext::Issuer,
          })?
        }
      };

    // locate the corresponding issuer
    let issuer: &CoreDocument = trusted_issuers
      .iter()
      .map(AsRef::as_ref)
      .find(|issuer_doc| <CoreDocument>::id(issuer_doc) == method_id.did())
      .ok_or(JwtValidationError::DocumentMismatch(SignerContext::Issuer))?;

    // Obtain the public key from the issuer's DID document
    issuer
      .resolve_method(&method_id, options.method_scope)
      .and_then(|method| method.data().composite_public_key())
      .ok_or_else(|| JwtValidationError::MethodDataLookupError {
        source: None,
        message: "could not extract CompositePublicKey from a method identified by kid",
        signer_ctx: SignerContext::Issuer,
      })
      .map(move |c: &CompositeJwk| (c, method_id))
  }

  /// Stateless version of [`Self::verify_signature`].
  fn verify_signature_with_verifiers<DOC, T>(
    traditional_signature_verifier: &TRV,
    pq_signature_verifier: &PQV,
    credential: &Jwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DecodedJwtCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>
  {
    // Note the below steps are necessary because `CoreDocument::verify_jws` decodes the JWS and then searches for a
    // method with a fragment (or full DID Url) matching `kid` in the given document. We do not want to carry out
    // that process for potentially every document in `trusted_issuers`.

    // Start decoding the credential
    let decoded: JwsValidationItem<'_> = Self::decode(credential.as_str())?;

    let (composite, method_id) = Self::parse_composite_pk(&decoded, trusted_issuers, options)?;

    let credential_token = Self::verify_decoded_signature(
      decoded,
      composite.traditional_public_key(),
      composite.pq_public_key(),
      traditional_signature_verifier,
      pq_signature_verifier,
    )?;

    // Check that the DID component of the parsed `kid` does indeed correspond to the issuer in the credential before
    // returning.
    let issuer_id: CoreDID = JwtCredentialValidatorUtils::extract_issuer(&credential_token.credential)?;
    if &issuer_id != method_id.did() {
      return Err(JwtValidationError::IdentifierMismatch {
        signer_ctx: SignerContext::Issuer,
      });
    };
    Ok(credential_token)
  }

  /// Decode the credential into a [`JwsValidationItem`].
  pub(crate) fn decode(credential_jws: &str) -> Result<JwsValidationItem<'_>, JwtValidationError> {
    let decoder: Decoder = Decoder::new();

    decoder
      .decode_compact_serialization(credential_jws.as_bytes(), None)
      .map_err(JwtValidationError::JwsDecodingError)
  }

  pub(crate) fn verify_signature_raw<'a>(
    decoded: JwsValidationItem<'a>,
    traditional_pk: &TraditionalJwk,
    pq_pk: &PostQuantumJwk,
    traditional_verifier: &TRV,
    pq_verifier: &PQV,
  ) -> Result<DecodedJws<'a>, JwtValidationError> {
    decoded
      .verify_hybrid(traditional_verifier, pq_verifier, traditional_pk, pq_pk)
      .map_err(|err| JwtValidationError::Signature {
        source: err,
        signer_ctx: SignerContext::Issuer,
      })
  }

  /// Verify the signature using the given `public_key` and `signature_verifier`.
  fn verify_decoded_signature<T>(
    decoded: JwsValidationItem<'_>,
    traditional_pk: &TraditionalJwk,
    pq_pk: &PostQuantumJwk,
    traditional_verifier: &TRV,
    pq_verifier: &PQV,
  ) -> Result<DecodedJwtCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
  {
    // Verify the JWS signature and obtain the decoded token containing the protected header and raw claims
    let DecodedJws { protected, claims, .. } =
      Self::verify_signature_raw(decoded, traditional_pk, pq_pk, traditional_verifier, pq_verifier)?;

    let credential_claims: CredentialJwtClaims<'_, T> =
      CredentialJwtClaims::from_json_slice(&claims).map_err(|err| {
        JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
      })?;

    let custom_claims = credential_claims.custom.clone();

    // Construct the credential token containing the credential and the protected header.
    let credential: Credential<T> = credential_claims
      .try_into_credential()
      .map_err(JwtValidationError::CredentialStructure)?;

    Ok(DecodedJwtCredential {
      credential,
      header: Box::new(protected),
      custom_claims,
    })
  }
}
