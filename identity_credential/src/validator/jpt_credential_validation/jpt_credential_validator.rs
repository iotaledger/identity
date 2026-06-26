// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use identity_document::verifiable::JwpVerificationOptions;
use jsonprooftoken::encoding::SerializationType;
use jsonprooftoken::jpt::claims::JptClaims;
use jsonprooftoken::jwk::key::Jwk as JwkExt;
use jsonprooftoken::jwp::issued::JwpIssuedDecoder;

use super::DecodedJptCredential;
use crate::credential::Credential;
use crate::credential::CredentialJwtClaims;
use crate::credential::Jpt;
use crate::validator::jwt_credential_validation::SignerContext;
use crate::validator::CompoundCredentialValidationError;
use crate::validator::FailFast;
use crate::validator::JptCredentialValidationOptions;
use crate::validator::JwtCredentialValidatorUtils;
use crate::validator::JwtValidationError;

/// A type for decoding and validating [`Credential`]s in JPT format.
#[non_exhaustive]
pub struct JptCredentialValidator;

impl JptCredentialValidator {
  /// Decodes and validates a [`Credential`] issued as a JPT (JWP Issued Form). A [`DecodedJptCredential`] is returned
  /// upon success.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's proof on the JWP,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  pub fn validate<DOC, T>(
    credential_jpt: &Jpt,
    issuer: &DOC,
    options: &JptCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<DecodedJptCredential<T>, CompoundCredentialValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    // First verify the JWP proof and decode the result into a credential token, then apply all other validations.
    let credential_token =
      Self::verify_proof(credential_jpt, issuer, &options.verification_options).map_err(|err| {
        CompoundCredentialValidationError {
          validation_errors: [err].into(),
        }
      })?;

    let credential: &Credential<T> = &credential_token.credential;

    Self::validate_credential::<T>(credential, options, fail_fast)?;

    Ok(credential_token)
  }

  pub(crate) fn validate_credential<T>(
    credential: &Credential<T>,
    options: &JptCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<(), CompoundCredentialValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
  {
    // Run all single concern Credential validations in turn and fail immediately if `fail_fast` is true.
    let expiry_date_validation = std::iter::once_with(|| {
      JwtCredentialValidatorUtils::check_expires_on_or_after(
        credential,
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

    let validation_units_error_iter = validation_units_iter.filter_map(|result| result.err());
    let validation_errors: Vec<JwtValidationError> = match fail_fast {
      FailFast::FirstError => validation_units_error_iter.take(1).collect(),
      FailFast::AllErrors => validation_units_error_iter.collect(),
    };

    if validation_errors.is_empty() {
      Ok(())
    } else {
      Err(CompoundCredentialValidationError { validation_errors })
    }
  }

  /// Proof verification function
  fn verify_proof<DOC, T>(
    credential: &Jpt,
    issuer: &DOC,
    options: &JwpVerificationOptions,
  ) -> Result<DecodedJptCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let decoded = JwpIssuedDecoder::decode(credential.as_str(), SerializationType::COMPACT)
      .map_err(JwtValidationError::JwpDecodingError)?;

    // If no method_url is set, parse the `kid` to a DID Url which should be the identifier
    // of a verification method in a trusted issuer's DID document.
    let method_id: DIDUrl = match &options.method_id {
      Some(method_id) => method_id.clone(),
      None => {
        let kid: &str = decoded
          .get_header()
          .kid()
          .ok_or(JwtValidationError::MethodDataLookupError {
            source: None,
            message: "could not extract kid from protected header",
            signer_ctx: SignerContext::Issuer,
          })?;

        // Convert kid to DIDUrl
        DIDUrl::parse(kid).map_err(|err| JwtValidationError::MethodDataLookupError {
          source: Some(err.into()),
          message: "could not parse kid as a DID Url",
          signer_ctx: SignerContext::Issuer,
        })?
      }
    };

    // check issuer
    let issuer: &CoreDocument = issuer.as_ref();

    if issuer.id() != method_id.did() {
      return Err(JwtValidationError::DocumentMismatch(SignerContext::Issuer));
    }

    // Obtain the public key from the issuer's DID document
    let public_key: JwkExt = issuer
      .resolve_method(&method_id, options.method_scope)
      .and_then(|method| method.data().public_key_jwk())
      .and_then(|k| k.try_into().ok()) //Conversio into jsonprooftoken::Jwk type
      .ok_or_else(|| JwtValidationError::MethodDataLookupError {
        source: None,
        message: "could not extract JWK from a method identified by kid",
        signer_ctx: SignerContext::Issuer,
      })?;

    let credential_token = Self::verify_decoded_jwp(decoded, &public_key)?;

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

  /// Verify the decoded issued JWP proof using the given `public_key`.
  fn verify_decoded_jwp<T>(
    decoded: JwpIssuedDecoder,
    public_key: &JwkExt,
  ) -> Result<DecodedJptCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
  {
    // Verify Jwp proof
    let decoded_jwp = decoded
      .verify(public_key)
      .map_err(JwtValidationError::JwpProofVerificationError)?;

    let claims = decoded_jwp.get_claims().ok_or("Claims not present").map_err(|err| {
      JwtValidationError::CredentialStructure(crate::Error::JptClaimsSetDeserializationError(err.into()))
    })?;
    let payloads = decoded_jwp.get_payloads();
    let jpt_claims = JptClaims::from_claims_and_payloads(claims, payloads);
    let jpt_claims_json = jpt_claims.to_json_vec().map_err(|err| {
      JwtValidationError::CredentialStructure(crate::Error::JptClaimsSetDeserializationError(err.into()))
    })?;

    // Deserialize the raw claims
    let credential_claims: CredentialJwtClaims<'_, T> = CredentialJwtClaims::from_json_slice(&jpt_claims_json)
      .map_err(|err| {
        JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
      })?;

    let custom_claims = credential_claims.custom.clone();

    // Construct the credential token containing the credential and the protected header.
    let credential: Credential<T> = credential_claims
      .try_into_credential()
      .map_err(JwtValidationError::CredentialStructure)?;

    Ok(DecodedJptCredential {
      credential,
      custom_claims,
      decoded_jwp,
    })
  }
}
