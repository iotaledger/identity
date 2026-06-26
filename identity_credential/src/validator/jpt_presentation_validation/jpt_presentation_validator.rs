// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use jsonprooftoken::encoding::SerializationType;
use jsonprooftoken::jpt::claims::JptClaims;
use jsonprooftoken::jwk::key::Jwk as JwkExt;
use jsonprooftoken::jwp::presented::JwpPresentedDecoder;

use crate::credential::Credential;
use crate::credential::CredentialJwtClaims;
use crate::credential::Jpt;
use crate::validator::CompoundCredentialValidationError;
use crate::validator::FailFast;
use crate::validator::JwtCredentialValidatorUtils;
use crate::validator::JwtValidationError;
use crate::validator::SignerContext;

use super::DecodedJptPresentation;
use super::JptPresentationValidationOptions;

/// A type for decoding and validating Presented [`Credential`]s in JPT format.
#[non_exhaustive]
pub struct JptPresentationValidator;

impl JptPresentationValidator {
  /// Decodes and validates a Presented [`Credential`] issued as a JPT (JWP Presented Form). A
  /// [`DecodedJptPresentation`] is returned upon success.
  ///
  /// The following properties are validated according to `options`:
  /// - the holder's proof on the JWP,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  pub fn validate<DOC, T>(
    presentation_jpt: &Jpt,
    issuer: &DOC,
    options: &JptPresentationValidationOptions,
    fail_fast: FailFast,
  ) -> Result<DecodedJptPresentation<T>, CompoundCredentialValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    // First verify the JWP proof and decode the result into a presented credential token, then apply all other
    // validations.
    let presented_credential_token =
      Self::verify_proof(presentation_jpt, issuer, options).map_err(|err| CompoundCredentialValidationError {
        validation_errors: [err].into(),
      })?;

    let credential: &Credential<T> = &presented_credential_token.credential;

    Self::validate_presented_credential::<T>(credential, fail_fast)?;

    Ok(presented_credential_token)
  }

  pub(crate) fn validate_presented_credential<T>(
    credential: &Credential<T>,
    fail_fast: FailFast,
  ) -> Result<(), CompoundCredentialValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
  {
    let structure_validation = std::iter::once_with(|| JwtCredentialValidatorUtils::check_structure(credential));

    let validation_units_iter = structure_validation;

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
    presentation_jpt: &Jpt,
    issuer: &DOC,
    options: &JptPresentationValidationOptions,
  ) -> Result<DecodedJptPresentation<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let decoded: JwpPresentedDecoder =
      JwpPresentedDecoder::decode(presentation_jpt.as_str(), SerializationType::COMPACT)
        .map_err(JwtValidationError::JwpDecodingError)?;

    let nonce: Option<&String> = options.nonce.as_ref();
    // Validate the nonce
    if decoded.get_presentation_header().nonce() != nonce {
      return Err(JwtValidationError::JwsDecodingError(
        identity_verification::jose::error::Error::InvalidParam("invalid nonce value"),
      ));
    }

    // If no method_url is set, parse the `kid` to a DID Url which should be the identifier
    // of a verification method in a trusted issuer's DID document.
    let method_id: DIDUrl = match &options.verification_options.method_id {
      Some(method_id) => method_id.clone(),
      None => {
        let kid: &str = decoded
          .get_issuer_header()
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
      .resolve_method(&method_id, options.verification_options.method_scope)
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

  /// Verify the decoded presented JWP proof using the given `public_key`.
  fn verify_decoded_jwp<T>(
    decoded: JwpPresentedDecoder,
    public_key: &JwkExt,
  ) -> Result<DecodedJptPresentation<T>, JwtValidationError>
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
    let mut jpt_claims = JptClaims::from_claims_and_payloads(claims, payloads);
    // if not set the deserializatioon will throw an error since even the iat is not set, so we set this to 0
    jpt_claims.nbf.map_or_else(
      || {
        jpt_claims.set_nbf(0);
      },
      |_| (),
    );

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

    let aud: Option<Url> = decoded_jwp.get_presentation_protected_header().aud().and_then(|aud| {
      Url::from_str(aud)
        .map_err(|_| {
          JwtValidationError::JwsDecodingError(identity_verification::jose::error::Error::InvalidParam(
            "invalid audience value",
          ))
        })
        .ok()
    });

    Ok(DecodedJptPresentation {
      credential,
      aud,
      custom_claims,
      decoded_jwp,
    })
  }
}
