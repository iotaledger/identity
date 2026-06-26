// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_did::DID;
use jsonprooftoken::encoding::SerializationType;
use jsonprooftoken::jpt::claims::JptClaims;
use jsonprooftoken::jwp::presented::JwpPresentedDecoder;

use crate::credential::Credential;
use crate::credential::CredentialJwtClaims;
use crate::credential::Jpt;
use crate::revocation::RevocationTimeframeStatus;
use crate::revocation::VerifierRevocationTimeframeStatus;
use crate::validator::JptCredentialValidatorUtils;
use crate::validator::JwtValidationError;
use crate::validator::SignerContext;

/// Utility functions for verifying JPT credentials.
#[derive(Debug)]
#[non_exhaustive]
pub struct JptPresentationValidatorUtils;

type ValidationUnitResult<T = ()> = std::result::Result<T, JwtValidationError>;

impl JptPresentationValidatorUtils {
  /// Utility for extracting the issuer field of a credential in JPT representation as DID.
  ///
  /// # Errors
  ///
  /// If the JPT decoding fails or the issuer field is not a valid DID.
  pub fn extract_issuer_from_presented_jpt<D>(presentation: &Jpt) -> std::result::Result<D, JwtValidationError>
  where
    D: DID,
    <D as FromStr>::Err: std::error::Error + Send + Sync + 'static,
  {
    let decoded = JwpPresentedDecoder::decode(presentation.as_str(), SerializationType::COMPACT)
      .map_err(JwtValidationError::JwpDecodingError)?;
    let claims = decoded
      .get_issuer_header()
      .claims()
      .ok_or("Claims not present")
      .map_err(|err| {
        JwtValidationError::CredentialStructure(crate::Error::JptClaimsSetDeserializationError(err.into()))
      })?;
    let payloads = decoded.get_payloads();
    let jpt_claims = JptClaims::from_claims_and_payloads(claims, payloads);
    let jpt_claims_json = jpt_claims.to_json_vec().map_err(|err| {
      JwtValidationError::CredentialStructure(crate::Error::JptClaimsSetDeserializationError(err.into()))
    })?;

    // Deserialize the raw claims
    let credential_claims: CredentialJwtClaims<'_, Object> = CredentialJwtClaims::from_json_slice(&jpt_claims_json)
      .map_err(|err| {
        JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
      })?;

    D::from_str(credential_claims.iss.url().as_str()).map_err(|err| JwtValidationError::SignerUrl {
      signer_ctx: SignerContext::Issuer,
      source: err.into(),
    })
  }

  /// Check timeframe interval in credentialStatus with `RevocationTimeframeStatus`.
  pub fn check_timeframes_with_validity_timeframe_2024<T>(
    credential: &Credential<T>,
    validity_timeframe: Option<Timestamp>,
    status_check: crate::validator::StatusCheck,
  ) -> ValidationUnitResult {
    if status_check == crate::validator::StatusCheck::SkipAll {
      return Ok(());
    }

    match &credential.credential_status {
      None => Ok(()),
      Some(status) => {
        if status.type_ == RevocationTimeframeStatus::TYPE {
          let status: VerifierRevocationTimeframeStatus =
            VerifierRevocationTimeframeStatus::try_from(status.clone()).map_err(JwtValidationError::InvalidStatus)?;

          JptCredentialValidatorUtils::check_validity_timeframe(status.0, validity_timeframe)
        } else {
          if status_check == crate::validator::StatusCheck::SkipUnsupported {
            return Ok(());
          }
          Err(JwtValidationError::InvalidStatus(crate::Error::InvalidStatus(format!(
            "unsupported type '{}'",
            status.type_
          ))))
        }
      }
    }
  }
}
