// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use crate::credential::Credential;
use crate::revocation::RevocationDocumentExt;
use crate::revocation::RevocationTimeframeStatus;
use std::str::FromStr;

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_did::DID;
use jsonprooftoken::encoding::SerializationType;
use jsonprooftoken::jpt::claims::JptClaims;
use jsonprooftoken::jwp::issued::JwpIssuedDecoder;

use crate::credential::CredentialJwtClaims;
use crate::credential::Jpt;
use crate::validator::JwtValidationError;
use crate::validator::SignerContext;

/// Utility functions for verifying JPT credentials.
#[derive(Debug)]
#[non_exhaustive]
pub struct JptCredentialValidatorUtils;

type ValidationUnitResult<T = ()> = std::result::Result<T, JwtValidationError>;

impl JptCredentialValidatorUtils {
  /// Utility for extracting the issuer field of a [`Credential`] as a DID.
  ///
  /// # Errors
  ///
  /// Fails if the issuer field is not a valid DID.
  pub fn extract_issuer<D, T>(credential: &Credential<T>) -> std::result::Result<D, JwtValidationError>
  where
    D: DID,
    <D as FromStr>::Err: std::error::Error + Send + Sync + 'static,
  {
    D::from_str(credential.issuer.url().as_str()).map_err(|err| JwtValidationError::SignerUrl {
      signer_ctx: SignerContext::Issuer,
      source: err.into(),
    })
  }

  /// Utility for extracting the issuer field of a credential in JPT representation as DID.
  ///
  /// # Errors
  ///
  /// If the JPT decoding fails or the issuer field is not a valid DID.
  pub fn extract_issuer_from_issued_jpt<D>(credential: &Jpt) -> std::result::Result<D, JwtValidationError>
  where
    D: DID,
    <D as FromStr>::Err: std::error::Error + Send + Sync + 'static,
  {
    let decoded = JwpIssuedDecoder::decode(credential.as_str(), SerializationType::COMPACT)
      .map_err(JwtValidationError::JwpDecodingError)?;
    let claims = decoded
      .get_header()
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
          let status: RevocationTimeframeStatus =
            RevocationTimeframeStatus::try_from(status).map_err(JwtValidationError::InvalidStatus)?;

          Self::check_validity_timeframe(status, validity_timeframe)
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

  pub(crate) fn check_validity_timeframe(
    status: RevocationTimeframeStatus,
    validity_timeframe: Option<Timestamp>,
  ) -> ValidationUnitResult {
    let timeframe = validity_timeframe.unwrap_or(Timestamp::now_utc());

    let check = timeframe >= status.start_validity_timeframe() && timeframe <= status.end_validity_timeframe();

    if !check {
      Err(JwtValidationError::OutsideTimeframe)
    } else {
      Ok(())
    }
  }

  /// Checks whether the credential status has been revoked.
  ///
  /// Only supports `RevocationTimeframe2024`.
  pub fn check_revocation_with_validity_timeframe_2024<
    DOC: AsRef<identity_document::document::CoreDocument> + ?Sized,
    T,
  >(
    credential: &Credential<T>,
    issuer: &DOC,
    status_check: crate::validator::StatusCheck,
  ) -> ValidationUnitResult {
    if status_check == crate::validator::StatusCheck::SkipAll {
      return Ok(());
    }

    match &credential.credential_status {
      None => Ok(()),
      Some(status) => {
        if status.type_ == RevocationTimeframeStatus::TYPE {
          let status: RevocationTimeframeStatus =
            RevocationTimeframeStatus::try_from(status).map_err(JwtValidationError::InvalidStatus)?;

          Self::check_revocation_bitmap(issuer, status)
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

  /// Check the given `status` against the matching [`RevocationBitmap`] service in the issuer's DID Document.
  fn check_revocation_bitmap<DOC: AsRef<identity_document::document::CoreDocument> + ?Sized>(
    issuer: &DOC,
    status: RevocationTimeframeStatus,
  ) -> ValidationUnitResult {
    let issuer_service_url: identity_did::DIDUrl = identity_did::DIDUrl::parse(status.id()).map_err(|err| {
      JwtValidationError::InvalidStatus(crate::Error::InvalidStatus(format!(
        "could not convert status id to DIDUrl; {err}",
      )))
    })?;

    // Check whether index is revoked.
    let revocation_bitmap: crate::revocation::RevocationBitmap = issuer
      .as_ref()
      .resolve_revocation_bitmap(issuer_service_url.into())
      .map_err(|_| JwtValidationError::ServiceLookupError)?;

    if let Some(index) = status.index() {
      if revocation_bitmap.is_revoked(index) {
        return Err(JwtValidationError::Revoked);
      }
    }
    Ok(())
  }

  /// Checks whether the credential status has been revoked or the timeframe interval is INVALID
  ///
  /// Only supports `RevocationTimeframe2024`.
  pub fn check_timeframes_and_revocation_with_validity_timeframe_2024<
    DOC: AsRef<identity_document::document::CoreDocument> + ?Sized,
    T,
  >(
    credential: &Credential<T>,
    issuer: &DOC,
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
          let status: RevocationTimeframeStatus =
            RevocationTimeframeStatus::try_from(status).map_err(JwtValidationError::InvalidStatus)?;

          let revocation = std::iter::once_with(|| Self::check_revocation_bitmap(issuer, status.clone()));

          let timeframes = std::iter::once_with(|| Self::check_validity_timeframe(status.clone(), validity_timeframe));

          let checks_iter = revocation.chain(timeframes);

          let checks_error_iter = checks_iter.filter_map(|result| result.err());

          let mut checks_errors: Vec<JwtValidationError> = checks_error_iter.take(1).collect();

          match checks_errors.pop() {
            Some(err) => Err(err),
            None => Ok(()),
          }
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
