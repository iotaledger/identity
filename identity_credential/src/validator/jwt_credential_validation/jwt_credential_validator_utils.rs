// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::str::FromStr;

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_did::DID;
use identity_verification::jws::Decoder;

use super::JwtValidationError;
use super::SignerContext;
use crate::credential::Credential;
use crate::credential::CredentialJwtClaims;
use crate::credential::CredentialT;
use crate::credential::Jwt;
#[cfg(feature = "status-list-2021")]
use crate::revocation::status_list_2021::StatusList2021Credential;
use crate::validator::SubjectHolderRelationship;

/// Utility functions for verifying JWT credentials.
#[derive(Debug)]
#[non_exhaustive]
pub struct JwtCredentialValidatorUtils;

type ValidationUnitResult<T = ()> = std::result::Result<T, JwtValidationError>;

impl JwtCredentialValidatorUtils {
  /// Validates the semantic structure of the [`Credential`].
  ///
  /// # Warning
  /// This does not validate against the credential's schema nor the structure of the subject claims.
  pub fn check_structure<T>(credential: &dyn CredentialT<Properties = T>) -> ValidationUnitResult {
    // Ensure the base context is present and in the correct location
    match credential.context().get(0) {
      Some(context) if context == credential.base_context() => {}
      Some(_) | None => {
        return Err(JwtValidationError::CredentialStructure(
          crate::Error::MissingBaseContext,
        ))
      }
    }

    // The set of types MUST contain the base type
    if !credential
      .type_()
      .iter()
      .any(|type_| type_ == Credential::<T>::base_type())
    {
      return Err(JwtValidationError::CredentialStructure(crate::Error::MissingBaseType));
    }

    // Credentials MUST have at least one subject
    if credential.subject().is_empty() {
      return Err(JwtValidationError::CredentialStructure(crate::Error::MissingSubject));
    }

    // Each subject is defined as one or more properties - no empty objects
    for subject in credential.subject().iter() {
      if subject.id.is_none() && subject.properties.is_empty() {
        return Err(JwtValidationError::CredentialStructure(crate::Error::InvalidSubject));
      }
    }

    Ok(())
  }

  /// Validate that the [`Credential`] expires on or after the specified [`Timestamp`].
  pub fn check_expires_on_or_after<T>(
    credential: &dyn CredentialT<Properties = T>,
    timestamp: Timestamp,
  ) -> ValidationUnitResult {
    match credential.valid_until() {
      Some(exp) if exp < timestamp => Err(JwtValidationError::ExpirationDate),
      _ => Ok(()),
    }
  }

  /// Validate that the [`Credential`] is issued on or before the specified [`Timestamp`].
  pub fn check_issued_on_or_before<T>(
    credential: &dyn CredentialT<Properties = T>,
    timestamp: Timestamp,
  ) -> ValidationUnitResult {
    if credential.valid_from() <= timestamp {
      Ok(())
    } else {
      Err(JwtValidationError::IssuanceDate)
    }
  }

  /// Validate that the relationship between the `holder` and the credential subjects is in accordance with
  /// `relationship`.
  pub fn check_subject_holder_relationship<T>(
    credential: &dyn CredentialT<Properties = T>,
    holder: &Url,
    relationship: SubjectHolderRelationship,
  ) -> ValidationUnitResult {
    let url_matches = || {
      if let [subject] = credential.subject().as_slice() {
        subject.id.as_ref() == Some(holder)
      } else {
        false
      }
    };

    let valid = match relationship {
      SubjectHolderRelationship::AlwaysSubject => url_matches(),
      SubjectHolderRelationship::SubjectOnNonTransferable => url_matches() || !credential.non_transferable(),
      SubjectHolderRelationship::Any => true,
    };

    if valid {
      Ok(())
    } else {
      Err(JwtValidationError::SubjectHolderRelationship)
    }
  }

  /// Checks whether the status specified in `credentialStatus` has been set by the issuer.
  ///
  /// Only supports `StatusList2021`.
  #[cfg(feature = "status-list-2021")]
  pub fn check_status_with_status_list_2021<T>(
    credential: &dyn CredentialT<Properties = T>,
    status_list_credential: &StatusList2021Credential,
    status_check: crate::validator::StatusCheck,
  ) -> ValidationUnitResult {
    use crate::revocation::status_list_2021::CredentialStatus;
    use crate::revocation::status_list_2021::StatusList2021Entry;

    if status_check == crate::validator::StatusCheck::SkipAll {
      return Ok(());
    }

    let Some(status) = credential.status() else {
      return Ok(());
    };

    let status = StatusList2021Entry::try_from(status)
      .map_err(|e| JwtValidationError::InvalidStatus(crate::Error::InvalidStatus(e.to_string())))?;
    if Some(status.status_list_credential()) == status_list_credential.id.as_ref()
      && status.purpose() == status_list_credential.purpose()
    {
      let entry_status = status_list_credential
        .entry(status.index())
        .map_err(|e| JwtValidationError::InvalidStatus(crate::Error::InvalidStatus(e.to_string())))?;
      match entry_status {
        CredentialStatus::Revoked => Err(JwtValidationError::Revoked),
        CredentialStatus::Suspended => Err(JwtValidationError::Suspended),
        CredentialStatus::Valid => Ok(()),
      }
    } else {
      Err(JwtValidationError::InvalidStatus(crate::Error::InvalidStatus(
        "The given statusListCredential doesn't match the credential's status".to_owned(),
      )))
    }
  }

  /// Checks whether the credential status has been revoked.
  ///
  /// Only supports `RevocationBitmap2022`.
  #[cfg(feature = "revocation-bitmap")]
  pub fn check_status<DOC: AsRef<identity_document::document::CoreDocument>, T>(
    credential: &dyn CredentialT<Properties = T>,
    trusted_issuers: &[DOC],
    status_check: crate::validator::StatusCheck,
  ) -> ValidationUnitResult {
    use identity_did::CoreDID;
    use identity_document::document::CoreDocument;

    if status_check == crate::validator::StatusCheck::SkipAll {
      return Ok(());
    }

    let Some(status) = credential.status() else {
      return Ok(());
    };

    // Check status is supported.
    if status.type_ != crate::revocation::RevocationBitmap::TYPE {
      if status_check == crate::validator::StatusCheck::SkipUnsupported {
        return Ok(());
      }
      return Err(JwtValidationError::InvalidStatus(crate::Error::InvalidStatus(format!(
        "unsupported type '{}'",
        status.type_
      ))));
    }
    let status: crate::credential::RevocationBitmapStatus =
      crate::credential::RevocationBitmapStatus::try_from(status.clone()).map_err(JwtValidationError::InvalidStatus)?;

    // Check the credential index against the issuer's DID Document.
    let issuer_did: CoreDID = Self::extract_issuer(credential)?;
    trusted_issuers
      .iter()
      .find(|issuer| <CoreDocument>::id(issuer.as_ref()) == &issuer_did)
      .ok_or(JwtValidationError::DocumentMismatch(SignerContext::Issuer))
      .and_then(|issuer| Self::check_revocation_bitmap_status(issuer, status))
  }

  /// Check the given `status` against the matching [`RevocationBitmap`] service in the
  /// issuer's DID Document.
  #[cfg(feature = "revocation-bitmap")]
  pub fn check_revocation_bitmap_status<DOC: AsRef<identity_document::document::CoreDocument> + ?Sized>(
    issuer: &DOC,
    status: crate::credential::RevocationBitmapStatus,
  ) -> ValidationUnitResult {
    use crate::revocation::RevocationDocumentExt;

    let issuer_service_url: identity_did::DIDUrl = status.id().map_err(JwtValidationError::InvalidStatus)?;

    // Check whether index is revoked.
    let revocation_bitmap: crate::revocation::RevocationBitmap = issuer
      .as_ref()
      .resolve_revocation_bitmap(issuer_service_url.into())
      .map_err(|_| JwtValidationError::ServiceLookupError)?;
    let index: u32 = status.index().map_err(JwtValidationError::InvalidStatus)?;
    if revocation_bitmap.is_revoked(index) {
      Err(JwtValidationError::Revoked)
    } else {
      Ok(())
    }
  }

  /// Utility for extracting the issuer field of a [`Credential`] as a DID.
  ///
  /// # Errors
  ///
  /// Fails if the issuer field is not a valid DID.
  pub fn extract_issuer<D, T>(
    credential: &dyn CredentialT<Properties = T>,
  ) -> std::result::Result<D, JwtValidationError>
  where
    D: DID,
    <D as FromStr>::Err: std::error::Error + Send + Sync + 'static,
  {
    D::from_str(credential.issuer().url().as_str()).map_err(|err| JwtValidationError::SignerUrl {
      signer_ctx: SignerContext::Issuer,
      source: err.into(),
    })
  }

  /// Utility for extracting the issuer field of a credential in JWT representation as DID.
  ///
  /// # Errors
  ///
  /// If the JWT decoding fails or the issuer field is not a valid DID.
  pub fn extract_issuer_from_jwt<D>(credential: &Jwt) -> std::result::Result<D, JwtValidationError>
  where
    D: DID,
    <D as FromStr>::Err: std::error::Error + Send + Sync + 'static,
  {
    let validation_item = Decoder::new()
      .decode_compact_serialization(credential.as_str().as_bytes(), None)
      .map_err(JwtValidationError::JwsDecodingError)?;

    let claims: CredentialJwtClaims<'_, Object> = CredentialJwtClaims::from_json_slice(&validation_item.claims())
      .map_err(|err| {
        JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
      })?;

    D::from_str(claims.iss.url().as_str()).map_err(|err| JwtValidationError::SignerUrl {
      signer_ctx: SignerContext::Issuer,
      source: err.into(),
    })
  }
}
