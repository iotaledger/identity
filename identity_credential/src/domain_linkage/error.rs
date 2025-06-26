// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

#[cfg(target_arch = "wasm32")]
use product_common::impl_wasm_error_from;

pub(crate) type DomainLinkageValidationResult = Result<(), DomainLinkageValidationError>;

/// An error caused by a failure to verify a Domain Linkage configuration or credential.
#[derive(Debug, thiserror::Error)]
pub struct DomainLinkageValidationError {
  /// Cause of the error.
  pub cause: DomainLinkageValidationErrorCause,
  /// Source of the error.
  pub source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

#[cfg(target_arch = "wasm32")]
impl_wasm_error_from!(DomainLinkageValidationError);

/// List of errors caused by failures to verify a Domain Linkage configuration or credential.
#[derive(Debug, thiserror::Error)]
pub struct DomainLinkageValidationErrorList {
  /// set of errors
  pub errors: Vec<DomainLinkageValidationError>,
}

/// A set of errors coming from validating multiple domain linkage credentials.
impl DomainLinkageValidationErrorList {
  /// Create new set of domain linkage validation errors.
  pub fn new(errors: Vec<DomainLinkageValidationError>) -> Self {
    Self { errors }
  }
}

// Implement for `Error` trait.
impl std::fmt::Display for DomainLinkageValidationErrorList {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{:?}", self.errors)
  }
}

impl std::fmt::Display for DomainLinkageValidationError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.cause)
  }
}

impl From<DomainLinkageValidationError> for &str {
  fn from(value: DomainLinkageValidationError) -> Self {
    value.cause.into()
  }
}

/// The causes for why domain linkage validation can fail.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum DomainLinkageValidationErrorCause {
  /// Caused when a Domain Linkage Credential cannot be successfully validated.
  #[error("invalid credential")]
  CredentialValidationError,
  /// Caused by an invalid JWT.
  #[error("invalid JWT")]
  InvalidJwt,
  /// Caused by a missing expiration date.
  #[error("the expiration date is missing")]
  MissingExpirationDate,
  /// Caused by the presence of an id property on a Domain Linkage Credential.
  #[error("id property is not allowed")]
  ImpermissibleIdProperty,
  /// Caused by a mismatch of the issuer and subject of the Domain Linkage Credential.
  #[error("issuer DID does not match the subject")]
  IssuerSubjectMismatch,
  /// Caused by an invalid Domain Linkage Credential subject.
  #[error("subject id is invalid")]
  InvalidSubjectId,
  /// Caused by the presence of multiple subjects on a Domain Linkage Credential.
  #[error("credential contains multiple subjects")]
  MultipleCredentialSubjects,
  /// Caused by an invalid issuer DID.
  #[error("invalid issuer DID")]
  InvalidIssuer,
  /// Caused by a missing id property on the Domain Linkage Credential subject.
  #[error("subject id property is missing")]
  MissingSubjectId,
  /// Caused by an invalid `type` property on the Domain Linkage Credential.
  #[error("credential type is invalid")]
  InvalidTypeProperty,
  /// Caused by a mismatch between the Domain Linkage Credential subject's origin and the provided domain origin.
  #[error("the subject's origin does not match the provided domain origin")]
  OriginMismatch,
  /// Caused by a missing or invalid Domain Linkage Credential subject's origin.
  #[error("the subject's origin property is either invalid or missing")]
  InvalidSubjectOrigin,
  /// Caused by an invalid semantic structure of the Domain Linkage Configuration.
  #[error("invalid semantic structure of the domain linkage configuration")]
  InvalidStructure,
  /// List of errors stemming from multiple validations.
  #[error("one or more validations failed")]
  List,
}
