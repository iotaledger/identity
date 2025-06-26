// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Errors that may occur when working with Verifiable Credentials.

#[cfg(target_arch = "wasm32")]
use product_common::impl_wasm_error_from;

/// Alias for a `Result` with the error type [`Error`].
pub type Result<T, E = Error> = ::core::result::Result<T, E>;

/// This type represents errors that can occur when constructing credentials and presentations or their serializations.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  /// Caused when constructing a credential or presentation without a valid base context.
  #[error("missing base context")]
  MissingBaseContext,
  /// Caused when constructing a credential or presentation without a valid base type.
  #[error("missing base type")]
  MissingBaseType,
  /// Caused when constructing a credential without an issuer.
  #[error("missing credential issuer")]
  MissingIssuer,
  /// Caused when constructing a credential without a subject.
  #[error("missing credential subject")]
  MissingSubject,
  /// Caused when constructing a Domain Linkage credential without an expiration date.
  #[error("missing expiration date")]
  MissingExpirationDate,
  /// Caused when constructing a Domain Linkage credential without an origin.
  #[error("missing origin")]
  MissingOrigin,
  /// Caused when constructing a credential with a malformed subject.
  #[error("invalid credential subject")]
  InvalidSubject,
  /// Caused when trying to construct an invalid status.
  #[error("invalid credential status: {0}")]
  InvalidStatus(String),
  /// Caused when constructing an invalid `LinkedDomainService` or `DomainLinkageConfiguration`.
  #[error("domain linkage error: {0}")]
  DomainLinkageError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
  /// Caused when constructing an invalid `LinkedVerifiablePresentationService`.
  #[error("linked verifiable presentation error: {0}")]
  LinkedVerifiablePresentationError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
  /// Caused when attempting to encode a `Credential` containing multiple subjects as a JWT.  
  #[error("could not create JWT claim set from verifiable credential: more than one subject")]
  MoreThanOneSubjectInJwt,
  /// Caused when attempting to convert a JWT to a `Credential` that has conflicting values
  /// between the registered claims and those in the `vc` object.
  #[error("could not convert JWT to the VC data model: {0}")]
  InconsistentCredentialJwtClaims(&'static str),

  /// Caused when deserializing a Presentation with an empty array for the
  /// `verifiableCredential` property.
  #[error("empty verifiableCredential array in presentation")]
  EmptyVerifiableCredentialArray,

  /// Caused when attempting to convert a JWT to a `Presentation` that has conflicting values
  /// between the registered claims and those in the `vp` object.
  #[error("could not convert JWT to the VP data model: {0}")]
  InconsistentPresentationJwtClaims(&'static str),
  /// Caused when attempting to parse a timestamp value that is outside the
  /// valid range defined in [RFC 3339](https://tools.ietf.org/html/rfc3339).  
  #[error("timestamp conversion failed")]
  TimestampConversionError,

  /// Caused by a failure to serialize the JWT claims set representation of a `Credential` or `Presentation`
  /// to JSON.
  #[error("could not serialize JWT claims set")]
  JwtClaimsSetSerializationError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

  /// Caused by a failure to deserialize the JWT claims set representation of a `Credential` or `Presentation` from
  /// JSON.
  #[error("could not deserialize JWT claims set")]
  JwtClaimsSetDeserializationError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

  /// Caused by a failure to deserialize the JPT claims set representation of a `Credential` JSON.
  #[error("could not deserialize JWT claims set")]
  JptClaimsSetDeserializationError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

  /// Cause by an invalid attribute path
  #[error("Attribute Not found")]
  SelectiveDisclosureError,

  /// Failure of an SD-JWT VC operation.
  #[cfg(feature = "sd-jwt-vc")]
  #[error(transparent)]
  SdJwtVc(#[from] crate::sd_jwt_vc::Error),
}

#[cfg(target_arch = "wasm32")]
impl_wasm_error_from!(Error);