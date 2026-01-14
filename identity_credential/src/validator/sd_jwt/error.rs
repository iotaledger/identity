// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;

use crate::validator::JwtValidationError;

/// An error indicating that an unexpected value was found.
#[derive(Debug)]
pub struct UnexpectedValue {
  /// The optional expected value.
  pub expected: Option<Cow<'static, str>>,
  /// The actual value that was found.
  pub found: Box<str>,
}

impl Display for UnexpectedValue {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if let Some(expected) = &self.expected {
      write!(f, "expected \"{expected}\", but found \"{}\"", self.found)
    } else {
      write!(f, "unexpected \"{}\"", self.found)
    }
  }
}

impl std::error::Error for UnexpectedValue {}

/// An error associated with validating KB-JWT.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum KeyBindingJwtError {
  /// Invalid key binding JWT.
  #[error("KB-JWT is invalid")]
  JwtValidationError(
    #[source]
    #[from]
    JwtValidationError,
  ),

  /// Deserialization failed.
  #[error("Deserialization error")]
  DeserializationError(#[source] Box<dyn std::error::Error + Send + Sync>),

  /// Error from `sd_jwt_payload`.
  #[error(transparent)]
  SdJwtError(#[from] sd_jwt::Error),

  /// The SD-JWT contains a 'cnf' value that cannot be processed.
  /// Valid values are [`Kid`](sd_jwt::RequiredKeyBinding::Kid) and
  /// [`Jwk`](sd_jwt::RequiredKeyBinding::Jwk).
  #[error("unsupported 'cnf' value")]
  UnsupportedCnfMethod,

  /// Invalid hash value.
  #[error("invalid KB-JWT 'sd_hash' value")]
  InvalidDigest(#[source] UnexpectedValue),

  /// Invalid nonce value.
  #[error("invalid KB-JWT 'nonce' value")]
  InvalidNonce(#[source] UnexpectedValue),

  /// Invalid `aud` value.
  #[error("invalid KB-JWT 'aud' value")]
  AudienceMismatch(#[source] UnexpectedValue),

  /// Issuance date validation error.
  #[error("invalid KB-JWT 'iat' value, {0}")]
  IssuanceDate(String),

  /// SD-JWT does not contain a key binding JWT.
  #[error("SD-JWT token requires a KB-JWT, but none was found")]
  MissingKeyBindingJwt,

  /// Header value `typ` is invalid.
  #[error("invalid KB-JWT header 'typ' value")]
  InvalidHeaderTypValue(#[source] UnexpectedValue),
}
