// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::validator::JwtValidationError;

#[cfg(target_arch = "wasm32")]
use product_common::impl_wasm_error_from;

/// An error associated with validating KB-JWT.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum KeyBindingJwtError {
  /// Invalid key binding JWT.
  #[error("KB-JWT is invalid")]
  JwtValidationError(#[from] JwtValidationError),

  /// Deserialization failed.
  #[error("Deserialization error")]
  DeserializationError(String),

  /// Error from `sd_jwt_payload`.
  #[error("SdJwt Error {0}")]
  SdJwtError(#[from] sd_jwt_payload::Error),

  /// Invalid hash value.
  #[error("the `_sd_hash` value of the KB-JWT does not match the derived value from the provided SD-JWT")]
  InvalidDigest,

  /// Invalid nonce value.
  #[error("provided nonce does not match the KB-JWT nonce claim")]
  InvalidNonce,

  /// Invalid `aud` value.
  #[error("provided audience value does not match the KB-JWT `aud` claim")]
  AudienceMismatch,

  /// Issuance date validation error.
  #[error("KB-JWT `iat` value is invalid, {0}")]
  IssuanceDate(String),

  /// SD-JWT does not contain a key binding JWT.
  #[error("the provided SD-JWT does not include a KB-JWT")]
  MissingKeyBindingJwt,

  /// Header value `typ` is invalid.
  #[error("header `typ` value is missing or not equal to `kb+jwt`")]
  InvalidHeaderTypValue,
}

#[cfg(target_arch = "wasm32")]
impl_wasm_error_from!(KeyBindingJwtError);