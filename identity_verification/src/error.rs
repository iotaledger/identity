// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Errors that may occur when working with Decentralized Identifiers.

/// Alias for a [`Result`][::core::result::Result] with the error type [Error].
pub type Result<T, E = Error> = ::core::result::Result<T, E>;

/// This type represents all possible errors that can occur in the crate.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  /// Caused by invalid or missing properties when constructing a
  /// [`VerificationMethod`](crate::VerificationMethod).
  #[error("invalid verification method property: {0}")]
  InvalidMethod(&'static str),
  /// Caused when construction of a [`DIDUrl`](identity_did::DIDUrl) fails.
  #[error("invalid DID url")]
  DIDUrlConstructionError(#[source] identity_did::Error),
  /// Caused when the fragment of a [`VerificationMethod`](crate::VerificationMethod) is missing.
  #[error("invalid or empty `id` fragment")]
  MissingIdFragment,
  /// Caused when string does not match any known [`MethodScope`](crate::MethodScope).
  #[error("unknown method scope")]
  UnknownMethodScope,
  /// Caused by key material in a [`MethodData`](crate::MethodData) that is expected to be base58 encoded.
  #[error("invalid base58 key data")]
  InvalidKeyDataBase58,
  /// Caused by key material in a [`MethodData`](crate::MethodData) that is expected to be multibase encoded.
  #[error("invalid multibase key data")]
  InvalidKeyDataMultibase,
  /// Caused by attempting to decode [`MethodData`](crate::MethodData) that is not in the expected encoding.
  #[error("the method data could not be transformed to the desired type")]
  InvalidMethodDataTransformation(&'static str),
  /// Caused by building a [`VerificationMethod`](crate::VerificationMethod) from a key that includes private key
  /// material.
  #[error("invalid verification material: private key material exposed")]
  PrivateKeyMaterialExposed,
  /// Caused by key material that is not a JSON Web Key.
  #[error("verification material format is not publicKeyJwk")]
  NotPublicKeyJwk,
  /// Failed to deserialize [`MethodRef`](crate::MethodRef)
  #[error("invalid method ref; {0}")]
  InvalidMethodRef(#[from] serde_json::Error),
}
