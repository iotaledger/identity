// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use crate::key_id_storage::KeyIdStorageError;
use crate::key_id_storage::MethodDigestConstructionError;
use crate::key_storage::KeyStorageError;

/// Errors that can occur when working with the [`JwkDocumentExt`](crate::storage::JwkDocumentExt) API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwkStorageDocumentError {
  /// Caused by a failure in the key storage.
  #[error("storage operation failed: key storage error")]
  KeyStorageError(KeyStorageError),
  /// Caused by a failure in the key id storage.
  #[error("storage operation failed: key id storage error: {0}")]
  KeyIdStorageError(KeyIdStorageError),
  /// Caused by an attempt to add a method with a fragment that already exists.
  #[error("could not add method: the fragment already exists")]
  FragmentAlreadyExists,
  /// Caused by a missing verification method.
  #[error("method not found")]
  MethodNotFound,
  /// Caused by the usage of a non-JWK method where a JWK method is expected.
  #[error("invalid method data format: expected publicKeyJwk")]
  NotPublicKeyJwk,
  /// Caused by the usage of a non-Composite method where a Composite method is expected.
  #[error("invalid method data format: expected compositePublicKey")]
  NotCompositePublicKey,
  /// Caused by an invalid JWS algorithm.
  #[error("invalid JWS algorithm")]
  InvalidJwsAlgorithm,
  /// Caused by an invalid JWP algorithm.
  #[error("invalid JWP algorithm")]
  InvalidJwpAlgorithm,
  /// Cannot construct a valid Jwp (issued or presented form)
  #[error("Not able to construct a valid Jwp")]
  JwpBuildingError,
  /// Credential's proof update internal error
  #[error("Credential's proof internal error")]
  ProofUpdateError(String),
  /// Caused by a failure to construct a verification method.
  #[error("method generation failed: unable to create a valid verification method")]
  VerificationMethodConstructionError(#[source] identity_verification::Error),
  /// Caused by an encoding error.
  #[error("could not produce jwt: encoding error")]
  EncodingError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
  /// Caused by a failure to construct a method digest.
  #[error("unable to produce method digest")]
  MethodDigestConstructionError(#[source] MethodDigestConstructionError),
  /// Caused by a failure during (de)serialization of JWS claims.
  #[error("could not produce JWS payload from the given claims: serialization failed")]
  ClaimsSerializationError(#[source] identity_credential::Error),
  /// Caused by a failure to undo a failed storage operation.
  #[error("storage operation failed after altering state. Unable to undo operation(s): {message}")]
  UndoOperationFailed {
    /// Additional error context.
    message: String,
    /// The source error.
    source: Box<Self>,
    /// The error that occurred during the undo operation.
    undo_error: Option<Box<Self>>,
  },
}

#[cfg(test)]
mod tests {
  use super::JwkStorageDocumentError;
  fn is_send_sync<T: Send + Sync + 'static>(_input: T) {}

  #[test]
  fn error_is_send_sync() {
    is_send_sync(JwkStorageDocumentError::FragmentAlreadyExists);
  }
}
