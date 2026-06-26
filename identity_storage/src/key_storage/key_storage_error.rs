// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;

use identity_core::common::SingleStructError;

/// Error type for key storage operations.
pub type KeyStorageError = SingleStructError<KeyStorageErrorKind>;

/// The cause of the failed key storage operation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KeyStorageErrorKind {
  /// Indicates that a user tried to generate a key which the key storage implementation
  /// does not support.
  UnsupportedKeyType,

  /// Indicates an attempt to generate or insert a key with a key type that the key storage implementation
  /// deems incompatible with the given signature algorithm.
  KeyAlgorithmMismatch,

  /// Indicates an attempt to parse a signature algorithm that is not recognized by the key storage implementation.
  UnsupportedSignatureAlgorithm,

  /// Indicates an attempt to parse a proof algorithm that is not recognized by the key storage implementation.
  UnsupportedProofAlgorithm,

  /// Indicates that the key storage implementation is not able to find the requested key.
  KeyNotFound,

  /// Indicates that the storage is unavailable for an unpredictable amount of time.
  ///
  /// Occurrences of this variant should hopefully be rare, but could occur if hardware fails, or a hosted key store
  /// goes offline.
  Unavailable,

  /// Indicates that an attempt was made to authenticate with the key storage, but the operation did not succeed.
  Unauthenticated,

  /// Indicates an unsuccessful I/O operation that may be retried, such as a temporary connection failure or timeouts.
  ///
  /// Returning this error signals to the caller that the operation may be retried with a chance of success.
  /// It is at the caller's discretion whether to retry or not, and how often.
  RetryableIOFailure,

  /// Indicates a failure to serialize or deserialize.
  SerializationError,

  /// Indicates that something went wrong, but it is unclear whether the reason matches any of the other variants.
  ///
  /// When using this variant one may want to attach additional context to the corresponding [`KeyStorageError`]. See
  /// [`KeyStorageError::with_custom_message`](KeyStorageError::with_custom_message()) and
  /// [`KeyStorageError::with_source`](KeyStorageError::with_source()).
  Unspecified,
}

impl KeyStorageErrorKind {
  /// Returns the string representation of the error.
  pub const fn as_str(&self) -> &str {
    match self {
      Self::UnsupportedKeyType => "key generation failed: the provided multikey schema is not supported",
      Self::KeyAlgorithmMismatch => "the key type cannot be used with the algorithm",
      Self::UnsupportedSignatureAlgorithm => "signing algorithm parsing failed",
      Self::UnsupportedProofAlgorithm => "proof algorithm parsing failed",
      Self::KeyNotFound => "key not found in storage",
      Self::Unavailable => "key storage unavailable",
      Self::Unauthenticated => "authentication with the key storage failed",
      Self::Unspecified => "key storage operation failed",
      Self::RetryableIOFailure => "key storage was unsuccessful because of an I/O failure",
      Self::SerializationError => "(de)serialization error",
    }
  }
}

impl AsRef<str> for KeyStorageErrorKind {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl Display for KeyStorageErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
  }
}
