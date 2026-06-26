// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;

use identity_core::common::SingleStructError;

/// Error type for key id storage operations.
pub type KeyIdStorageError = SingleStructError<KeyIdStorageErrorKind>;

/// The cause of the failed key id storage operation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KeyIdStorageErrorKind {
  /// Indicates that the key id storage implementation is not able to find the requested key id.
  KeyIdNotFound,

  /// Indicates that the key id already exists in the storage.
  KeyIdAlreadyExists,

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
  /// When using this variant one may want to attach additional context to the corresponding [`KeyIdStorageError`]. See
  /// [`KeyIdStorageError::with_custom_message`](KeyIdStorageError::with_custom_message()) and
  /// [`KeyIdStorageError::with_source`](KeyIdStorageError::with_source()).
  Unspecified,
}

impl KeyIdStorageErrorKind {
  /// Returns the string representation of the error.
  pub const fn as_str(&self) -> &str {
    match self {
      Self::KeyIdAlreadyExists => "Key id already exists in storage",
      Self::KeyIdNotFound => "key id not found in storage",
      Self::Unavailable => "key id storage unavailable",
      Self::Unauthenticated => "authentication with the key id storage failed",
      Self::Unspecified => "key id storage operation failed",
      Self::RetryableIOFailure => "key id storage was unsuccessful because of an I/O failure",
      Self::SerializationError => "(de)serialization error",
    }
  }
}

impl AsRef<str> for KeyIdStorageErrorKind {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl Display for KeyIdStorageErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
  }
}
