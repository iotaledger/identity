// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;

use crate::StorageError;
use crate::StorageErrorKind;

/// Error type for key id storage operations.
pub type KeyIdStorageError = StorageError<KeyIdStorageErrorKind>;

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
  /// When using this variant one may want to attach additional context to the corresponding [`StorageError`]. See
  /// [`KeyStorageError::with_custom_message`](KeyIdStorageError::with_custom_message()) and
  /// [`KeyStorageError::with_source`](KeyIdStorageError::with_source()).
  Unspecified,
}

impl StorageErrorKind for KeyIdStorageErrorKind {
  fn description(&self) -> &str {
    match self {
      Self::KeyIdAlreadyExists => "Key id already exists in storage",
      Self::KeyIdNotFound => "key id not found",
      Self::Unavailable => "key id storage unavailable",
      Self::Unauthenticated => "authentication with the key id storage failed",
      Self::Unspecified => "key storage operation failed",
      Self::RetryableIOFailure => "key id storage was unsuccessful because of an I/O failure",
      Self::SerializationError => "(de)serialization error",
    }
  }
}

impl Display for KeyIdStorageErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.description())
  }
}
