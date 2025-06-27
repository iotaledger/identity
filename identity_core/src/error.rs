// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Errors that may occur in the identity core crate.

use crate::convert::Base;

#[cfg(target_arch = "wasm32")]
use product_common::impl_wasm_error_from;

/// Alias for a `Result` with the error type [`Error`].
pub type Result<T, E = Error> = ::core::result::Result<T, E>;

/// This type represents all possible errors that can occur in the library.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  /// Caused by a failure to encode Rust types as JSON.
  #[error("failed to encode JSON")]
  EncodeJSON(#[source] serde_json::Error),
  /// Caused by a failure to decode Rust types from JSON.
  #[error("failed to decode JSON")]
  DecodeJSON(#[source] serde_json::Error),
  /// Caused by a failure to decode base-encoded data.
  #[error("failed to decode {0:?} data")]
  DecodeBase(Base, #[source] multibase::Error),
  /// Caused by a failure to decode multibase-encoded data.
  #[error("failed to decode multibase data")]
  DecodeMultibase(#[source] multibase::Error),
  /// Caused by attempting to parse an invalid `Url`.
  #[error("invalid url")]
  InvalidUrl(#[source] url::ParseError),
  /// Caused by attempting to parse an invalid `Timestamp`.
  #[error("invalid timestamp")]
  InvalidTimestamp(#[source] time::error::Error),
  /// Caused by attempting to create an empty `OneOrSet` instance or remove all its elements.
  #[error("OneOrSet cannot be empty")]
  OneOrSetEmpty,
  /// Caused by attempting to convert a collection with duplicate keys into an OrderedSet.
  #[error("duplicate key in OrderedSet")]
  OrderedSetDuplicate,
}

#[cfg(target_arch = "wasm32")]
impl_wasm_error_from!(Error);