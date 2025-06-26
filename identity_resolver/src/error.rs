// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0


#[cfg(target_arch = "wasm32")]
use product_common::bindings::wasm_error;
#[cfg(target_arch = "wasm32")]
use std::borrow::Cow;

/// Alias for a `Result` with the error type [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Error returned from the [Resolver's](crate::Resolver) methods.
///
/// The [`Self::error_cause`](Self::error_cause()) method provides information about the cause of the error.
#[derive(Debug)]
pub struct Error {
  error_cause: ErrorCause,
}

#[cfg(target_arch = "wasm32")]
impl From<Error> for wasm_error::WasmError<'_> {
  fn from(error: Error) -> Self {
    Self {
      name: Cow::Owned(format!("ResolverError::{}", <&'static str>::from(error.error_cause()))),
      message: Cow::Owned(wasm_error::ErrorMessage(&error).to_string()),
    }
  }
}

impl Error {
  pub(crate) fn new(cause: ErrorCause) -> Self {
    Self { error_cause: cause }
  }

  /// Returns the cause of the error.
  pub fn error_cause(&self) -> &ErrorCause {
    &self.error_cause
  }

  /// Converts the error into [`ErrorCause`].
  pub fn into_error_cause(self) -> ErrorCause {
    self.error_cause
  }
}

impl std::fmt::Display for Error {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.error_cause)
  }
}

impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    self.error_cause.source()
  }
}

/// Error failure modes associated with the methods on the [Resolver's](crate::Resolver).
///
/// NOTE: This is a "read only error" in the sense that it can only be constructed by the methods in this crate.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum ErrorCause {
  /// Caused by a failure to parse a DID string during DID resolution.
  #[error("did resolution failed: could not parse the given did")]
  #[non_exhaustive]
  DIDParsingError {
    /// The source of the parsing error.
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
  },
  /// A handler attached to the [`Resolver`](crate::resolution::Resolver) attempted to resolve the DID, but the
  /// resolution did not succeed.
  #[error("did resolution failed: the attached handler failed")]
  #[non_exhaustive]
  HandlerError {
    /// The source of the handler error.
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
  },
  /// Caused by attempting to resolve a DID whose method does not have a corresponding handler attached to the
  /// [`Resolver`](crate::resolution::Resolver).
  #[error("did resolution failed: the DID method \"{method}\" is not supported by the resolver")]
  UnsupportedMethodError {
    /// The method that is unsupported.
    method: String,
  },
  /// No client attached to the specific network.
  #[error("none of the attached clients support the network {0}")]
  UnsupportedNetwork(String),
}
