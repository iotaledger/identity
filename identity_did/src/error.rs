// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;

/// Error type caused by invalid DID handling.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  #[error("invalid fragment")]
  InvalidFragment,
  #[error("invalid method id")]
  InvalidMethodId,
  #[error("invalid method name")]
  InvalidMethodName,
  #[error("invalid path")]
  InvalidPath,
  #[error("invalid query")]
  InvalidQuery,
  #[error("invalid scheme")]
  InvalidScheme,
  #[error("{0}")]
  Other(&'static str),
}

impl From<did_url_parser::Error> for Error {
  fn from(error: did_url_parser::Error) -> Self {
    match error {
      did_url_parser::Error::InvalidFragment => Self::InvalidFragment,
      did_url_parser::Error::InvalidMethodId => Self::InvalidMethodId,
      did_url_parser::Error::InvalidMethodName => Self::InvalidMethodName,
      did_url_parser::Error::InvalidPath => Self::InvalidPath,
      did_url_parser::Error::InvalidQuery => Self::InvalidQuery,
      did_url_parser::Error::InvalidScheme => Self::InvalidScheme,
      error => Self::Other(error.as_str()),
    }
  }
}
