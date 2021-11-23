// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Fragment;
use identity_did::verification::MethodType;

use crate::types::KeyLocation;

/// Errors than may occur while processing an update in the [`Account`][crate::account::Account].
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
  #[error("document already exists")]
  DocumentAlreadyExists,
  #[error("verification method not found")]
  MethodNotFound,
  #[error("service not found")]
  ServiceNotFound,
  #[error("invalid method type - {}", .0.as_str())]
  InvalidMethodType(MethodType),
  #[error("invalid method fragment - {0}")]
  InvalidMethodFragment(&'static str),
  #[error("invalid method secret: {0}")]
  InvalidMethodSecret(String),
  /// Caused by attempting to attach or detach a relationship on an embedded method.
  #[error("invalid target method - method is embedded")]
  InvalidTargetEmbeddedMethod,
  #[error("missing required field - {0}")]
  MissingRequiredField(&'static str),
  #[error("duplicate key location - {0}")]
  DuplicateKeyLocation(KeyLocation),
  #[error("duplicate key fragment - {0}")]
  DuplicateKeyFragment(Fragment),
  #[error("duplicate service fragment - {0}")]
  DuplicateServiceFragment(String),
}
