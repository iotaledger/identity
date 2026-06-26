// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Timestamp;
use serde::Deserialize;
use serde::Serialize;

/// Criteria for validating a Key Binding JWT (KB-JWT).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct KeyBindingJwtValidationOptions {
  /// Validates the nonce value of the KB-JWT claims.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub nonce: Option<String>,
  /// Validates the `aud` properties in the KB-JWT claims.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub aud: Option<String>,
  /// Declares that the KB-JWT is considered invalid if the `iat` value in the claims is
  /// earlier than this timestamp.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub earliest_issuance_date: Option<Timestamp>,
  /// Declares that the KB-JWT is considered invalid if the `iat` value in the claims is
  /// later than this timestamp.
  /// Uses the current timestamp during validation if not set.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_issuance_date: Option<Timestamp>,
}

impl KeyBindingJwtValidationOptions {
  /// Constructor that sets all options to their defaults.
  pub fn new() -> Self {
    Self::default()
  }

  /// Validates the nonce value of the KB-JWT claims.
  pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
    self.nonce = Some(nonce.into());
    self
  }

  /// Sets the `aud` property for verification.
  pub fn aud(mut self, aud: impl Into<String>) -> Self {
    self.aud = Some(aud.into());
    self
  }

  /// Declares that the KB-JWT is considered invalid if the `iat` value in the claims is
  /// earlier than this timestamp.
  pub fn earliest_issuance_date(mut self, earliest_issuance_date: Timestamp) -> Self {
    self.earliest_issuance_date = Some(earliest_issuance_date);
    self
  }

  /// Declares that the KB-JWT is considered invalid if the `iat` value in the claims is
  /// later than this timestamp.
  /// Uses the current timestamp during validation if not set.
  pub fn latest_issuance_date(mut self, latest_issuance_date: Timestamp) -> Self {
    self.latest_issuance_date = Some(latest_issuance_date);
    self
  }
}
