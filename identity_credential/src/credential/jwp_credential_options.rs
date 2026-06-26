// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

/// Options for creating a JSON Web Proof.
#[non_exhaustive]
#[derive(Debug, Default, serde::Serialize, serde::Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct JwpCredentialOptions {
  /// The kid to set in the Issuer Protected Header.
  ///
  /// If unset, the kid of the JWK with which the JWP is produced is used.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub kid: Option<String>,
}

impl JwpCredentialOptions {
  /// Creates a new [`JwsSignatureOptions`].
  pub fn new() -> Self {
    Self::default()
  }

  /// Replace the value of the `kid` field.
  pub fn kid(mut self, value: impl Into<String>) -> Self {
    self.kid = Some(value.into());
    self
  }
}
