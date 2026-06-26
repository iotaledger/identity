// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_did::DIDUrl;
use identity_verification::MethodScope;

/// Holds additional options for verifying a JWP
#[non_exhaustive]
#[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JwpVerificationOptions {
  /// Verify the signing verification method relation matches this.
  pub method_scope: Option<MethodScope>,
  /// The DID URl of the method, whose JWK should be used to verify the JWP.
  /// If unset, the `kid` of the JWP is used as the DID Url.
  pub method_id: Option<DIDUrl>,
}

impl JwpVerificationOptions {
  /// Creates a new [`JwpVerificationOptions`].
  pub fn new() -> Self {
    Self::default()
  }

  /// Set the scope of the verification methods that may be used to verify the given JWP.
  pub fn method_scope(mut self, value: MethodScope) -> Self {
    self.method_scope = Some(value);
    self
  }

  /// The DID URl of the method, whose JWK should be used to verify the JWP.
  pub fn method_id(mut self, value: DIDUrl) -> Self {
    self.method_id = Some(value);
    self
  }
}
