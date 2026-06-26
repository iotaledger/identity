// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::StringOrUrl;
use serde::Deserialize;
use serde::Serialize;

use identity_core::common::Timestamp;

/// Options to be set in the JWT claims of a verifiable presentation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtPresentationOptions {
  /// Set the presentation's expiration date.
  /// Default: `None`.
  pub expiration_date: Option<Timestamp>,
  /// Set the issuance date.
  /// Default: current datetime.
  pub issuance_date: Option<Timestamp>,
  /// Sets the audience for presentation (`aud` property in JWT claims).
  /// Default: `None`.
  pub audience: Option<StringOrUrl>,
  /// Custom claims that can be used to set additional claims on the resulting JWT.
  pub custom_claims: Option<Object>,
}

impl JwtPresentationOptions {
  /// Set the presentation's expiration date.
  pub fn expiration_date(mut self, expires: Timestamp) -> Self {
    self.expiration_date = Some(expires);
    self
  }

  /// Set the issuance date.
  pub fn issuance_date(mut self, issued_at: Timestamp) -> Self {
    self.issuance_date = Some(issued_at);
    self
  }

  /// Sets the audience for presentation (`aud` property in JWT claims).
  pub fn audience(mut self, audience: StringOrUrl) -> Self {
    self.audience = Some(audience);
    self
  }
}

impl Default for JwtPresentationOptions {
  fn default() -> Self {
    Self {
      expiration_date: None,
      issuance_date: Some(Timestamp::now_utc()),
      audience: None,
      custom_claims: None,
    }
  }
}
