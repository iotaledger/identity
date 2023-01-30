// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::ops::Deref;
use core::ops::DerefMut;

use crate::jose::JoseHeader;
use crate::jws::JwsAlgorithm;
use crate::jwt::JwtHeader;

/// JSON Web Signature JOSE Header.
///
/// [More Info](https://tools.ietf.org/html/rfc7515#section-4)
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct JwsHeader {
  /// Common JOSE Header Parameters.
  #[serde(flatten)]
  common: JwtHeader,
  /// Algorithm.
  ///
  /// Identifies the cryptographic algorithm used to secure the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.1)
  #[serde(skip_serializing_if = "Option::is_none")]
  alg: Option<JwsAlgorithm>,
  /// Base64url-Encode Payload.
  ///
  /// Determines whether the payload is represented in the JWS and the JWS
  /// signing input as ASCII(BASE64URL(JWS Payload)) or as the JWS Payload
  /// value itself with no encoding performed.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7797#section-3)
  ///
  /// The following table shows the JWS Signing Input computation, depending
  /// upon the value of this parameter:
  ///
  /// +-------+-----------------------------------------------------------+
  /// | "b64" | JWS Signing Input Formula                                 |
  /// +-------+-----------------------------------------------------------+
  /// | true  | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||     |
  /// |       | BASE64URL(JWS Payload))                                   |
  /// |       |                                                           |
  /// | false | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.') ||    |
  /// |       | JWS Payload                                               |
  /// +-------+-----------------------------------------------------------+
  #[serde(skip_serializing_if = "Option::is_none")]
  b64: Option<bool>,
  /// PASSporT extension identifier.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc8225#section-8.1)
  #[serde(skip_serializing_if = "Option::is_none")]
  ppt: Option<String>,
}

impl JwsHeader {
  /// Create a new empty `JwsHeader`.
  pub const fn new() -> Self {
    Self {
      common: JwtHeader::new(),
      alg: None,
      b64: None,
      ppt: None,
    }
  }

  /// Returns the value for the algorithm claim (alg).
  pub fn alg(&self) -> Option<JwsAlgorithm> {
    self.alg.as_ref().copied()
  }

  /// Sets a value for the algorithm claim (alg).
  pub fn set_alg(&mut self, value: impl Into<JwsAlgorithm>) {
    self.alg = Some(value.into());
  }

  /// Returns the value of the base64url-encode payload claim (b64).
  pub fn b64(&self) -> Option<bool> {
    self.b64
  }

  /// Sets a value for the base64url-encode payload claim (b64).
  pub fn set_b64(&mut self, value: impl Into<bool>) {
    self.b64 = Some(value.into());
  }

  /// Returns the value of the passport extension claim (ppt).
  pub fn ppt(&self) -> Option<&str> {
    self.ppt.as_deref()
  }

  /// Sets a value for the passport extension claim (ppt).
  pub fn set_ppt(&mut self, value: impl Into<String>) {
    self.ppt = Some(value.into());
  }

  // ===========================================================================
  // ===========================================================================

  pub fn has(&self, claim: &str) -> bool {
    match claim {
      "alg" => self.alg().is_some(),
      "b64" => self.b64().is_some(),
      "ppt" => self.ppt().is_some(),
      _ => self.common.has(claim),
    }
  }

  /// Returns `true` if none of the fields are set in both `self` and `other`.
  pub fn is_disjoint(&self, other: &JwsHeader) -> bool {
    let has_duplicate: bool = self.alg().is_some() && other.alg.is_some()
      || self.b64.is_some() && other.b64.is_some()
      || self.ppt.is_some() && other.ppt.is_some();

    !has_duplicate && self.common.is_disjoint(other.common())
  }
}

impl Deref for JwsHeader {
  type Target = JwtHeader;

  fn deref(&self) -> &Self::Target {
    &self.common
  }
}

impl DerefMut for JwsHeader {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.common
  }
}

impl JoseHeader for JwsHeader {
  fn common(&self) -> &JwtHeader {
    self
  }

  fn has_claim(&self, claim: &str) -> bool {
    self.has(claim)
  }
}

impl Default for JwsHeader {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_header_disjoint() {
    let header1: JwsHeader = serde_json::from_value(serde_json::json!({
      "alg": "ES256",
      "b64": false,
    }))
    .unwrap();
    let header2: JwsHeader = serde_json::from_value(serde_json::json!({
      "alg": "ES256",
      "crit": ["b64"],
    }))
    .unwrap();
    let header3: JwsHeader = serde_json::from_value(serde_json::json!({
      "ppt": "pptx",
      "cty": "mediatype"
    }))
    .unwrap();

    assert!(!header1.is_disjoint(&header2));
    assert!(header1.is_disjoint(&header3));
    assert!(header2.is_disjoint(&header3));
    assert!(header1.is_disjoint(&JwsHeader::new()));
  }
}
