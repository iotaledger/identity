// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::ops::Deref;
use core::ops::DerefMut;
use std::collections::BTreeMap;

use serde_json::Value;

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

  /// Additional header parameters.
  #[serde(flatten, skip_serializing_if = "Option::is_none")]
  custom: Option<BTreeMap<String, Value>>,
}

impl JwsHeader {
  /// Create a new empty `JwsHeader`.
  pub const fn new() -> Self {
    Self {
      common: JwtHeader::new(),
      alg: None,
      b64: None,
      custom: None,
    }
  }

  /// Returns the value for the algorithm claim (alg).
  pub fn alg(&self) -> Option<JwsAlgorithm> {
    self.alg.as_ref().cloned()
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

  /// Returns the additional parameters in the header.
  pub fn custom(&self) -> Option<&BTreeMap<String, Value>> {
    self.custom.as_ref()
  }

  /// Sets additional parameters in the header.
  pub fn set_custom(&mut self, value: BTreeMap<String, Value>) {
    self.custom = Some(value)
  }

  /// Returns `true` if the header contains the given `claim`, `false` otherwise.
  pub fn has(&self, claim: &str) -> bool {
    match claim {
      "alg" => self.alg().is_some(),
      "b64" => self.b64().is_some(),
      _ => {
        self.common.has(claim)
          || self
            .custom
            .as_ref()
            .map(|custom| custom.get(claim).is_some())
            .unwrap_or(false)
      }
    }
  }

  /// Returns `true` if none of the fields are set in both `self` and `other`.
  pub fn is_disjoint(&self, other: &JwsHeader) -> bool {
    let has_duplicate: bool = self.alg().is_some() && other.alg.is_some() || self.b64.is_some() && other.b64.is_some();

    !has_duplicate && self.common.is_disjoint(other.common()) && self.is_custom_disjoint(other)
  }

  /// Returns `true` if none of the fields are set in both `self.custom` and `other.custom`.
  fn is_custom_disjoint(&self, other: &JwsHeader) -> bool {
    match (&self.custom, &other.custom) {
      (Some(self_custom), Some(other_custom)) => {
        for self_key in self_custom.keys() {
          if other_custom.contains_key(self_key) {
            return false;
          }
        }
        true
      }
      _ => true,
    }
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
  fn test_custom() {
    let header1: JwsHeader = serde_json::from_value(serde_json::json!({
      "alg": "ES256",
      "b64": false,
      "test": "tst-value",
      "test-bool": false
    }))
    .unwrap();

    assert_eq!(
      header1.custom().unwrap().get("test").unwrap().as_str().unwrap(),
      "tst-value".to_owned()
    );

    assert!(!header1.custom().unwrap().get("test-bool").unwrap().as_bool().unwrap());
    assert!(header1.has("test"));
    assert!(!header1.has("invalid"));
  }

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
      "kid": "kid value",
      "cty": "mediatype",
      "custom": "test value",
    }))
    .unwrap();
    let header4: JwsHeader = serde_json::from_value(serde_json::json!({
      "custom": "test value",
    }))
    .unwrap();

    assert!(!header1.is_disjoint(&header2));
    assert!(header1.is_disjoint(&header3));
    assert!(header2.is_disjoint(&header3));
    assert!(header1.is_disjoint(&JwsHeader::new()));
    assert!(!header4.is_disjoint(&header3));
    assert!(header4.is_disjoint(&header2));
  }
}
