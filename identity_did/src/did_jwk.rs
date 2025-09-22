// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::str::FromStr;

use identity_jose::jwk::Jwk;
use identity_jose::jwu::decode_b64_json;
use identity_jose::jwu::encode_b64_json;

use crate::CoreDID;
use crate::Error;
use crate::DID;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(into = "CoreDID", try_from = "CoreDID")]
/// A type representing a `did:jwk` DID.
pub struct DIDJwk {
  did: CoreDID,
  jwk: Jwk,
}

impl DIDJwk {
  /// [`DIDJwk`]'s method.
  pub const METHOD: &'static str = "jwk";

  /// Creates a new [DIDJwk] from the given [Jwk].
  pub fn new(jwk: Jwk) -> Self {
    let did_str = format!("did:jwk:{}", encode_b64_json(&jwk).expect("valid JSON"));
    let did = did_str.parse().expect("valid CoreDID");

    Self { did, jwk }
  }

  /// Tries to parse a [`DIDJwk`] from a string.
  pub fn parse(s: &str) -> Result<Self, Error> {
    s.parse()
  }

  /// Returns the JWK encoded inside this did:jwk.
  pub fn jwk(&self) -> Jwk {
    self.jwk.clone()
  }

  /// Returns a reference to the [Jwk] encoded inside this did:jwk.
  pub fn as_jwk(&self) -> &Jwk {
    &self.jwk
  }
}

impl Ord for DIDJwk {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.did.cmp(&other.did)
  }
}

impl PartialOrd for DIDJwk {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl Hash for DIDJwk {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.did.hash(state)
  }
}

impl AsRef<CoreDID> for DIDJwk {
  fn as_ref(&self) -> &CoreDID {
    &self.did
  }
}

impl AsRef<Jwk> for DIDJwk {
  fn as_ref(&self) -> &Jwk {
    &self.jwk
  }
}

impl From<DIDJwk> for CoreDID {
  fn from(value: DIDJwk) -> Self {
    value.did
  }
}

impl<'a> TryFrom<&'a str> for DIDJwk {
  type Error = Error;
  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    value.parse()
  }
}

impl Display for DIDJwk {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.did)
  }
}

impl FromStr for DIDJwk {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    s.parse::<CoreDID>().and_then(TryFrom::try_from)
  }
}

impl From<DIDJwk> for String {
  fn from(value: DIDJwk) -> Self {
    value.to_string()
  }
}

impl From<DIDJwk> for Jwk {
  fn from(value: DIDJwk) -> Self {
    value.jwk
  }
}

impl TryFrom<CoreDID> for DIDJwk {
  type Error = Error;
  fn try_from(value: CoreDID) -> Result<Self, Self::Error> {
    let Self::METHOD = value.method() else {
      return Err(Error::InvalidMethodName);
    };
    decode_b64_json(value.method_id())
      .map(|jwk| Self { did: value, jwk })
      .map_err(|_| Error::InvalidMethodId)
  }
}

#[cfg(test)]
mod tests {
  use identity_core::convert::FromJson;

  use super::*;

  #[test]
  fn test_valid_deserialization() -> Result<(), Error> {
    "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".parse::<DIDJwk>()?;
    "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".parse::<DIDJwk>()?;

    Ok(())
  }

  #[test]
  fn test_jwk() {
    let did = DIDJwk::parse("did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9").unwrap();
    let target_jwk = Jwk::from_json_value(serde_json::json!({
      "kty":"OKP","crv":"X25519","use":"enc","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
    }))
    .unwrap();

    assert_eq!(did.jwk(), target_jwk);
  }

  #[test]
  fn test_new() {
    let jwk = Jwk::from_json_value(serde_json::json!({
      "kty":"OKP","crv":"X25519","use":"enc","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
    }))
    .unwrap();
    let target_did_jwk = DIDJwk::parse(&format!("did:jwk:{}", encode_b64_json(&jwk).unwrap())).unwrap();

    let did_jwk = DIDJwk::new(jwk);
    assert_eq!(target_did_jwk, did_jwk);
  }

  #[test]
  fn test_invalid_deserialization() {
    assert!(
      "did:iota:0xf4d6f08f5a1b80dd578da7dc1b49c886d580acd4cf7d48119dfeb82b538ad88a"
        .parse::<DIDJwk>()
        .is_err()
    );
    assert!("did:jwk:".parse::<DIDJwk>().is_err());
    assert!("did:jwk:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
      .parse::<DIDJwk>()
      .is_err());
  }
}
