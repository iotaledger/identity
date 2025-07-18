// Copyright 2020-2025 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fmt::Display;
use std::str::FromStr;

use identity_jose::jwk::CompositeJwk;
use identity_jose::jwu::decode_b64_json;

use crate::CoreDID;
use crate::Error;
use crate::DID;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
#[serde(into = "CoreDID", try_from = "CoreDID")]
/// A type representing a `did:compositejwk` DID.
pub struct DIDCompositeJwk(CoreDID);

impl DIDCompositeJwk {
  /// [`DIDCompositeJwk`]'s method.
  pub const METHOD: &'static str = "compositejwk";

  /// Tries to parse a [`DIDCompositeJwk`] from a string.
  pub fn parse(s: &str) -> Result<Self, Error> {
    s.parse()
  }

  /// Returns the JWK encoded inside this did:jwk.
  pub fn composite_jwk(&self) -> CompositeJwk {
    decode_b64_json(self.method_id()).expect("did:compositejwk encodes a valid compositeJwk")
  }
}

impl AsRef<CoreDID> for DIDCompositeJwk {
  fn as_ref(&self) -> &CoreDID {
    &self.0
  }
}

impl From<DIDCompositeJwk> for CoreDID {
  fn from(value: DIDCompositeJwk) -> Self {
    value.0
  }
}

impl<'a> TryFrom<&'a str> for DIDCompositeJwk {
  type Error = Error;
  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    value.parse()
  }
}

impl Display for DIDCompositeJwk {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl FromStr for DIDCompositeJwk {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    s.parse::<CoreDID>().and_then(TryFrom::try_from)
  }
}

impl From<DIDCompositeJwk> for String {
  fn from(value: DIDCompositeJwk) -> Self {
    value.to_string()
  }
}

impl TryFrom<CoreDID> for DIDCompositeJwk {
  type Error = Error;
  fn try_from(value: CoreDID) -> Result<Self, Self::Error> {
    let Self::METHOD = value.method() else {
      return Err(Error::InvalidMethodName);
    };
    decode_b64_json::<CompositeJwk>(value.method_id())
      .map(|_| Self(value))
      .map_err(|_| Error::InvalidMethodId)
  }
}
