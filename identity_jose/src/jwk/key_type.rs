// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

/// Supported types for the JSON Web Key `kty` property.
///
/// [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-types)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
pub enum JwkType {
  /// Elliptic Curve.
  #[serde(rename = "EC")]
  Ec,
  /// RSA.
  #[serde(rename = "RSA")]
  Rsa,
  /// Octet sequence.
  #[serde(rename = "oct")]
  Oct,
  /// Octet string key pairs.
  #[serde(rename = "OKP")]
  Okp,
  /// Algorithm Key Pair, JSON Web Key Type for the ML-DSA and SLH-DSA Algorithm Family.
  /// [More Info] (https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-06#name-algorithm-key-pair-type)
  #[serde(rename = "AKP")]
  Akp,
}

impl JwkType {
  /// Returns the JWK "kty" as a `str` slice.
  pub const fn name(self) -> &'static str {
    match self {
      Self::Ec => "EC",
      Self::Rsa => "RSA",
      Self::Oct => "oct",
      Self::Okp => "OKP",
      Self::Akp => "AKP",
    }
  }
}

impl Display for JwkType {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}
