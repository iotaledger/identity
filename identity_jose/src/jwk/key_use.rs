// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

/// Supported algorithms for the JSON Web Key `use` property.
///
/// [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-use)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
pub enum JwkUse {
  /// Digital Signature or MAC.
  #[serde(rename = "sig")]
  Signature,
  /// Encryption.
  #[serde(rename = "enc")]
  Encryption,
  /// Proof
  #[serde(rename = "proof")]
  Proof,
}

impl JwkUse {
  /// Returns the JWK "use" as a `str` slice.
  pub const fn name(&self) -> &'static str {
    match self {
      Self::Signature => "sig",
      Self::Encryption => "enc",
      Self::Proof => "proof",
    }
  }
}

impl Display for JwkUse {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}
