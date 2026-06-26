// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

/// Supported algorithms for the JSON Web Key `key_ops` property.
///
/// [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-operations)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JwkOperation {
  /// Compute digital signature or MAC.
  Sign,
  /// Verify digital signature or MAC.
  Verify,
  /// Encrypt content.
  Encrypt,
  /// Decrypt content and validate decryption, if applicable.
  Decrypt,
  /// Encrypt key.
  WrapKey,
  /// Decrypt key and validate decryption, if applicable.
  UnwrapKey,
  /// Derive key.
  DeriveKey,
  /// Derive bits not to be used as a key.
  DeriveBits,
  /// Compute proof
  ProofGeneration,
  /// Verify proof
  ProofVerification,
}

impl JwkOperation {
  /// Returns the JWK "key_ops" as a `str` slice.
  pub const fn name(&self) -> &'static str {
    match self {
      Self::Sign => "sign",
      Self::Verify => "verify",
      Self::Encrypt => "encrypt",
      Self::Decrypt => "decrypt",
      Self::WrapKey => "wrapKey",
      Self::UnwrapKey => "unwrapKey",
      Self::DeriveKey => "deriveKey",
      Self::DeriveBits => "deriveBits",
      Self::ProofGeneration => "proofGeneration",
      Self::ProofVerification => "proofVerification",
    }
  }

  /// Returns the inverse operation of `self`.
  pub const fn invert(&self) -> Self {
    match self {
      Self::Sign => Self::Verify,
      Self::Verify => Self::Sign,
      Self::Encrypt => Self::Decrypt,
      Self::Decrypt => Self::Encrypt,
      Self::WrapKey => Self::UnwrapKey,
      Self::UnwrapKey => Self::WrapKey,
      Self::DeriveKey => Self::DeriveKey,
      Self::DeriveBits => Self::DeriveBits,
      Self::ProofGeneration => Self::ProofVerification,
      Self::ProofVerification => Self::ProofGeneration,
    }
  }
}

impl Display for JwkOperation {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}
