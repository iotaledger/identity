// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

/// Supported BLS Curves.
///
/// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05#name-curve-parameter-registratio)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlsCurve {
  /// A cryptographic key on the Barreto-Lynn-Scott (BLS) curve featuring an embedding degree 12 with 381-bit p in the
  /// subgroup of G1.
  BLS12381G1,
  /// A cryptographic key on the Barreto-Lynn-Scott (BLS) curve featuring an embedding degree 12 with 381-bit p in the
  /// subgroup of G2.
  BLS12381G2,
  /// A cryptographic key on the Barreto-Lynn-Scott (BLS) curve featuring an embedding degree 48 with 581-bit p in the
  /// subgroup of G1.
  BLS48581G1,
  /// A cryptographic key on the Barreto-Lynn-Scott (BLS) curve featuring an embedding degree 48 with 581-bit p in the
  /// subgroup of G2.
  BLS48581G2,
}

impl BlsCurve {
  /// Returns the name of the curve as a string slice.
  pub const fn name(self) -> &'static str {
    match self {
      Self::BLS12381G1 => "BLS12381G1",
      Self::BLS12381G2 => "BLS12381G2",
      Self::BLS48581G1 => "BLS48581G1",
      Self::BLS48581G2 => "BLS48581G2",
    }
  }
}

impl Display for BlsCurve {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}
