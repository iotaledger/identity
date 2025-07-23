// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the types described in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2).

use std::fmt::Display;
use std::ops::Range;
use std::str::FromStr;

/// Valid namespace lengths. \[3, 8\].
const NAMESPACE_SIZE: Range<usize> = 3..9;
/// Valid reference lengths. \[1, 32\].
const REFERENCE_SIZE: Range<usize> = 1..33;

/// A chain ID's namespace, as defined in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2#specification).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Namespace(Box<str>);

impl AsRef<str> for Namespace {
  fn as_ref(&self) -> &str {
    &self.0
  }
}

impl Display for Namespace {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_ref())
  }
}

impl Namespace {
  /// Attempts to parse a valid [Namespace] from the given string.
  /// # Example
  /// ```
  /// # use std::str::FromStr as _;
  ///
  /// # use identity_chain_agnostic::chain_id::{Namespace, NamespaceParsingError, ParsingErrorKind};
  /// # fn main() -> Result<(), NamespaceParsingError> {
  /// let namespace = Namespace::parse("eip155")?;
  /// assert_eq!(namespace.as_str(), "eip155");
  ///
  /// let parsing_error = Namespace::parse("inval!d").unwrap_err();
  /// assert!(matches!(parsing_error.kind, ParsingErrorKind::InvalidCharacter { c: '!', pos: 5 }));
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn parse(s: impl AsRef<str>) -> Result<Self, NamespaceParsingError> {
    s.as_ref().parse()
  }

  /// Returns the string representation for this [Namespace].
  /// # Example
  /// ```
  /// # use std::str::FromStr as _;
  /// #
  /// # use identity_chain_agnostic::chain_id::{ChainId, Namespace, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id: ChainId = "eip155:1".parse()?;
  /// let namespace: &Namespace = chain_id.namespace();
  /// assert_eq!(namespace.as_str(), "eip155");
  /// #   Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    self.as_ref()
  }
}

/// Error type that might occur when parsing a [Namespace].
#[derive(Debug, thiserror::Error)]
#[error("\"{input}\" is not a valid chain ID namespace")]
#[non_exhaustive]
pub struct NamespaceParsingError {
  /// The input string that was being parsed.
  pub input: String,
  /// The type of failure.
  #[source]
  pub kind: ParsingErrorKind,
}

impl FromStr for Namespace {
  type Err = NamespaceParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let len = s.len();
    if len < 3 || len > 8 {
      return Err(NamespaceParsingError {
        input: s.to_owned(),
        kind: ParsingErrorKind::InvalidSize {
          got: len,
          expected: NAMESPACE_SIZE,
        },
      });
    }

    let is_valid_char = |c: char| c == '-' || c.is_ascii_lowercase() || c.is_digit(10);

    for (i, c) in s.char_indices() {
      if !is_valid_char(c) {
        return Err(NamespaceParsingError {
          input: s.to_owned(),
          kind: ParsingErrorKind::InvalidCharacter { c, pos: i },
        });
      }
    }

    Ok(Namespace(s.into()))
  }
}

/// A chain ID's reference, as defined in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2#specification).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference(Box<str>);

impl AsRef<str> for Reference {
  fn as_ref(&self) -> &str {
    &self.0
  }
}

impl Display for Reference {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_ref())
  }
}

impl Reference {
  /// Attempts to parse a valid [Reference] from the given string.
  /// # Example
  /// ```
  /// # use std::str::FromStr as _;
  ///
  /// # use identity_chain_agnostic::chain_id::{Reference, ReferenceParsingError, ParsingErrorKind};
  /// # fn main() -> Result<(), ReferenceParsingError> {
  /// let reference = Reference::parse("Binance-Chain-Tigris")?;
  /// assert_eq!(reference.as_str(), "Binance-Chain-Tigris");
  ///
  /// let parsing_error = Reference::parse("inval!d").unwrap_err();
  /// assert!(matches!(parsing_error.kind, ParsingErrorKind::InvalidCharacter { c: '!', pos: 5 }));
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn parse(s: impl AsRef<str>) -> Result<Self, ReferenceParsingError> {
    s.as_ref().parse()
  }

  /// Returns the string representation for this [Reference].
  /// # Example
  /// ```
  /// # use std::str::FromStr as _;
  /// #
  /// # use identity_chain_agnostic::chain_id::{ChainId, Reference, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id: ChainId = "eip155:1".parse()?;
  /// let reference: &Reference = chain_id.reference();
  /// assert_eq!(reference.as_str(), "1");
  /// #   Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    self.as_ref()
  }
}

/// Error that might occur when attempting to parse a [Reference] from a string.
#[derive(Debug, thiserror::Error)]
#[error("\"{input}\" is not a valid chain ID reference")]
#[non_exhaustive]
pub struct ReferenceParsingError {
  /// The string that was being parsed.
  pub input: String,
  /// The type of failure.
  #[source]
  pub kind: ParsingErrorKind,
}

impl FromStr for Reference {
  type Err = ReferenceParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let len = s.len();
    if len < 1 || len > 32 {
      return Err(ReferenceParsingError {
        input: s.to_owned(),
        kind: ParsingErrorKind::InvalidSize {
          got: len,
          expected: REFERENCE_SIZE,
        },
      });
    }

    let is_valid_char = |c: char| c == '-' || c == '_' || c.is_ascii_alphabetic() || c.is_digit(10);

    for (i, c) in s.char_indices() {
      if !is_valid_char(c) {
        return Err(ReferenceParsingError {
          input: s.to_owned(),
          kind: ParsingErrorKind::InvalidCharacter { c, pos: i },
        });
      }
    }

    Ok(Reference(s.into()))
  }
}

/// A chain ID, as defined in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2#specification).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId {
  namespace: Namespace,
  reference: Reference,
}

impl Display for ChainId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", self.namespace, self.reference)
  }
}

impl ChainId {
  /// Attempts to parse a [ChainId] from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::{ChainId, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id = ChainId::parse("eip155:1")?;
  /// assert_eq!(chain_id.to_string().as_str(), "eip155:1");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn parse(s: impl AsRef<str>) -> Result<Self, ChainIdParsingError> {
    s.as_ref().parse()
  }
  /// This chain ID's [Namespace].
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::{ChainId, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id = ChainId::parse("eip155:1")?;
  /// assert_eq!(chain_id.namespace().as_str(), "eip155");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn namespace(&self) -> &Namespace {
    &self.namespace
  }

  /// This chain ID's [Reference].
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::{ChainId, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id = ChainId::parse("eip155:1")?;
  /// assert_eq!(chain_id.reference().as_str(), "1");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn reference(&self) -> &Reference {
    &self.reference
  }
}

/// Types of failure that might occur when parsing a string.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParsingErrorKind {
  /// Invalid string size.
  #[error("invalid size; expected value in the range [{}, {}), but got {got}", expected.start, expected.end)]
  InvalidSize { got: usize, expected: Range<usize> },
  /// An unexpected character was found.
  #[error("invalid character '{c}' at position {pos}")]
  InvalidCharacter { c: char, pos: usize },
}

/// Error that might occur when parsing a [ChainId] from a string.
#[derive(Debug, thiserror::Error)]
#[error("\"{input}\" is not a valid chain ID")]
#[non_exhaustive]
pub struct ChainIdParsingError {
  /// The string that was being parsed.
  pub input: String,
  /// The type of failure.
  #[source]
  pub kind: ChainIdParsingErrorKind,
}

/// Type of failures that might occure when parsing a [ChainId] from string.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainIdParsingErrorKind {
  /// Empty string.
  #[error("empty string")]
  Empty,
  /// Missing namespace/reference separator.
  #[error("missing ':' separator")]
  MissingSeparator,
  /// Unexpected value for [Namespace].
  #[error(transparent)]
  InvalidNamespace(#[from] NamespaceParsingError),
  /// Unexpected value for [Reference].
  #[error(transparent)]
  InvalidReference(#[from] ReferenceParsingError),
}

impl FromStr for ChainId {
  type Err = ChainIdParsingError;
  fn from_str(input: &str) -> Result<Self, Self::Err> {
    if input.is_empty() {
      return Err(ChainIdParsingError {
        input: input.to_owned(),
        kind: ChainIdParsingErrorKind::Empty,
      });
    }

    let separator_pos = input.find(':').ok_or_else(|| ChainIdParsingError {
      input: input.to_owned(),
      kind: ChainIdParsingErrorKind::MissingSeparator,
    })?;
    let (namespace, reference) = input.split_at(separator_pos);
    let namespace = namespace
      .parse()
      .map_err(|e: NamespaceParsingError| ChainIdParsingError {
        input: input.to_owned(),
        kind: e.into(),
      })?;
    let reference = reference[1..] // removes the leading ':'.
      .parse()
      .map_err(|e: ReferenceParsingError| ChainIdParsingError {
        input: input.to_owned(),
        kind: e.into(),
      })?;

    Ok(ChainId { namespace, reference })
  }
}

#[cfg(feature = "serde")]
mod serde_impl {
  use std::error::Error as _;

  use super::*;

  use serde::Deserialize;
  use serde::Serialize;

  macro_rules! impl_serde {
    ($t:ty) => {
      impl Serialize for $t {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
          S: serde::Serializer,
        {
          serializer.serialize_str(&self.to_string())
        }
      }

      impl<'de> Deserialize<'de> for $t {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
          D: serde::Deserializer<'de>,
        {
          let s = <&str as Deserialize>::deserialize(deserializer)?;
          <$t>::parse(s).map_err(|e| {
            let mut err_msg = e.to_string();
            while let Some(source) = e.source() {
              err_msg = format!("{err_msg}: {source}");
            }

            <D::Error as serde::de::Error>::custom(err_msg)
          })
        }
      }
    };
  }

  impl_serde!(Namespace);
  impl_serde!(Reference);
  impl_serde!(ChainId);
}

#[cfg(test)]
mod tests {
  use super::*;

  const VALID_CHAIN_IDS: &[&str] = &[
    "eip155:1",
    "bip122:000000000019d6689c085ae165831e93",
    "cosmos:cosmoshub-3",
    "cosmos:Binance-Chain-Tigris",
    "starknet:SN_GOERLI",
    "chainstd:8c3444cf8970a9e41a706fab93e7a6c4",
    "iota:mainnet",
  ];

  #[test]
  fn parsing_valid_namespaces_works() {
    let ok = VALID_CHAIN_IDS
      .iter()
      .map(|chain_id| chain_id.split_once(':').unwrap().0)
      .map(Namespace::from_str)
      .all(|res| res.is_ok());
    assert!(ok);
  }

  #[test]
  fn parsing_valid_references_works() {
    let ok = VALID_CHAIN_IDS
      .iter()
      .map(|chain_id| chain_id.split_once(':').unwrap().1)
      .map(Reference::from_str)
      .all(|res| res.is_ok());
    assert!(ok);
  }

  #[test]
  fn parsing_valid_chain_ids_works() {
    let ok = VALID_CHAIN_IDS
      .iter()
      .map(|s| ChainId::from_str(s))
      .all(|res| res.is_ok());
    assert!(ok);
  }

  #[test]
  fn chain_id_to_string_works() {
    for (chain_id, expected) in VALID_CHAIN_IDS.iter().map(|s| (ChainId::from_str(s).unwrap(), *s)) {
      assert_eq!(chain_id.to_string(), expected);
    }
  }

  #[test]
  fn parsing_chain_id_from_empty_string_returns_empty() {
    let e = "".parse::<ChainId>().unwrap_err();
    assert!(matches!(e.kind, ChainIdParsingErrorKind::Empty));
  }

  #[test]
  fn parsing_invalid_namespaces_works() {
    let e = "".parse::<Namespace>().unwrap_err();
    assert!(matches!(
      e.kind,
      ParsingErrorKind::InvalidSize {
        got: 0,
        expected: NAMESPACE_SIZE
      }
    ));

    let e = "a2".parse::<Namespace>().unwrap_err();
    assert!(matches!(
      e.kind,
      ParsingErrorKind::InvalidSize {
        got: 2,
        expected: NAMESPACE_SIZE
      }
    ));

    let e = "too-loong".parse::<Namespace>().unwrap_err();
    assert!(matches!(
      e.kind,
      ParsingErrorKind::InvalidSize {
        got: 9,
        expected: NAMESPACE_SIZE
      }
    ));

    let e = "inval!d".parse::<Namespace>().unwrap_err();
    assert!(matches!(e.kind, ParsingErrorKind::InvalidCharacter { c: '!', pos: 5 }));
  }

  #[test]
  fn parsing_invalid_references_works() {
    let e = "".parse::<Reference>().unwrap_err();
    assert!(matches!(
      e.kind,
      ParsingErrorKind::InvalidSize {
        got: 0,
        expected: REFERENCE_SIZE,
      }
    ));

    let too_long = std::iter::repeat('x').take(33).collect::<String>();
    let e = too_long.parse::<Reference>().unwrap_err();
    assert!(matches!(
      e.kind,
      ParsingErrorKind::InvalidSize {
        got: 33,
        expected: REFERENCE_SIZE
      },
    ));

    let e = "inval!d".parse::<Reference>().unwrap_err();
    assert!(matches!(e.kind, ParsingErrorKind::InvalidCharacter { c: '!', pos: 5 }));
  }

  #[test]
  fn parsing_invalid_chain_ids_works() {
    let e = "valid::valid".parse::<ChainId>().unwrap_err();
    assert!(matches!(
      e.kind,
      ChainIdParsingErrorKind::InvalidReference(ReferenceParsingError {
        kind: ParsingErrorKind::InvalidCharacter { c: ':', pos: 0 },
        ..
      })
    ))
  }

  #[test]
  fn namespace_serde_works() {
    let expected = Namespace::parse("eip155").unwrap();
    let deserialized: Namespace = serde_json::from_str("\"eip155\"").unwrap();
    assert_eq!(deserialized, expected);
    let serialized = serde_json::to_string(&expected).unwrap();
    assert_eq!(serialized.as_str(), "\"eip155\"");
  }

  #[test]
  fn reference_serde_works() {
    let expected = Reference::parse("testnet").unwrap();
    let deserialized: Reference = serde_json::from_str("\"testnet\"").unwrap();
    assert_eq!(deserialized, expected);
    let serialized = serde_json::to_string(&expected).unwrap();
    assert_eq!(serialized.as_str(), "\"testnet\"");
  }

  #[test]
  fn chain_id_serde_works() {
    let expected = ChainId::parse("eip155:1").unwrap();
    let deserialized: ChainId = serde_json::from_str("\"eip155:1\"").unwrap();
    assert_eq!(deserialized, expected);
    let serialized = serde_json::to_string(&expected).unwrap();
    assert_eq!(serialized.as_str(), "\"eip155:1\"");
  }
}
