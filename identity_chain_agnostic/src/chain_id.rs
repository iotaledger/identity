// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the types described in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2).

use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

use crate::parser::*;

/// A chain ID, as defined in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2#specification).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainId<'i> {
  data: Cow<'i, str>,
  pub(crate) separator: usize,
}

impl<'i> Display for ChainId<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.data)
  }
}

impl<'i> ChainId<'i> {
  pub(crate) fn new(data: &'i str, separator: usize) -> Self {
    Self {
      data: data.into(),
      separator,
    }
  }
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
  pub fn parse<I>(s: &'i I) -> Result<Self, ChainIdParsingError>
  where
    I: AsRef<str> + ?Sized,
  {
    all_consuming(chain_id_parser)
      .process(s.as_ref())
      .map(|(_, output)| output)
      .map_err(|e| ChainIdParsingError { source: e.into_owned() })
  }
  /// This chain ID's namespace.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::{ChainId, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id = ChainId::parse("eip155:1")?;
  /// assert_eq!(chain_id.namespace(), "eip155");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn namespace(&self) -> &str {
    &self.data[..self.separator]
  }

  /// This chain ID's reference.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::{ChainId, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id = ChainId::parse("eip155:1")?;
  /// assert_eq!(chain_id.reference(), "1");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn reference(&self) -> &str {
    &self.data[self.separator + 1..]
  }

  /// Clones the internal string representation.
  pub fn into_owned(self) -> ChainId<'static> {
    ChainId {
      data: Cow::Owned(self.data.into_owned()),
      ..self
    }
  }

  /// Returns a string slice to the underlying string representation of this chain ID.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::{ChainId, ChainIdParsingError};
  /// #
  /// # fn main() -> Result<(), ChainIdParsingError> {
  /// let chain_id = ChainId::parse("eip155:1")?;
  /// assert_eq!(chain_id.as_str(), "eip155:1");
  /// # Ok(())
  /// # }
  /// ```
  pub fn as_str(&self) -> &str {
    &self.data
  }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainIdParsingError {
  source: ParseError<'static>,
}

impl Display for ChainIdParsingError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("failed to parse chain ID")
  }
}

impl std::error::Error for ChainIdParsingError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

impl FromStr for ChainId<'static> {
  type Err = ChainIdParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(ChainId::parse(&s)?.into_owned())
  }
}

impl<'i> TryFrom<&'i str> for ChainId<'i> {
  type Error = ChainIdParsingError;
  fn try_from(value: &'i str) -> Result<Self, Self::Error> {
    Self::parse(value)
  }
}

pub(crate) fn chain_id_parser(input: &str) -> ParserResult<ChainId> {
  let (rem, namespace) = namespace_parser(input)?;
  let (rem, _colon) = char(':')(rem)?;
  let (rem, _reference) = reference_parser(rem)?;
  let consumed = input.len() - rem.len();

  let chain_id = ChainId {
    data: Cow::Borrowed(&input[..consumed]),
    separator: namespace.len(),
  };

  Ok((rem, chain_id))
}

fn namespace_parser(input: &str) -> ParserResult<&str> {
  let valid_chars = |c: char| !c.is_ascii_uppercase() && c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit();
  take_while_min_max(3, 8, valid_chars)(input)
}

fn reference_parser(input: &str) -> ParserResult<&str> {
  let valid_chars = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
  take_while_min_max(1, 32, valid_chars)(input)
}

#[cfg(feature = "serde")]
mod serde_impl {
  use super::*;

  use serde::de::Error as _;
  use serde::Deserialize;
  use serde::Serialize;

  impl<'i> Serialize for ChainId<'i> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(self.as_str())
    }
  }

  impl<'de> Deserialize<'de> for ChainId<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
      D: serde::Deserializer<'de>,
    {
      let s = <&str>::deserialize(deserializer)?;
      ChainId::parse(s).map_err(|e| D::Error::custom(e.source))
    }
  }
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
  fn parsing_valid_chain_ids_works() {
    let ok = VALID_CHAIN_IDS.iter().map(ChainId::parse).all(|res| res.is_ok());
    assert!(ok);
  }

  #[test]
  fn chain_id_to_string_works() {
    for (chain_id, expected) in VALID_CHAIN_IDS.iter().map(|s| (ChainId::parse(s).unwrap(), *s)) {
      assert_eq!(chain_id.to_string(), expected);
    }
  }
}
