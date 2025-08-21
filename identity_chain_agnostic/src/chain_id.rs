// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::hash::Hash;
use std::ops::Deref;
use std::str::FromStr;

use crate::parser::*;

/// A chain ID, as defined in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2#specification).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId {
  pub namespace: Namespace,
  pub reference: Reference,
}

impl Display for ChainId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", self.namespace, self.reference)
  }
}

impl ChainId {
  /// Returns a new chain ID from the given namespace and reference.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::ChainId;
  /// # use std::str::FromStr;
  /// #
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let chain_id = ChainId::new("iota".parse()?, "mainnet".parse()?);
  /// assert_eq!(chain_id.to_string().as_str(), "iota:mainnet");
  /// # Ok(())
  /// # }
  /// ```
  pub const fn new(namespace: Namespace, reference: Reference) -> Self {
    Self { namespace, reference }
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
  pub fn parse(s: &str) -> Result<Self, ChainIdParsingError> {
    all_consuming(chain_id_parser)
      .process(s)
      .map(|(_, output)| output)
      .map_err(|e| ChainIdParsingError {
        input: s.to_owned(),
        source: e.into_owned(),
      })
  }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainIdParsingError {
  pub(crate) input: String,
  pub(crate) source: ParseError<'static>,
}

impl Display for ChainIdParsingError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "invalid chain ID \"{}\"", self.input)
  }
}

impl std::error::Error for ChainIdParsingError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

impl FromStr for ChainId {
  type Err = ChainIdParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::parse(s)
  }
}

pub(crate) fn chain_id_parser(input: &str) -> ParserResult<'_, ChainId> {
  separated_pair(namespace_parser, char(':'), reference_parser)
    .map(|(namespace, reference)| ChainId::new(namespace, reference))
    .process(input)
}

/// A valid chain ID's namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Namespace(Box<str>);

impl Deref for Namespace {
  type Target = str;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl AsRef<str> for Namespace {
  fn as_ref(&self) -> &str {
    &self.0
  }
}

impl Display for Namespace {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl Namespace {
  pub(crate) fn new_unchecked(s: impl Into<Box<str>>) -> Self {
    Self(s.into())
  }

  /// Attempts to parse a valid chain ID namespace from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::InvalidNamespace;
  /// # use identity_chain_agnostic::chain_id::Namespace;
  /// # fn main() -> Result<(), InvalidNamespace> {
  /// assert!(Namespace::parse("iota").is_ok());
  /// assert!(Namespace::parse("n0t4n4m3sp4c3").is_err());
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse<'i>(s: impl Into<Cow<'i, str>>) -> Result<Self, InvalidNamespace> {
    let s = s.into();
    all_consuming(namespace_parser)
      .process(&s)
      .map_err(|e| InvalidNamespace { source: e.into_owned() })?;

    Ok(Self(s.into()))
  }

  /// Returns this namespace string representation.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl FromStr for Namespace {
  type Err = InvalidNamespace;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Namespace::parse(s)
  }
}

#[derive(Debug)]
pub struct InvalidNamespace {
  source: ParseError<'static>,
}

impl Display for InvalidNamespace {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("invalid chain ID namespace")
  }
}

impl std::error::Error for InvalidNamespace {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

/// A valid chain ID's reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Reference(Box<str>);

impl Deref for Reference {
  type Target = str;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl Display for Reference {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl FromStr for Reference {
  type Err = InvalidReference;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Reference::parse(s)
  }
}

impl Reference {
  pub(crate) fn new_unchecked(s: impl Into<Box<str>>) -> Self {
    Self(s.into())
  }

  /// Attempts to parse a valid chain ID reference from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::InvalidReference;
  /// # use identity_chain_agnostic::chain_id::Reference;
  /// # fn main() -> Result<(), InvalidReference> {
  /// assert!(Reference::parse("testnet").is_ok());
  /// assert!(Reference::parse("1nv4l!d").is_err());
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse<'i>(s: impl Into<Cow<'i, str>>) -> Result<Self, InvalidReference> {
    let s = s.into();
    all_consuming(reference_parser)
      .process(&s)
      .map_err(|e| InvalidReference { source: e.into_owned() })?;

    Ok(Self(s.into()))
  }

  /// Return this reference's string representation.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

#[derive(Debug)]
pub struct InvalidReference {
  source: ParseError<'static>,
}

impl Display for InvalidReference {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("invalid chain ID reference")
  }
}

impl std::error::Error for InvalidReference {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn namespace_parser(input: &str) -> ParserResult<'_, Namespace> {
  let valid_chars = |c: char| !c.is_ascii_uppercase() && c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit();
  take_while_min_max(3, 8, valid_chars)
    .map(Namespace::new_unchecked)
    .process(input)
}

fn reference_parser(input: &str) -> ParserResult<'_, Reference> {
  let valid_chars = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
  take_while_min_max(1, 32, valid_chars)
    .map(Reference::new_unchecked)
    .process(input)
}

#[cfg(feature = "serde")]
mod serde_impl {
  use super::*;

  use serde::de::Error as _;
  use serde::Deserialize;
  use serde::Serialize;

  impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(&self.to_string())
    }
  }

  impl<'de> Deserialize<'de> for ChainId {
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
    let ok = VALID_CHAIN_IDS.iter().map(|i| ChainId::parse(i)).all(|res| res.is_ok());
    assert!(ok);
  }

  #[test]
  fn chain_id_to_string_works() {
    for (chain_id, expected) in VALID_CHAIN_IDS.iter().map(|s| (ChainId::parse(s).unwrap(), *s)) {
      assert_eq!(chain_id.to_string(), expected);
    }
  }
}
