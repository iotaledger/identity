// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::hash::Hash;
use std::ops::Deref;
use std::str::FromStr;

use crate::parser::*;

/// An owned chain identifier, as defined in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2#specification).
#[derive(Debug, Clone, Eq)]
pub struct ChainIdBuf {
  data: Box<str>,
  #[allow(unused)]
  separator: usize,
}

impl ChainIdBuf {
  /// Creates a new [ChainIdBuf] from a valid [Namespace] and [Reference].
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::chain_id::ChainIdBuf;
  /// # use std::str::FromStr;
  /// #
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let chain_id = ChainIdBuf::new("iota".parse()?, "mainnet".parse()?);
  /// assert_eq!(chain_id.as_str(), "iota:mainnet");
  /// # Ok(())
  /// # }
  /// ```
  pub fn new(namespace: Namespace<'_>, reference: Reference<'_>) -> Self {
    Self {
      data: format!("{namespace}:{reference}").into_boxed_str(),
      separator: namespace.len(),
    }
  }

  /// Sets the value for this chain ID namespace.
  #[inline(always)]
  pub fn set_namespace(&mut self, namespace: Namespace<'_>) {
    self.data = format!("{namespace}:{}", self.reference()).into_boxed_str();
  }

  /// Attempts to set this chain ID namespace with the given string.
  /// # Errors
  /// - Returns an [InvalidNamespace] error if the given string is not a valid chain ID namespace.
  pub fn try_set_namespace(&mut self, namespace: impl AsRef<str>) -> Result<(), InvalidNamespace> {
    let namespace = Namespace::parse(namespace.as_ref())?;
    self.set_namespace(namespace);

    Ok(())
  }

  /// Sets the value for this chain ID reference.
  #[inline(always)]
  pub fn set_reference(&mut self, reference: Reference<'_>) {
    self.data = format!("{}:{reference}", self.namespace()).into_boxed_str();
  }

  /// Attempts to set this chain ID reference with the given string.
  /// # Errors
  /// - Returns an [InvalidReference] error if the given string is not a valid chain ID reference.
  pub fn try_set_reference(&mut self, reference: impl AsRef<str>) -> Result<(), InvalidReference> {
    let reference = Reference::parse(reference.as_ref())?;
    self.set_reference(reference);

    Ok(())
  }

  /// Returns a reference to a borrowed chain ID type.
  #[inline(always)]
  pub const fn as_chain_id(&self) -> &ChainId<'_> {
    self.as_static_chain_id()
  }

  #[inline(always)]
  const fn as_static_chain_id(&self) -> &ChainId<'static> {
    // Safety: ChainIdBuf and ChainIdBorrow have the same repr.
    unsafe { &*(self as *const ChainIdBuf as *const ChainId) }
  }
}

impl Display for ChainIdBuf {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.data)
  }
}

impl PartialEq for ChainIdBuf {
  fn eq(&self, other: &Self) -> bool {
    self.as_str() == other.as_str()
  }
}

impl Hash for ChainIdBuf {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.data.hash(state)
  }
}

impl PartialOrd for ChainIdBuf {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for ChainIdBuf {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.partial_cmp(other).unwrap()
  }
}

impl Deref for ChainIdBuf {
  type Target = ChainId<'static>;
  fn deref(&self) -> &Self::Target {
    self.as_static_chain_id()
  }
}

impl AsRef<ChainId<'static>> for ChainIdBuf {
  fn as_ref(&self) -> &ChainId<'static> {
    self.as_static_chain_id()
  }
}

/// A chain ID, as defined in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2#specification).
#[derive(Debug, Eq)]
pub struct ChainId<'i> {
  data: &'i str,
  pub(crate) separator: usize,
}

impl<'i> Display for ChainId<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.data)
  }
}

impl<'i> PartialEq for ChainId<'i> {
  fn eq(&self, other: &Self) -> bool {
    self.as_str() == other.as_str()
  }
}

impl<'i> Hash for ChainId<'i> {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.data.hash(state)
  }
}

impl<'i> PartialOrd for ChainId<'i> {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl<'i> Ord for ChainId<'i> {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.partial_cmp(other).unwrap()
  }
}

impl<'i> ChainId<'i> {
  #[inline(always)]
  pub(crate) const fn new(data: &'i str, separator: usize) -> Self {
    Self { data, separator }
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
  pub fn parse(s: &'i str) -> Result<Self, ChainIdParsingError> {
    all_consuming(chain_id_parser)
      .process(s)
      .map(|(_, output)| output)
      .map_err(|e| ChainIdParsingError {
        input: s.to_owned(),
        source: e.into_owned(),
      })
  }
  /// This chain ID's namespace.
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
  pub fn namespace(&self) -> Namespace<'_> {
    Namespace::new_unchecked(&self.data[..self.separator])
  }

  /// This chain ID's reference.
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
  pub fn reference(&self) -> Reference<'_> {
    Reference::new_unchecked(&self.data[self.separator + 1..])
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
    self.data
  }

  /// Returns an owned version of this chain ID.
  #[inline(always)]
  pub fn to_owned(&self) -> ChainIdBuf {
    ChainIdBuf {
      data: self.data.into(),
      separator: self.separator,
    }
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

impl FromStr for ChainIdBuf {
  type Err = ChainIdParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(ChainId::parse(s)?.to_owned())
  }
}

impl<'i> TryFrom<&'i str> for ChainId<'i> {
  type Error = ChainIdParsingError;
  fn try_from(value: &'i str) -> Result<Self, Self::Error> {
    Self::parse(value)
  }
}

impl TryFrom<String> for ChainIdBuf {
  type Error = ChainIdParsingError;
  fn try_from(value: String) -> Result<Self, Self::Error> {
    let separator = ChainId::parse(value.as_str())?.separator;
    Ok(Self {
      data: value.into_boxed_str(),
      separator,
    })
  }
}

pub(crate) fn chain_id_parser(input: &str) -> ParserResult<'_, ChainId<'_>> {
  let (rem, (namespace, _reference)) = separated_pair(namespace_parser, char(':'), reference_parser)(input)?;
  let consumed = input.len() - rem.len();

  let chain_id = ChainId {
    data: &input[..consumed],
    separator: namespace.len(),
  };

  Ok((rem, chain_id))
}

/// A valid chain ID's namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Namespace<'i>(Cow<'i, str>);

impl<'i> Deref for Namespace<'i> {
  type Target = str;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl<'i> Display for Namespace<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl<'i> Namespace<'i> {
  #[inline(always)]
  pub(crate) const fn new_unchecked(s: &'i str) -> Self {
    Self(Cow::Borrowed(s))
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
  pub fn parse(s: impl Into<Cow<'i, str>>) -> Result<Self, InvalidNamespace> {
    let s = s.into();
    all_consuming(namespace_parser)
      .process(&s)
      .map_err(|e| InvalidNamespace { source: e.into_owned() })?;

    Ok(Self(s))
  }

  /// Returns this namespace string representation.
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl<'i> FromStr for Namespace<'i> {
  type Err = InvalidNamespace;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Namespace::parse(s)?;
    Ok(Self(Cow::Owned(s.to_owned())))
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
pub struct Reference<'i>(Cow<'i, str>);

impl<'i> Deref for Reference<'i> {
  type Target = str;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl<'i> Display for Reference<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl<'i> FromStr for Reference<'i> {
  type Err = InvalidReference;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Reference::parse(s)?;
    Ok(Self(Cow::Owned(s.to_owned())))
  }
}

impl<'i> Reference<'i> {
  #[inline(always)]
  pub(crate) const fn new_unchecked(s: &'i str) -> Self {
    Self(Cow::Borrowed(s))
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
  pub fn parse(s: impl Into<Cow<'i, str>>) -> Result<Self, InvalidReference> {
    let s = s.into();
    all_consuming(reference_parser)
      .process(&s)
      .map_err(|e| InvalidReference { source: e.into_owned() })?;

    Ok(Self(s))
  }

  /// Return this reference's string representation.
  #[inline(always)]
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

fn namespace_parser(input: &str) -> ParserResult<'_, &str> {
  let valid_chars = |c: char| !c.is_ascii_uppercase() && c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit();
  take_while_min_max(3, 8, valid_chars)(input)
}

fn reference_parser(input: &str) -> ParserResult<'_, &str> {
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
