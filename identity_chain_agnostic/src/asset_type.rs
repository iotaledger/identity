// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::hash::Hash;
use std::ops::Deref;
use std::str::FromStr;

use crate::chain_id::chain_id_parser;
use crate::chain_id::ChainId;
use crate::parser::*;

const REFERENCE_MAX_LEN: usize = 128;
const TOKEN_ID_MAX_LEN: usize = 78;
const NAMESPACE_MIN_LEN: usize = 3;
const NAMESPACE_MAX_LEN: usize = 8;

/// An asset type, as defined in [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetType {
  pub chain_id: ChainId,
  pub asset_id: AssetId,
}

impl AssetType {
  /// Attempts to parse an [AssetType] from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetType, AssetTypeParsingError};
  /// #
  /// # fn main() -> Result<(), AssetTypeParsingError> {
  /// let asset_type = AssetType::parse("eip155:1/slip44:60")?;
  /// assert_eq!(asset_type.to_string().as_str(), "eip155:1/slip44:60");
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, AssetTypeParsingError> {
    all_consuming(asset_type_parser)
      .process(input.as_ref())
      .map(|(_, output)| output)
      .map_err(|e| AssetTypeParsingError {
        source: e.into_owned().into(),
      })
  }
}

impl Display for AssetType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}/{}", self.chain_id, self.asset_id)
  }
}

impl FromStr for AssetType {
  type Err = AssetTypeParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    AssetType::parse(s)
  }
}

fn asset_type_parser(input: &str) -> ParserResult<'_, AssetType> {
  separated_pair(chain_id_parser, char('/'), asset_id_parser)
    .map(|(chain_id, asset_id)| AssetType { chain_id, asset_id })
    .process(input)
}

#[derive(Debug)]
#[non_exhaustive]
pub struct AssetTypeParsingError {
  source: Box<dyn std::error::Error + Send + Sync>,
}

impl Display for AssetTypeParsingError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("failed to parse asset type")
  }
}

impl std::error::Error for AssetTypeParsingError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(self.source.as_ref())
  }
}

/// An asset ID, as defined in [CAIP-19](https://chainagnostic.org/CAIPs/caip-19#specification-of-asset-id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId {
  pub namespace: Namespace,
  pub reference: Reference,
  pub token_id: Option<TokenId>,
}

impl AssetId {
  /// Attempts to parse an [AssetId] from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id.to_string().as_str(), "slip44:714");
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, AssetIdParsingError> {
    all_consuming(asset_id_parser)
      .process(input.as_ref())
      .map(|(_, output)| output)
      .map_err(|e| AssetIdParsingError { source: e.into_owned() })
  }
}

impl Display for AssetId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", self.namespace, self.reference)?;
    if let Some(token_id) = &self.token_id {
      write!(f, "/{token_id}")?;
    }

    Ok(())
  }
}

impl FromStr for AssetId {
  type Err = AssetIdParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    AssetId::parse(s)
  }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AssetIdParsingError {
  source: ParseError<'static>,
}

impl Display for AssetIdParsingError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("failed to parse asset ID")
  }
}

impl std::error::Error for AssetIdParsingError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn asset_id_parser(input: &str) -> ParserResult<'_, AssetId> {
  let (rem, (namespace, reference)) = separated_pair(namespace_parser, char(':'), reference_parser)(input)?;
  let (rem, token_id) = opt(preceded(char('/'), token_id_parser))(rem)?;

  let asset_id = AssetId {
    namespace,
    reference,
    token_id,
  };

  Ok((rem, asset_id))
}

fn namespace_parser(input: &str) -> ParserResult<'_, Namespace> {
  let is_valid_char = |c: char| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit();
  take_while_min_max(NAMESPACE_MIN_LEN, NAMESPACE_MAX_LEN, is_valid_char)
    .map(Namespace::new_unchecked)
    .process(input)
}

/// A valid asset namespace.
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
  /// # use identity_chain_agnostic::asset_type::InvalidNamespace;
  /// # use identity_chain_agnostic::asset_type::Namespace;
  /// # fn main() -> Result<(), InvalidNamespace> {
  /// assert!(Namespace::parse("object").is_ok());
  /// assert!(Namespace::parse("n0t4n4m3sp4c3!").is_err());
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
    f.write_str("invalid asset namespace")
  }
}

impl std::error::Error for InvalidNamespace {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

/// A valid asset reference.
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

  /// Attempts to parse a valid asset reference from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::InvalidReference;
  /// # use identity_chain_agnostic::asset_type::Reference;
  /// # fn main() -> Result<(), InvalidReference> {
  /// assert!(
  ///   Reference::parse("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd").is_ok()
  /// );
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
    f.write_str("invalid asset ID reference")
  }
}

impl std::error::Error for InvalidReference {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn reference_and_token_parser(input: &str, max: usize) -> ParserResult<'_, &str> {
  let valid_char_parser = take_while_min_max(1, max, |c: char| c == '.' || c == '-' || c.is_ascii_alphanumeric());
  let (_, output) = recognize(many1(any((valid_char_parser, recognize(perc_encoded_parser))))).process(input)?;

  let consumed = output.len().min(max);
  let (output, rem) = input.split_at(consumed);

  Ok((rem, output))
}

fn reference_parser(input: &str) -> ParserResult<'_, Reference> {
  reference_and_token_parser(input, REFERENCE_MAX_LEN).map(|(rem, output)| (rem, Reference::new_unchecked(output)))
}

/// A valid token ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TokenId(Box<str>);

impl Deref for TokenId {
  type Target = str;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl Display for TokenId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl FromStr for TokenId {
  type Err = InvalidTokenId;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    TokenId::parse(s)
  }
}

impl TokenId {
  pub(crate) fn new_unchecked(s: impl Into<Box<str>>) -> Self {
    Self(s.into())
  }

  /// Attempts to parse a valid asset reference from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::InvalidTokenId;
  /// # use identity_chain_agnostic::asset_type::TokenId;
  /// # fn main() -> Result<(), InvalidTokenId> {
  /// assert!(TokenId::parse("42").is_ok());
  /// assert!(TokenId::parse("1nv4l!d").is_err());
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse<'i>(s: impl Into<Cow<'i, str>>) -> Result<Self, InvalidTokenId> {
    let s = s.into();
    all_consuming(token_id_parser)
      .process(&s)
      .map_err(|e| InvalidTokenId { source: e.into_owned() })?;

    Ok(Self(s.into()))
  }

  /// Return this reference's string representation.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

#[derive(Debug)]
pub struct InvalidTokenId {
  source: ParseError<'static>,
}

impl Display for InvalidTokenId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("invalid asset ID reference")
  }
}

impl std::error::Error for InvalidTokenId {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn token_id_parser(input: &str) -> ParserResult<'_, TokenId> {
  reference_and_token_parser(input, TOKEN_ID_MAX_LEN).map(|(rem, output)| (rem, TokenId::new_unchecked(output)))
}

#[cfg(feature = "serde")]
mod serde_impl {
  use super::*;

  use serde::de::Error as _;
  use serde::Deserialize;
  use serde::Serialize;

  impl Serialize for AssetType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(self.to_string().as_ref())
    }
  }

  impl<'de> Deserialize<'de> for AssetType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
      D: serde::Deserializer<'de>,
    {
      let s = <&str>::deserialize(deserializer)?;
      AssetType::parse(s).map_err(|e| D::Error::custom(e.source))
    }
  }

  impl Serialize for AssetId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(self.to_string().as_str())
    }
  }

  impl<'de> Deserialize<'de> for AssetId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
      D: serde::Deserializer<'de>,
    {
      let s = <&str>::deserialize(deserializer)?;
      AssetId::parse(s).map_err(|e| D::Error::custom(e.source))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const VALID_ASSET_TYPES: &[&str] = &[
    "eip155:1/slip44:60",
    "bip122:000000000019d6689c085ae165831e93/slip44:0",
    "hedera:mainnet/nft:0.0.55492/12",
    "iota:mainnet/object:0x1a2b3c4d5e6f8a9b",
    "eip155:1/erc20:0x6b175474e89094c44da98b954eedeac495271d0f",
    "cosmos:Binance-Chain-Tigris/slip44:714",
  ];

  #[test]
  fn parsing_valid_asset_types_works() {
    for expected in VALID_ASSET_TYPES {
      let parsed = AssetType::parse(expected).unwrap();
      assert_eq!(parsed.to_string().as_str(), *expected);
    }
  }

  #[test]
  fn parsing_asset_id_too_long_fails() {
    let reference: String = std::iter::repeat_n('a', 129).collect();
    let e = AssetId::parse(&format!("object:{reference}")).unwrap_err();
    assert_eq!(
      e.source,
      ParseError::new(
        "a",
        ParseErrorKind::UnexpectedCharacter {
          invalid: 'a',
          expected: Some(Expected::EoI)
        }
      )
    );
  }
}
