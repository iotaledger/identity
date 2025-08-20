// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::hash::Hash;
use std::str::FromStr;

use crate::chain_id::chain_id_parser;
use crate::chain_id::ChainId;
use crate::parser::*;

const REFERENCE_MAX_LEN: usize = 128;
const TOKEN_ID_MAX_LEN: usize = 78;
const NAMESPACE_MIN_LEN: usize = 3;
const NAMESPACE_MAX_LEN: usize = 8;

/// An asset type, as defined in [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
#[derive(Debug, Clone)]
pub struct AssetType<'i> {
  data: Cow<'i, str>,
  chain_id_separator: usize,
  separator: usize,
  asset_id_separator: usize,
  token_id_separator: Option<usize>,
}

impl<'i> AssetType<'i> {
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
  pub fn parse<I>(input: &'i I) -> Result<Self, AssetTypeParsingError>
  where
    I: AsRef<str> + ?Sized,
  {
    all_consuming(asset_type_parser)
      .process(input.as_ref())
      .map(|(_, output)| output)
      .map_err(|e| AssetTypeParsingError {
        source: e.into_owned().into(),
      })
  }

  /// Returns a string slice to the underlying string representation of this asset type.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetType, AssetTypeParsingError};
  /// #
  /// # fn main() -> Result<(), AssetTypeParsingError> {
  /// let asset_type = AssetType::parse("eip155:1/slip44:60")?;
  /// assert_eq!(asset_type.as_str(), "eip155:1/slip44:60");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    &self.data
  }

  /// Clones the internal string representation.
  pub fn into_owned(self) -> AssetType<'static> {
    AssetType {
      data: Cow::Owned(self.data.into_owned()),
      ..self
    }
  }

  /// Returns a the [chain ID](ChainId) part of this [asset type](AssetType).
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetType, AssetTypeParsingError};
  /// #
  /// # fn main() -> Result<(), AssetTypeParsingError> {
  /// let asset_type = AssetType::parse("eip155:1/slip44:60")?;
  /// assert_eq!(asset_type.chain_id().as_str(), "eip155:1");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn chain_id(&self) -> ChainId<'_> {
    let data = &self.data[..self.separator];
    ChainId::new(data, self.chain_id_separator)
  }

  /// Returns a reference to the [asset ID](AssetId) part of this [asset type](AssetType).
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetType, AssetTypeParsingError};
  /// #
  /// # fn main() -> Result<(), AssetTypeParsingError> {
  /// let asset_type = AssetType::parse("eip155:1/slip44:60")?;
  /// assert_eq!(asset_type.asset_id().as_str(), "slip44:60");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn asset_id(&self) -> AssetId<'_> {
    let data = &self.data[self.separator + 1..];
    AssetId {
      data: data.into(),
      separator: self.asset_id_separator,
      token_id: self.token_id_separator,
    }
  }
}

impl<'i> AsRef<str> for AssetType<'i> {
  fn as_ref(&self) -> &str {
    &self.data
  }
}

impl<'i> Display for AssetType<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.data)
  }
}

impl<'i> TryFrom<&'i str> for AssetType<'i> {
  type Error = AssetTypeParsingError;
  fn try_from(value: &'i str) -> Result<Self, Self::Error> {
    AssetType::parse(value)
  }
}

impl FromStr for AssetType<'static> {
  type Err = AssetTypeParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    AssetType::parse(s).map(AssetType::into_owned)
  }
}

impl<'i> PartialEq for AssetType<'i> {
  fn eq(&self, other: &Self) -> bool {
    self.as_str() == other.as_str()
  }
}

impl<'i> Eq for AssetType<'i> {}

impl<'i> Hash for AssetType<'i> {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.data.hash(state)
  }
}

impl<'i> PartialOrd for AssetType<'i> {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl<'i> Ord for AssetType<'i> {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.partial_cmp(other).unwrap()
  }
}

fn asset_type_parser(input: &str) -> ParserResult<'_, AssetType<'_>> {
  let (rem, (chain_id, asset_id)) = separated_pair(chain_id_parser, char('/'), asset_id_parser)(input)?;

  let consumed = input.len() - rem.len();
  let asset_type = AssetType {
    data: Cow::Borrowed(&input[..consumed]),
    chain_id_separator: chain_id.separator,
    separator: chain_id.as_str().len(),
    asset_id_separator: asset_id.separator,
    token_id_separator: asset_id.token_id,
  };

  Ok((rem, asset_type))
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
#[derive(Debug, Clone)]
pub struct AssetId<'i> {
  data: Cow<'i, str>,
  separator: usize,
  token_id: Option<usize>,
}

impl<'i> AssetId<'i> {
  /// Attempts to parse an [AssetId] from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id.as_str(), "slip44:714");
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse<I>(input: &'i I) -> Result<Self, AssetIdParsingError>
  where
    I: AsRef<str> + ?Sized,
  {
    all_consuming(asset_id_parser)
      .process(input.as_ref())
      .map(|(_, output)| output)
      .map_err(|e| AssetIdParsingError { source: e.into_owned() })
  }

  /// Returns a string slice to the underlying string representation of this asset ID.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id.as_str(), "slip44:714");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    &self.data
  }

  /// This asset ID's namespace.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id.namespace(), "slip44");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn namespace(&self) -> &str {
    &self.data[..self.separator]
  }

  /// This asset ID's reference.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id.reference(), "714");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn reference(&self) -> &str {
    &self.data[self.separator + 1..]
  }

  /// This asset ID's token ID.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_type::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id_no_token_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id_no_token_id.token_id(), None);
  ///
  /// let asset_id = AssetId::parse("nft:0.0.55492/12")?;
  /// assert_eq!(asset_id.token_id(), Some("12"));
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn token_id(&self) -> Option<&str> {
    self.token_id.as_ref().map(|idx| &self.data[*idx + 1..])
  }

  /// Clones the underlying string.
  pub fn into_owned(self) -> AssetId<'static> {
    AssetId {
      data: Cow::Owned(self.data.into_owned()),
      ..self
    }
  }
}

impl<'i> Display for AssetId<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.data)
  }
}

impl<'i> AsRef<str> for AssetId<'i> {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl<'i> TryFrom<&'i str> for AssetId<'i> {
  type Error = AssetIdParsingError;
  fn try_from(value: &'i str) -> Result<Self, Self::Error> {
    AssetId::parse(value)
  }
}

impl FromStr for AssetId<'static> {
  type Err = AssetIdParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    AssetId::parse(s).map(AssetId::into_owned)
  }
}

impl<'i> PartialEq for AssetId<'i> {
  fn eq(&self, other: &Self) -> bool {
    self.as_str() == other.as_str()
  }
}

impl<'i> Eq for AssetId<'i> {}

impl<'i> Hash for AssetId<'i> {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.data.hash(state)
  }
}

impl<'i> PartialOrd for AssetId<'i> {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl<'i> Ord for AssetId<'i> {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.partial_cmp(other).unwrap()
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

fn asset_id_parser(input: &str) -> ParserResult<'_, AssetId<'_>> {
  let (rem, (namespace, _reference)) = separated_pair(namespace_parser, char(':'), reference_parser)(input)?;
  let token_id_len = if let Ok((rem, _slash)) = char('/')(rem) {
    let (_, token_id) = token_id_parser(rem)?;
    Some(token_id.len())
  } else {
    None
  };

  let consumed = input.len() - rem.len() + token_id_len.map(|len| len + 1).unwrap_or_default();
  let asset_id = AssetId {
    data: Cow::Borrowed(&input[..consumed]),
    separator: namespace.len(),
    token_id: token_id_len.map(|len| consumed - len - 1),
  };

  Ok((&input[consumed..], asset_id))
}

fn namespace_parser(input: &str) -> ParserResult<'_, &str> {
  let is_valid_char = |c: char| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit();
  take_while_min_max(NAMESPACE_MIN_LEN, NAMESPACE_MAX_LEN, is_valid_char)(input)
}

fn reference_and_token_parser(input: &str, max: usize) -> ParserResult<'_, &str> {
  let valid_char_parser = take_while_min_max(1, max, |c: char| c == '.' || c == '-' || c.is_ascii_alphanumeric());
  let (_, output) = recognize(many1(any((valid_char_parser, recognize(perc_encoded_parser))))).process(input)?;

  let consumed = output.len().min(max);
  let (output, rem) = input.split_at(consumed);

  Ok((rem, output))
}

#[inline(always)]
fn reference_parser(input: &str) -> ParserResult<'_, &str> {
  reference_and_token_parser(input, REFERENCE_MAX_LEN)
}

#[inline(always)]
fn token_id_parser(input: &str) -> ParserResult<'_, &str> {
  reference_and_token_parser(input, TOKEN_ID_MAX_LEN)
}

#[cfg(feature = "serde")]
mod serde_impl {
  use super::*;

  use serde::de::Error as _;
  use serde::Deserialize;
  use serde::Serialize;

  impl<'i> Serialize for AssetType<'i> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(self.as_ref())
    }
  }

  impl<'de> Deserialize<'de> for AssetType<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
      D: serde::Deserializer<'de>,
    {
      let s = <&str>::deserialize(deserializer)?;
      AssetType::parse(s).map_err(|e| D::Error::custom(e.source))
    }
  }

  impl<'i> Serialize for AssetId<'i> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(self.as_str())
    }
  }

  impl<'de> Deserialize<'de> for AssetId<'de> {
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
