// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the types described in [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).

use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Range;
use std::str::FromStr;

use crate::chain_id::chain_id_parser;
use crate::chain_id::ChainId;
use crate::parser::*;

/// An asset type, as defined in [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetType<'i> {
  data: Cow<'i, str>,
  chain_id_namespace: Range<usize>,
  chain_id_reference: Range<usize>,
  asset_id_namespace: Range<usize>,
  asset_id_reference: Range<usize>,
  asset_id_token_id: Option<Range<usize>>,
}

impl<'i> AssetType<'i> {
  /// Attempts to parse an [AssetType] from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_id::{AssetType, AssetTypeParsingError};
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
  /// # use identity_chain_agnostic::asset_id::{AssetType, AssetTypeParsingError};
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
  /// # use identity_chain_agnostic::asset_id::{AssetType, AssetTypeParsingError};
  /// #
  /// # fn main() -> Result<(), AssetTypeParsingError> {
  /// let asset_type = AssetType::parse("eip155:1/slip44:60")?;
  /// assert_eq!(asset_type.chain_id().as_str(), "eip155:1");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn chain_id(&self) -> ChainId {
    let data = &self.data[..self.chain_id_reference.end];
    ChainId::new(data, self.chain_id_namespace.clone(), self.chain_id_reference.clone())
  }

  /// Returns a reference to the [asset ID](AssetId) part of this [asset type](AssetType).
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_id::{AssetType, AssetTypeParsingError};
  /// #
  /// # fn main() -> Result<(), AssetTypeParsingError> {
  /// let asset_type = AssetType::parse("eip155:1/slip44:60")?;
  /// assert_eq!(asset_type.asset_id().as_str(), "slip44:60");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn asset_id(&self) -> AssetId {
    let data = &self.data[self.chain_id_reference.end + 1..];
    AssetId {
      data: data.into(),
      namespace: self.asset_id_namespace.clone(),
      reference: self.asset_id_reference.clone(),
      token_id: self.asset_id_token_id.clone(),
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

fn asset_type_parser(input: &str) -> ParserResult<AssetType> {
  let (rem, chain_id) = chain_id_parser(input)?;
  let (rem, _slash) = char('/')(rem)?;
  let (rem, asset_id) = asset_id_parser(rem)?;

  let consumed = input.len() - rem.len();
  let asset_type = AssetType {
    data: Cow::Borrowed(&input[..consumed]),
    chain_id_namespace: chain_id.namespace,
    chain_id_reference: chain_id.reference,
    asset_id_namespace: asset_id.namespace,
    asset_id_reference: asset_id.reference,
    asset_id_token_id: asset_id.token_id,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetId<'i> {
  data: Cow<'i, str>,
  namespace: Range<usize>,
  reference: Range<usize>,
  token_id: Option<Range<usize>>,
}

impl<'i> AssetId<'i> {
  /// Attempts to parse an [AssetId] from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_id::{AssetId, AssetIdParsingError};
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
  /// # use identity_chain_agnostic::asset_id::{AssetId, AssetIdParsingError};
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
  /// # use identity_chain_agnostic::asset_id::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id.namespace(), "slip44");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn namespace(&self) -> &str {
    &self.data[self.namespace.clone()]
  }

  /// This asset ID's reference.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_id::{AssetId, AssetIdParsingError};
  /// #
  /// # fn main() -> Result<(), AssetIdParsingError> {
  /// let asset_id = AssetId::parse("slip44:714")?;
  /// assert_eq!(asset_id.reference(), "714");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn reference(&self) -> &str {
    &self.data[self.reference.clone()]
  }

  /// This asset ID's token ID.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::asset_id::{AssetId, AssetIdParsingError};
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
    self.token_id.as_ref().map(|idx| &self.data[idx.clone()])
  }

  /// Clones the underlying string.
  pub fn into_owned(self) -> AssetId<'static> {
    AssetId {
      data: Cow::Owned(self.data.into_owned()),
      namespace: self.namespace,
      reference: self.reference,
      token_id: self.token_id,
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

fn asset_id_parser(input: &str) -> ParserResult<AssetId> {
  let (rem, namespace) = namespace_parser(input)?;
  let (rem, _colon) = char(':')(rem)?;
  let namespace_span = 0..namespace.len();

  let (rem, reference) = reference_parser(rem)?;
  let reference_span = {
    let offset = namespace_span.end + 1;
    offset..offset + reference.len()
  };

  let mut remaining_input = rem;
  let token_id = if let Ok((rem, _slash)) = char('/')(rem) {
    let (rem_after_token, token_id) = token_id_parser(rem)?;
    let offset = reference_span.end + 1;
    remaining_input = rem_after_token;

    Some(offset..offset + token_id.len())
  } else {
    None
  };
  let consumed = token_id.as_ref().map(|range| range.end).unwrap_or(reference_span.end);
  let asset_id = AssetId {
    data: Cow::Borrowed(&input[..consumed]),
    namespace: namespace_span,
    reference: reference_span,
    token_id,
  };

  Ok((remaining_input, asset_id))
}

fn namespace_parser(input: &str) -> ParserResult<&str> {
  let is_valid_char = |c: char| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit();
  take_while_min_max(3, 8, is_valid_char)(input)
}

fn perc_encoded_parser(input: &str) -> ParserResult<u8> {
  let (rem, _perc) = char('%')(input)?;
  let (rem, hex_byte) = take_while_min_max(2, 2, |c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())(rem)?;

  let byte = u8::from_str_radix(hex_byte, 16).expect("valid hex byte");
  Ok((rem, byte))
}

fn reference_and_token_parser(input: &str) -> ParserResult<&str> {
  let valid_char_parser = take_while_min_max(1, usize::MAX, |c: char| {
    c == '.' || c == '-' || c.is_ascii_alphanumeric()
  });
  recognize(many1(any((valid_char_parser, recognize(perc_encoded_parser))))).process(input)
}

fn reference_parser(input: &str) -> ParserResult<&str> {
  let (mut rem, mut output) = reference_and_token_parser(input)?;
  if output.len() > 128 {
    let (clipped_output, clipped_rem) = output.split_at(128);
    rem = clipped_rem;
    output = clipped_output;
  }

  Ok((rem, output))
}

fn token_id_parser(input: &str) -> ParserResult<&str> {
  let (mut rem, mut output) = reference_and_token_parser(input)?;
  if output.len() > 78 {
    let (clipped_output, clipped_rem) = output.split_at(128);
    rem = clipped_rem;
    output = clipped_output;
  }

  Ok((rem, output))
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
}
