// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::hash::Hash;
use std::ops::Deref;
use std::str::FromStr;

use crate::chain_id::chain_id_parser;
use crate::parser::*;
use crate::ChainId;

const ACCOUNT_ADDRESS_MAX_LEN: usize = 128;

/// A chain-agnostic account ID, as defined in [CAIP-10](https://chainagnostic.org/CAIPs/caip-10).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId {
  pub chain_id: ChainId,
  pub address: AccountAddress,
}

impl Display for AccountId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", self.chain_id, self.address)
  }
}

impl AccountId {
  /// Returns a new [AccountId] with the given [ChainId] and [AccountAddress].
  pub const fn new(chain_id: ChainId, address: AccountAddress) -> Self {
    Self { chain_id, address }
  }

  /// Parses an [AccountId] from the given input string.
  pub fn parse(input: &str) -> Result<Self, AccountIdParsingError> {
    all_consuming(account_id_parser)
      .process(input.as_ref())
      .map(|(_, id)| id)
      .map_err(|e| AccountIdParsingError { source: e.into_owned() })
  }
}

impl FromStr for AccountId {
  type Err = AccountIdParsingError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    AccountId::parse(s)
  }
}

/// Error that may accure when parsing an [AccountId] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccountIdParsingError {
  source: ParseError<'static>,
}

fn account_id_parser(input: &str) -> ParserResult<'_, AccountId> {
  separated_pair(chain_id_parser, char(':'), account_address_parser)
    .map(|(chain_id, address)| AccountId::new(chain_id, address))
    .process(input)
}

fn account_address_parser(input: &str) -> ParserResult<'_, AccountAddress> {
  let valid_chars = take_while_min_max(1, ACCOUNT_ADDRESS_MAX_LEN, |c| {
    c == '.' || c == '-' || c.is_ascii_alphanumeric()
  });

  let (_, output) = recognize(many1(any((valid_chars, recognize(perc_encoded_parser))))).process(input)?;
  let consumed = output.len().min(ACCOUNT_ADDRESS_MAX_LEN);
  let (output, rem) = input.split_at(consumed);

  Ok((rem, AccountAddress::new_unchecked(output)))
}

/// A valid Account ID address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountAddress(Box<str>);

impl AccountAddress {
  pub(crate) fn new_unchecked(s: impl Into<Box<str>>) -> Self {
    Self(s.into())
  }

  /// Attempts to parse a valid [AccountAddress] from the given string.
  pub fn parse<'i>(input: impl Into<Cow<'i, str>>) -> Result<Self, InvalidAccountAddress> {
    let input = input.into();
    all_consuming(account_address_parser)
      .process(input.as_ref())
      .map_err(|e| InvalidAccountAddress { source: e.into_owned() })?;

    Ok(Self(input.into()))
  }

  /// Returns the string representation for this [AccountAddress].
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl Display for AccountAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self)
  }
}

impl Deref for AccountAddress {
  type Target = str;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

/// Error that may occur when parsing an [AccountAddress] from a given string.
#[derive(Debug)]
pub struct InvalidAccountAddress {
  source: ParseError<'static>,
}

impl Display for InvalidAccountAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("invalid account address")
  }
}

impl std::error::Error for InvalidAccountAddress {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

#[cfg(feature = "serde")]
mod serde_impl {
  use super::*;
  use serde::de::Error as _;
  use serde::Deserialize;
  use serde::Serialize;

  impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(&self.to_string())
    }
  }

  impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
      D: serde::Deserializer<'de>,
    {
      let s = <&str>::deserialize(deserializer)?;
      AccountId::parse(s).map_err(|e| D::Error::custom(e.source))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const VALID_ACCOUNT_IDS: &[&str] = &[
    "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
    "bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6",
    "cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0",
    "polkadot:b0a8d493285c2df73290dfb7e61f870f:5hmuyxw9xdgbpptgypokw4thfyoe3ryenebr381z9iaegmfy",
    "starknet:SN_GOERLI:0x02dd1b492765c064eac4039e3841aa5f382773b598097a40073bd8b48170ab57",
    "chainstd:8c3444cf8970a9e41a706fab93e7a6c4:6d9b0b4b9994e8a6afbd3dc3ed983cd51c755afb27cd1dc7825ef59c134a39f7",
    "hedera:mainnet:0.0.1234567890-zbhlt",
    "iota:mainnet:0x12345678901234567890123456789012345678901234",
  ];

  #[test]
  fn parsing_valid_account_ids_works() {
    assert!(VALID_ACCOUNT_IDS
      .iter()
      .map(|s| AccountId::parse(s))
      .all(|res| res.is_ok()));
  }

  #[test]
  fn parsing_account_id_with_address_over_128_chars_fails() {
    let too_long = format!("achain:anetwork:{}", std::iter::repeat_n('x', 129).collect::<String>());
    let e = AccountId::parse(&too_long).unwrap_err();
    assert_eq!(
      e.source,
      ParseError::new(
        "x",
        ParseErrorKind::UnexpectedCharacter {
          invalid: 'x',
          expected: Some(Expected::EoI)
        }
      )
    )
  }

  #[test]
  fn parsing_account_id_with_empty_address_fails() {
    let e = AccountId::parse("hedera:mainnet:").unwrap_err();
    assert_eq!(e.source, ParseError::new("", ParseErrorKind::EoI));
  }
}
