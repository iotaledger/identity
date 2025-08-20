// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

use crate::chain_id::chain_id_parser;
use crate::parser::*;
use crate::ChainId;

const ACCOUNT_ADDRESS_MAX_LEN: usize = 128;

/// A chain-agnostic account ID, as defined in [CAIP-10](https://chainagnostic.org/CAIPs/caip-10).
#[derive(Debug, Clone, Eq)]
pub struct AccountId<'i> {
  data: Cow<'i, str>,
  chain_id_separator: usize,
  separator: usize,
}

impl<'i> AsRef<str> for AccountId<'i> {
  fn as_ref(&self) -> &str {
    &self.data
  }
}

impl<'i> Display for AccountId<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_str())
  }
}

impl<'i> PartialEq for AccountId<'i> {
  fn eq(&self, other: &Self) -> bool {
    self.data == other.data
  }
}

impl<'i> Ord for AccountId<'i> {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.data.cmp(&other.data)
  }
}

impl<'i> PartialOrd for AccountId<'i> {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl<'i> AccountId<'i> {
  #[inline(always)]
  pub(crate) fn new(data: &'i str, chain_id_separator: usize, separator: usize) -> Self {
    Self {
      data: data.into(),
      chain_id_separator,
      separator,
    }
  }

  /// Returns a reference to the underlying string representation.
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    &self.data
  }

  /// Parses an [AccountId] from the given input string.
  pub fn parse<I>(input: &'i I) -> Result<Self, AccountIdParsingError<'i>>
  where
    I: AsRef<str> + ?Sized,
  {
    all_consuming(account_id_parser)
      .process(input.as_ref())
      .map(|(_, id)| id)
      .map_err(|e| AccountIdParsingError { source: e })
  }

  /// Takes ownership of the underlying string.
  pub fn into_owned(self) -> AccountId<'static> {
    AccountId {
      data: Cow::Owned(self.data.into_owned()),
      ..self
    }
  }

  /// Returns the [chain ID](ChainId) part of this [AccountId].
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::account_id::{AccountId, AccountIdParsingError};
  /// #
  /// # fn main() -> Result<(), AccountIdParsingError<'static>> {
  /// let account_id = AccountId::parse("hedera:mainnet:0.0.1234567890-zbhlt")?;
  /// assert_eq!(account_id.chain_id().namespace().as_str(), "hedera");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn chain_id(&self) -> ChainId<'_> {
    ChainId::new(&self.data[..self.separator], self.chain_id_separator)
  }

  /// Returns a string slice to the account address part of this [AccountId].
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::account_id::{AccountId, AccountIdParsingError};
  /// #
  /// # fn main() -> Result<(), AccountIdParsingError<'static>> {
  /// let account_id = AccountId::parse("hedera:mainnet:0.0.1234567890-zbhlt")?;
  /// assert_eq!(account_id.address(), "0.0.1234567890-zbhlt");
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn address(&self) -> &str {
    &self.data[self.separator + 1..]
  }
}

impl FromStr for AccountId<'static> {
  type Err = AccountIdParsingError<'static>;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    AccountId::parse(s)
      .map(AccountId::into_owned)
      .map_err(|e| e.into_owned())
  }
}

impl<'i> TryFrom<&'i str> for AccountId<'i> {
  type Error = AccountIdParsingError<'i>;
  fn try_from(value: &'i str) -> Result<Self, Self::Error> {
    Self::parse(value)
  }
}

impl TryFrom<String> for AccountId<'static> {
  type Error = AccountIdParsingError<'static>;
  fn try_from(value: String) -> Result<Self, Self::Error> {
    let (chain_id_separator, separator) = AccountId::parse(&value)
      .map(|id| (id.chain_id_separator, id.separator))
      .map_err(AccountIdParsingError::into_owned)?;

    Ok(Self {
      data: value.into(),
      chain_id_separator,
      separator,
    })
  }
}

/// Error that may accure when parsing an [AccountId] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccountIdParsingError<'i> {
  source: ParseError<'i>,
}

impl<'i> AccountIdParsingError<'i> {
  /// Takes ownership of the input.
  pub fn into_owned(self) -> AccountIdParsingError<'static> {
    AccountIdParsingError {
      source: self.source.into_owned(),
    }
  }
}

fn account_id_parser<'i>(input: &'i str) -> ParserResult<'i, AccountId<'i>> {
  let (rem, (chain_id, _address)) = separated_pair(chain_id_parser, char(':'), account_address_parser)(input)?;
  let consumed = input.len() - rem.len();

  Ok((
    rem,
    AccountId {
      data: input[..consumed].into(),
      chain_id_separator: chain_id.separator,
      separator: chain_id.as_str().len(),
    },
  ))
}

fn account_address_parser(input: &str) -> ParserResult<'_, &str> {
  let valid_chars = take_while_min_max(1, ACCOUNT_ADDRESS_MAX_LEN, |c| {
    c == '.' || c == '-' || c.is_ascii_alphanumeric()
  });
  let (_, output) = recognize(many1(any((valid_chars, recognize(perc_encoded_parser))))).process(input)?;

  let consumed = output.len().min(ACCOUNT_ADDRESS_MAX_LEN);
  let (output, rem) = input.split_at(consumed);

  Ok((rem, output))
}

#[cfg(feature = "serde")]
mod serde_impl {
  use super::*;
  use serde::de::Error as _;
  use serde::Deserialize;
  use serde::Serialize;

  impl<'i> Serialize for AccountId<'i> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: serde::Serializer,
    {
      serializer.serialize_str(self.as_str())
    }
  }

  impl<'de> Deserialize<'de> for AccountId<'de> {
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
    assert!(VALID_ACCOUNT_IDS.iter().map(AccountId::parse).all(|res| res.is_ok()));
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
