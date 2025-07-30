// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

use crate::account_id::AccountId;
use crate::parser::*;
use crate::ChainId;

const IOTA_CHAIN_ID_LEN: usize = 8;
const IOTA_MAINNET_ID: &str = "6364aad5";
const IOTA_TESTNET_ID: &str = "2304aa97";
const IOTA_DEVNET_ID: &str = "e678123a";

/// An IOTA network. Either an official alias `mainnet`, `testnet`, `devnet`
/// or an IOTA Chain Identifier (e.g. `a1b2c3d4`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IotaNetwork<'i>(IotaNetworkRepr<'i>);

impl<'i> AsRef<str> for IotaNetwork<'i> {
  fn as_ref(&self) -> &str {
    match &self.0 {
      IotaNetworkRepr::Mainnet => "mainnet",
      IotaNetworkRepr::Testnet => "testnet",
      IotaNetworkRepr::Devnet => "devnet",
      IotaNetworkRepr::Custom(network) => network.as_ref(),
    }
  }
}

impl<'i> Display for IotaNetwork<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_ref())
  }
}

impl IotaNetwork<'static> {
  /// IOTA Mainnet.
  #[inline(always)]
  pub const fn mainnet() -> Self {
    Self(IotaNetworkRepr::Mainnet)
  }

  /// IOTA Testnet.
  #[inline(always)]
  pub const fn testnet() -> Self {
    Self(IotaNetworkRepr::Testnet)
  }

  /// IOTA Devnet.
  #[inline(always)]
  pub const fn devnet() -> Self {
    Self(IotaNetworkRepr::Devnet)
  }
}

impl<'i> IotaNetwork<'i> {
  /// Returns the IOTA Chain Identifier of this [IotaNetwork].
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::IotaNetwork;
  /// # fn main() {
  /// let iota_mainnet = IotaNetwork::mainnet();
  /// assert_eq!(iota_mainnet.as_chain_identifier(), "6364aad5");
  /// # }
  /// ```
  pub fn as_chain_identifier(&self) -> &str {
    match self.0 {
      IotaNetworkRepr::Mainnet => IOTA_MAINNET_ID,
      IotaNetworkRepr::Testnet => IOTA_TESTNET_ID,
      IotaNetworkRepr::Devnet => IOTA_DEVNET_ID,
      IotaNetworkRepr::Custom(ref id) => id,
    }
  }

  /// Returns an [IotaNetwork] by parsing the given string input as an IOTA Chain Identifier.
  /// Returns [None] if the given input is an invalid IOTA Chain Identifier.
  ///
  /// If the chain identifier of an official IOTA network is provided, its network's alias will
  /// be used instead. If this behavior is undesirable use [IotaNetwork::custom] instead.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::IotaNetwork;
  /// # fn test() -> Option<()> {
  /// let custom_network = IotaNetwork::from_chain_identifier("a1b2c3d4")?;
  /// assert_eq!(custom_network.as_chain_identifier(), "a1b2c3d4");
  ///
  /// let mainnet = IotaNetwork::from_chain_identifier("6364aad5")?;
  /// assert_eq!(mainnet.as_str(), "mainnet");
  /// # Some(())
  /// # }
  /// #
  /// # fn main() {
  /// #   test().unwrap();
  /// # }
  /// ```
  pub fn from_chain_identifier(chain_identifier: &'i str) -> Option<IotaNetwork<'i>> {
    let (_, chain_id) = all_consuming(network_parser)(chain_identifier).ok()?;
    let repr = match chain_id {
      IOTA_MAINNET_ID => IotaNetworkRepr::Mainnet,
      IOTA_TESTNET_ID => IotaNetworkRepr::Testnet,
      IOTA_DEVNET_ID => IotaNetworkRepr::Devnet,
      _ => IotaNetworkRepr::Custom(chain_id.into()),
    };
    Some(Self(repr))
  }

  /// Returns an [IotaNetwork] by parsing the given string input as an IOTA Chain Identifier.
  /// Returns [None] if the given input is an invalid IOTA Chain Identifier.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::IotaNetwork;
  /// # fn test() -> Option<()> {
  /// let custom_network = IotaNetwork::custom("a1b2c3d4")?;
  /// assert_eq!(custom_network.as_chain_identifier(), "a1b2c3d4");
  ///
  /// let iota_mainnet = IotaNetwork::mainnet();
  /// let mainnet = IotaNetwork::custom(iota_mainnet.as_chain_identifier())?;
  /// assert_eq!(mainnet.as_str(), "6364aad5");
  /// # Some(())
  /// # }
  ///
  /// # fn main() {
  /// #   test().unwrap();
  /// # }
  /// ```
  pub fn custom(chain_identifier: &'i str) -> Option<Self> {
    let (_, chain_id) = all_consuming(network_parser)(chain_identifier).ok()?;
    Some(Self::custom_unchecked(chain_id))
  }

  #[inline(always)]
  const fn custom_unchecked(id: &'i str) -> Self {
    Self(IotaNetworkRepr::Custom(Cow::Borrowed(id)))
  }

  /// Takes ownership of the underlying string.
  pub fn into_owned(self) -> IotaNetwork<'static> {
    IotaNetwork(self.0.into_owned())
  }

  /// Returns a string representation for this [IotaNetwork].
  /// For unofficial IOTA networks their Chain Identifier is returned,
  /// whereas for official IOTA networks their alias (i.e. `mainnet`, `testnet`, `devnet`)
  /// is returned instead.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::IotaNetwork;
  /// # fn test() -> Option<()> {
  /// assert_eq!(IotaNetwork::mainnet().as_str(), "mainnet");
  /// assert_eq!(IotaNetwork::testnet().as_str(), "testnet");
  /// assert_eq!(
  ///   IotaNetwork::from_chain_identifier("a1b2c3d4")?.as_str(),
  ///   "a1b2c3d4"
  /// );
  /// assert_eq!(
  ///   IotaNetwork::from_chain_identifier("6364aad5")?.as_str(),
  ///   "mainnet"
  /// );
  /// # Some(())
  /// # }
  /// # fn main() {
  /// # test().unwrap();
  /// # }
  /// ```
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    self.as_ref()
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum IotaNetworkRepr<'i> {
  Mainnet,
  Testnet,
  Devnet,
  Custom(Cow<'i, str>),
}

impl<'i> IotaNetworkRepr<'i> {
  #[inline(always)]
  fn into_owned(self) -> IotaNetworkRepr<'static> {
    match self {
      Self::Mainnet => IotaNetworkRepr::Mainnet,
      Self::Testnet => IotaNetworkRepr::Testnet,
      Self::Devnet => IotaNetworkRepr::Devnet,
      Self::Custom(id) => IotaNetworkRepr::Custom(Cow::Owned(id.into_owned())),
    }
  }
}

/// IOTA-specific [Chain ID](crate::chain_id::ChainId) implementation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "ChainId", try_from = "ChainId", bound(deserialize = "'de: 'i"))
)]
pub struct IotaChainId<'i>(ChainId<'i>);

impl<'i> AsRef<ChainId<'i>> for IotaChainId<'i> {
  fn as_ref(&self) -> &ChainId<'i> {
    &self.0
  }
}

impl<'i> From<IotaChainId<'i>> for ChainId<'i> {
  fn from(value: IotaChainId<'i>) -> Self {
    value.0
  }
}

impl<'i> Display for IotaChainId<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.0.as_str())
  }
}

impl<'i> IotaChainId<'i> {
  /// Parses an IOTA Chain ID from the given input string.
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaChainId, IotaChainIdParseError, IotaNetwork};
  /// # fn main() -> Result<(), IotaChainIdParseError<'static>> {
  /// let iota_chain_id = IotaChainId::parse("iota:mainnet")?;
  /// assert_eq!(iota_chain_id.as_ref().namespace(), "iota");
  /// assert_eq!(iota_chain_id.network(), IotaNetwork::mainnet());
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse<I>(input: &'i I) -> Result<Self, IotaChainIdParseError<'i>>
  where
    I: AsRef<str> + ?Sized,
  {
    all_consuming(iota_chain_id_parser)
      .process(input.as_ref())
      .map(|(_, id)| id)
      .map_err(|e| IotaChainIdParseError { source: e.into_owned() })
  }

  /// Takes ownership of the underlying string input by cloning it.
  #[inline(always)]
  pub fn into_owned(self) -> IotaChainId<'static> {
    IotaChainId(self.0.into_owned())
  }

  /// Returns this chain ID's string representation.
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// Returns the IOTA Network this chain ID refers to.
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaChainId, IotaChainIdParseError, IotaNetwork};
  /// # fn main() -> Result<(), IotaChainIdParseError<'static>> {
  /// let iota_mainnet = IotaChainId::parse("iota:mainnet")?;
  /// assert_eq!(iota_mainnet.network(), IotaNetwork::mainnet());
  ///
  /// let iota_mainnet = IotaChainId::parse("iota:6364aad5")?;
  /// assert_eq!(iota_mainnet.network(), IotaNetwork::mainnet());
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn network(&self) -> IotaNetwork<'_> {
    match self.0.reference() {
      "mainnet" => IotaNetwork::mainnet(),
      "testnet" => IotaNetwork::testnet(),
      "devnet" => IotaNetwork::devnet(),
      chain_id => IotaNetwork::from_chain_identifier(chain_id).unwrap(),
    }
  }
}

impl IotaChainId<'static> {
  /// Returns a new [IotaChainId] referencing the given IOTA network.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaChainId, IotaNetwork};
  /// # fn main() {
  /// let iota_testnet_chain_id = IotaChainId::new(&IotaNetwork::testnet());
  /// assert_eq!(iota_testnet_chain_id.as_str(), "iota:testnet");
  /// # }
  /// ```
  pub fn new<'i>(network: &IotaNetwork<'i>) -> Self {
    Self(format!("iota:{}", network.as_str()).try_into().unwrap())
  }
}

impl<'i> TryFrom<ChainId<'i>> for IotaChainId<'i> {
  type Error = InvalidChainId<'i>;
  fn try_from(chain_id: ChainId<'i>) -> Result<Self, Self::Error> {
    if chain_id.namespace() != "iota" {
      return Err(InvalidChainId {
        chain_id,
        kind: InvalidChainIdKind::InvalidNamespace,
      });
    }

    if !is_valid_chain_id_reference(&chain_id) {
      return Err(InvalidChainId {
        chain_id,
        kind: InvalidChainIdKind::InvalidReference,
      });
    }

    Ok(Self(chain_id))
  }
}

impl<'i> TryFrom<&'i str> for IotaChainId<'i> {
  type Error = IotaChainIdParseError<'i>;
  fn try_from(value: &'i str) -> Result<Self, Self::Error> {
    Self::parse(value)
  }
}

impl FromStr for IotaChainId<'static> {
  type Err = IotaChainIdParseError<'static>;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    IotaChainId::parse(s)
      .map(IotaChainId::into_owned)
      .map_err(|e| e.into_owned())
  }
}

impl TryFrom<String> for IotaChainId<'static> {
  type Error = IotaChainIdParseError<'static>;
  fn try_from(value: String) -> Result<Self, Self::Error> {
    let _ = IotaChainId::parse(&value).map_err(|e| e.into_owned())?;
    Ok(Self(value.try_into().unwrap()))
  }
}

fn is_valid_chain_id_reference<'i>(chain_id: &ChainId<'i>) -> bool {
  ["mainnet", "testnet", "devnet"].contains(&chain_id.reference())
    || (chain_id.reference().len() == IOTA_CHAIN_ID_LEN
      && chain_id
        .reference()
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
}

/// Error that may occure when converting a [ChainId] into an [IotaChainId].
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct InvalidChainId<'i> {
  /// The [ChainId] that was being converted.
  pub chain_id: ChainId<'i>,
  /// The kind of failure.
  pub kind: InvalidChainIdKind,
}

impl<'i> Display for InvalidChainId<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "chain ID `{}` is not a valid IOTA's chain ID: ",
      self.chain_id.as_str()
    )?;
    match self.kind {
      InvalidChainIdKind::InvalidNamespace => {
        write!(f, "invalid namespace `{}` expected `iota`", self.chain_id.namespace())
      }
      InvalidChainIdKind::InvalidReference => write!(
        f,
        "invalid reference `{}` expected a network alias (`mainnet`, `testnet`, `devnet`) or an IOTA Chain Identifier",
        self.chain_id.reference()
      ),
    }
  }
}

/// Kind of failure for the conversion of a [ChainId] into an [IotaChainId].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InvalidChainIdKind {
  /// Invalid chain ID namespace.
  InvalidNamespace,
  /// Invalid chain ID reference.
  InvalidReference,
}

impl<'i> std::error::Error for InvalidChainId<'i> {}

/// Error that may occure when parsing an [IotaChainId] from a string.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct IotaChainIdParseError<'i> {
  /// The error returned by the underlying parser.
  pub source: ParseError<'i>,
}

impl<'i> IotaChainIdParseError<'i> {
  /// Takes ownership of the input string.
  pub fn into_owned(self) -> IotaChainIdParseError<'static> {
    IotaChainIdParseError {
      source: self.source.into_owned(),
    }
  }
}

impl<'i> Display for IotaChainIdParseError<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("failed to parse IOTA chain ID")
  }
}

impl std::error::Error for IotaChainIdParseError<'static> {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn iota_chain_id_parser<'i>(input: &'i str) -> ParserResult<'i, IotaChainId<'i>> {
  let (rem, (_, network)) = separated_pair(tag("iota"), char(':'), network_parser)(input)?;
  let consumed = input.len() - rem.len();
  let chain_id = ChainId::new(&input[..consumed], consumed - network.len() - 1);

  Ok((rem, IotaChainId(chain_id)))
}

fn network_parser<'i>(input: &'i str) -> ParserResult<'i, &'i str> {
  // exactly 8 lowercase hex digits.
  let iota_chain_identifier = take_while_min_max(IOTA_CHAIN_ID_LEN, IOTA_CHAIN_ID_LEN, |c| {
    c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
  });
  any((tag("mainnet"), tag("testnet"), tag("devnet"), iota_chain_identifier)).process(input)
}

/// An IOTA-specific [account ID](AccountId).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "AccountId", try_from = "AccountId", bound(deserialize = "'de: 'i"))
)]
pub struct IotaAccountId<'i>(AccountId<'i>);

impl<'i> IotaAccountId<'i> {
  /// Returns the string representation of this account ID.
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// Parses an [IotaAccountId] from the given input string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaNetwork, IotaAccountId, IotaAccountIdParsingError};
  /// #
  /// # fn main() -> Result<(), IotaAccountIdParsingError<'static>> {
  /// let iota_account = IotaAccountId::parse("iota:testnet:0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")?;
  /// assert_eq!(iota_account.address(), "0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
  /// assert_eq!(iota_account.network(), IotaNetwork::testnet());
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse<I>(input: &'i I) -> Result<Self, IotaAccountIdParsingError<'i>>
  where
    I: AsRef<str> + ?Sized,
  {
    all_consuming(iota_account_id_parser)
      .process(input.as_ref())
      .map(|(_, id)| id)
      .map_err(|source| IotaAccountIdParsingError { source })
  }

  /// Returns the [IOTA network](IotaNetwork) this account id references.
  /// # Example
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaNetwork, IotaAccountId, IotaAccountIdParsingError};
  /// #
  /// # fn main() -> Result<(), IotaAccountIdParsingError<'static>> {
  /// let iota_account = IotaAccountId::parse("iota:testnet:0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")?;
  /// assert_eq!(iota_account.network(), IotaNetwork::testnet());
  /// # Ok(())
  /// # }
  /// ```
  pub fn network(&self) -> IotaNetwork<'_> {
    let chain_id = IotaChainId(self.0.chain_id());
    let network = chain_id.network();

    // Safety: `network`'s lifetime is coherced to be the same lifetime as the local
    // `chain_id`, though that's *not* the case, as `network`'s lifetime is the same
    // as `self`'s.
    unsafe { std::mem::transmute(network) }
  }

  /// ```
  /// # use identity_chain_agnostic::iota::{IotaNetwork, IotaAccountId, IotaAccountIdParsingError};
  /// #
  /// # fn main() -> Result<(), IotaAccountIdParsingError<'static>> {
  /// let iota_account = IotaAccountId::parse("iota:testnet:0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")?;
  /// assert_eq!(iota_account.address(), "0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
  /// assert_eq!(iota_account.network(), IotaNetwork::testnet());
  /// # Ok(())
  /// # }
  /// ```
  #[inline(always)]
  pub fn address(&self) -> &str {
    self.0.address()
  }
}

impl<'i> AsRef<AccountId<'i>> for IotaAccountId<'i> {
  fn as_ref(&self) -> &AccountId<'i> {
    &self.0
  }
}

impl<'i> From<IotaAccountId<'i>> for AccountId<'i> {
  fn from(value: IotaAccountId<'i>) -> Self {
    value.0
  }
}

impl<'i> TryFrom<AccountId<'i>> for IotaAccountId<'i> {
  type Error = InvalidAccountId<'i>;
  fn try_from(value: AccountId<'i>) -> Result<Self, Self::Error> {
    if let Err(e) = IotaChainId::try_from(value.chain_id()) {
      let kind = match e.kind {
        InvalidChainIdKind::InvalidNamespace => InvalidAccountIdKind::InvalidChain,
        InvalidChainIdKind::InvalidReference => InvalidAccountIdKind::InvalidNetwork,
      };
      return Err(InvalidAccountId {
        account_id: value,
        kind,
      });
    }

    if !is_valid_iota_address(value.address()) {
      return Err(InvalidAccountId {
        account_id: value,
        kind: InvalidAccountIdKind::InvalidAddress,
      });
    }

    Ok(Self(value))
  }
}

fn iota_account_id_parser<'i>(input: &'i str) -> ParserResult<'i, IotaAccountId<'i>> {
  let (rem, (chain_id, _address)) = separated_pair(iota_chain_id_parser, char(':'), iota_address_parser)(input)?;
  let consumed = input.len() - rem.len();

  let account_id = AccountId::new(&input[..consumed], chain_id.0.separator, chain_id.as_str().len());
  Ok((rem, IotaAccountId(account_id)))
}

fn iota_address_parser<'i>(input: &'i str) -> ParserResult<'i, &'i str> {
  let (rem, _prefix) = tag("0x")(input)?;
  let (rem, _address) = take_while_min_max(64, 64, is_lowercase_hex_char)(rem)?;
  let consumed = input.len() - rem.len();

  Ok((rem, &input[..consumed]))
}

fn is_valid_iota_address(input: &str) -> bool {
  all_consuming(iota_address_parser)(input).is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IotaAccountIdParsingError<'i> {
  source: ParseError<'i>,
}

impl<'i> IotaAccountIdParsingError<'i> {
  /// Takes ownership of the underlying input.
  pub fn into_owned(self) -> IotaAccountIdParsingError<'static> {
    IotaAccountIdParsingError {
      source: self.source.into_owned(),
    }
  }
}

impl<'i> Display for IotaAccountIdParsingError<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("failed to parse IOTA account ID")
  }
}

impl std::error::Error for IotaAccountIdParsingError<'static> {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidAccountId<'i> {
  pub account_id: AccountId<'i>,
  pub kind: InvalidAccountIdKind,
}

impl<'i> InvalidAccountId<'i> {
  /// Takes ownership of the underlying input.
  pub fn into_owned(self) -> InvalidAccountId<'static> {
    InvalidAccountId {
      account_id: self.account_id.into_owned(),
      ..self
    }
  }
}

impl<'i> Display for InvalidAccountId<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "account ID `{}` is not a valid IOTA account ID: ",
      self.account_id.as_str()
    )?;
    match self.kind {
      InvalidAccountIdKind::InvalidChain => write!(
        f,
        "expected `iota` chain ID's namespace, but got `{}`",
        self.account_id.chain_id().namespace()
      ),
      InvalidAccountIdKind::InvalidNetwork => write!(
        f,
        "invalid network `{}`, expected `mainnet`, `testnet`, `devnet`, or an IOTA Chain Identifier",
        self.account_id.chain_id().reference()
      ),
      InvalidAccountIdKind::InvalidAddress => write!(f, "invalid address `{}`", self.account_id.address()),
    }
  }
}

/// Types of failures for error [InvalidAccountId].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidAccountIdKind {
  /// Not an IOTA chain.
  InvalidChain,
  /// Invalid IOTA network identifier.
  InvalidNetwork,
  /// Invalid IOTA address.
  InvalidAddress,
}

#[cfg(test)]
mod tests {
  use super::*;

  const VALID_IOTA_CHAIN_IDS: &[&str] = &["iota:mainnet", "iota:testnet", "iota:devnet", "iota:a1b2c3d4"];

  #[test]
  fn parsing_valid_iota_chain_ids_works() {
    assert!(VALID_IOTA_CHAIN_IDS
      .iter()
      .map(IotaChainId::parse)
      .all(|res| res.is_ok()))
  }

  #[test]
  fn fails_to_parse_when_namespace_is_not_iota() {
    let e = IotaChainId::parse("eip155:1").unwrap_err();
    assert_eq!(
      e.source,
      ParseError::new(
        "eip155:1",
        ParseErrorKind::UnexpectedCharacter {
          invalid: 'e',
          expected: Some(Expected::Char('i'))
        }
      )
    );
  }

  #[test]
  fn iota_chain_id_to_string_works() {
    let iota_chain_id = IotaChainId::parse("iota:testnet").unwrap();
    assert_eq!(iota_chain_id.to_string().as_str(), "iota:testnet");
  }

  #[test]
  fn chain_id_to_iota_chain_id_conversion_works() {
    let chain_id = ChainId::parse("iota:a1b2c3d4").unwrap();
    let iota_chain_id = IotaChainId::try_from(chain_id.clone()).unwrap();
    assert_eq!(&chain_id, iota_chain_id.as_ref());

    let chain_id = ChainId::parse("eip155:1").unwrap();
    let e = IotaChainId::try_from(chain_id.clone()).unwrap_err();
    assert_eq!(
      e,
      InvalidChainId {
        chain_id,
        kind: InvalidChainIdKind::InvalidNamespace
      }
    );

    let chain_id = ChainId::parse("iota:errnet").unwrap();
    let e = IotaChainId::try_from(chain_id.clone()).unwrap_err();
    assert_eq!(
      e,
      InvalidChainId {
        chain_id,
        kind: InvalidChainIdKind::InvalidReference
      }
    )
  }

  #[test]
  fn account_id_to_iota_account_id_conversion_works() {
    let account_id =
      AccountId::parse("iota:mainnet:0x1234567890123456789012345678901234567890123456789012345678901234").unwrap();
    let _iota_account_id = IotaAccountId::try_from(account_id).unwrap();

    let account_id = AccountId::parse("hedera:mainnet:0.0.1234567890-zbhlt").unwrap();
    let e = IotaAccountId::try_from(account_id).unwrap_err();
    assert_eq!(e.kind, InvalidAccountIdKind::InvalidChain);

    let account_id = AccountId::parse("iota:errnet:0.0.1234567890-zbhlt").unwrap();
    let e = IotaAccountId::try_from(account_id).unwrap_err();
    assert_eq!(e.kind, InvalidAccountIdKind::InvalidNetwork);

    let account_id = AccountId::parse("iota:mainnet:0.0.1234567890-zbhlt").unwrap();
    let e = IotaAccountId::try_from(account_id).unwrap_err();
    assert_eq!(e.kind, InvalidAccountIdKind::InvalidAddress);
  }
}
