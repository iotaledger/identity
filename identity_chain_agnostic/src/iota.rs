// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::str::FromStr;

use crate::account_id::AccountAddress;
use crate::account_id::AccountId;
use crate::chain_id;
use crate::parser::*;
use crate::resource::relative_url_parser;
use crate::resource::OnChainResourceLocator;
use crate::resource::RelativeUrl;
use crate::ChainId;

const IOTA_CHAIN_ID_LEN: usize = 8;
const IOTA_MAINNET_ID: &str = "6364aad5";
const IOTA_TESTNET_ID: &str = "2304aa97";
const IOTA_DEVNET_ID: &str = "e678123a";

/// An IOTA network. Either an official alias `mainnet`, `testnet`, `devnet`
/// or an IOTA Chain Identifier (e.g. `a1b2c3d4`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IotaNetwork(IotaNetworkRepr);

impl AsRef<str> for IotaNetwork {
  fn as_ref(&self) -> &str {
    match &self.0 {
      IotaNetworkRepr::Mainnet => "mainnet",
      IotaNetworkRepr::Testnet => "testnet",
      IotaNetworkRepr::Devnet => "devnet",
      IotaNetworkRepr::Custom(network) => network.as_ref(),
    }
  }
}

impl Display for IotaNetwork {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_ref())
  }
}

impl IotaNetwork {
  /// IOTA Mainnet.
  pub const fn mainnet() -> Self {
    Self(IotaNetworkRepr::Mainnet)
  }

  /// IOTA Testnet.
  pub const fn testnet() -> Self {
    Self(IotaNetworkRepr::Testnet)
  }

  /// IOTA Devnet.
  pub const fn devnet() -> Self {
    Self(IotaNetworkRepr::Devnet)
  }

  /// Returns the last 8 hex characters of this [IotaNetwork]'s genesis digest.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::IotaNetwork;
  /// # fn main() {
  /// let iota_mainnet = IotaNetwork::mainnet();
  /// assert_eq!(iota_mainnet.as_genesis_digest(), "6364aad5");
  /// # }
  /// ```
  pub fn as_genesis_digest(&self) -> &str {
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
  /// If the genesis digest of an official IOTA network is provided, its network's alias will
  /// be used instead. If this behavior is undesirable use [IotaNetwork::custom] instead.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::IotaNetwork;
  /// # fn test() -> Option<()> {
  /// let custom_network = IotaNetwork::from_genesis_digest("a1b2c3d4")?;
  /// assert_eq!(custom_network.as_genesis_digest(), "a1b2c3d4");
  ///
  /// let mainnet = IotaNetwork::from_genesis_digest("6364aad5")?;
  /// assert_eq!(mainnet.as_str(), "mainnet");
  /// # Some(())
  /// # }
  /// #
  /// # fn main() {
  /// #   test().unwrap();
  /// # }
  /// ```
  pub fn from_genesis_digest(digest: &str) -> Option<IotaNetwork> {
    let repr = match digest {
      IOTA_MAINNET_ID => IotaNetworkRepr::Mainnet,
      IOTA_TESTNET_ID => IotaNetworkRepr::Testnet,
      IOTA_DEVNET_ID => IotaNetworkRepr::Devnet,
      digest => network_parser(digest).map(|(_, network)| network).ok()?.0,
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
  /// assert_eq!(custom_network.as_genesis_digest(), "a1b2c3d4");
  ///
  /// let iota_mainnet = IotaNetwork::mainnet();
  /// let mainnet = IotaNetwork::custom(iota_mainnet.as_genesis_digest())?;
  /// assert_eq!(mainnet.as_str(), "6364aad5");
  /// # Some(())
  /// # }
  ///
  /// # fn main() {
  /// #   test().unwrap();
  /// # }
  /// ```
  pub fn custom(chain_identifier: &str) -> Option<Self> {
    let (_, network) = all_consuming(network_parser)(chain_identifier).ok()?;
    Some(network)
  }

  fn custom_unchecked(id: &str) -> Self {
    Self(IotaNetworkRepr::Custom(id.into()))
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
  ///   IotaNetwork::from_genesis_digest("a1b2c3d4")?.as_str(),
  ///   "a1b2c3d4"
  /// );
  /// assert_eq!(
  ///   IotaNetwork::from_genesis_digest("6364aad5")?.as_str(),
  ///   "mainnet"
  /// );
  /// # Some(())
  /// # }
  /// # fn main() {
  /// # test().unwrap();
  /// # }
  /// ```
  pub fn as_str(&self) -> &str {
    self.as_ref()
  }
}

impl From<IotaNetwork> for ChainId {
  fn from(value: IotaNetwork) -> Self {
    let namespace = chain_id::Namespace::new_unchecked("iota");
    let reference = chain_id::Reference::new_unchecked(value.as_str());
    ChainId::new(namespace, reference)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum IotaNetworkRepr {
  Mainnet,
  Testnet,
  Devnet,
  Custom(Box<str>),
}

/// IOTA-specific [Chain ID](crate::chain_id::ChainId) implementation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "ChainId", try_from = "ChainId"))]
#[non_exhaustive]
pub struct IotaChainId {
  pub network: IotaNetwork,
}

impl From<IotaChainId> for ChainId {
  fn from(value: IotaChainId) -> Self {
    value.network.into()
  }
}

impl Display for IotaChainId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "iota:{}", self.network)
  }
}

impl IotaChainId {
  /// Parses an IOTA Chain ID from the given input string.
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaChainId, IotaChainIdParseError, IotaNetwork};
  /// # fn main() -> Result<(), IotaChainIdParseError> {
  /// let iota_chain_id = IotaChainId::parse("iota:mainnet")?;
  /// assert_eq!(iota_chain_id.network, IotaNetwork::mainnet());
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, IotaChainIdParseError> {
    all_consuming(iota_chain_id_parser)
      .process(input.as_ref())
      .map(|(_, id)| id)
      .map_err(|e| IotaChainIdParseError { source: e.into_owned() })
  }

  /// Returns a new [IotaChainId] referencing the given IOTA network.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaChainId, IotaNetwork};
  /// # fn main() {
  /// let iota_testnet_chain_id = IotaChainId::new(IotaNetwork::testnet());
  /// assert_eq!(iota_testnet_chain_id.to_string().as_str(), "iota:testnet");
  /// # }
  /// ```
  pub fn new(network: IotaNetwork) -> Self {
    Self { network }
  }
}

impl TryFrom<ChainId> for IotaChainId {
  type Error = InvalidChainId;
  fn try_from(chain_id: ChainId) -> Result<Self, Self::Error> {
    if chain_id.namespace.as_str() != "iota" {
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

    let network = IotaNetwork::custom_unchecked(chain_id.reference.as_str());

    Ok(Self { network })
  }
}

impl FromStr for IotaChainId {
  type Err = IotaChainIdParseError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    IotaChainId::parse(s)
  }
}

fn is_valid_chain_id_reference(chain_id: &ChainId) -> bool {
  ["mainnet", "testnet", "devnet"].contains(&chain_id.reference.as_str())
    || (chain_id.reference.len() == IOTA_CHAIN_ID_LEN
      && chain_id
        .reference
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
}

/// Error that may occure when converting a [ChainId] into an [IotaChainId].
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct InvalidChainId {
  /// The [ChainId] that was being converted.
  pub chain_id: ChainId,
  /// The kind of failure.
  pub kind: InvalidChainIdKind,
}

impl Display for InvalidChainId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "chain ID `{}` is not a valid IOTA's chain ID: ", self.chain_id)?;
    match self.kind {
      InvalidChainIdKind::InvalidNamespace => {
        write!(f, "invalid namespace `{}` expected `iota`", self.chain_id.namespace)
      }
      InvalidChainIdKind::InvalidReference => write!(
        f,
        "invalid reference `{}` expected a network alias (`mainnet`, `testnet`, `devnet`) or an IOTA genesis digest",
        self.chain_id.reference
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

impl std::error::Error for InvalidChainId {}

/// Error that may occure when parsing an [IotaChainId] from a string.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct IotaChainIdParseError {
  /// The error returned by the underlying parser.
  source: ParseError<'static>,
}

impl Display for IotaChainIdParseError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("failed to parse IOTA chain ID")
  }
}

impl std::error::Error for IotaChainIdParseError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn iota_chain_id_parser(input: &str) -> ParserResult<'_, IotaChainId> {
  preceded(tag("iota:"), network_parser)
    .map(|network| IotaChainId { network })
    .process(input)
}

fn network_parser(input: &str) -> ParserResult<'_, IotaNetwork> {
  // exactly 8 lowercase hex digits.
  let iota_genesis_digest = take_while_min_max(IOTA_CHAIN_ID_LEN, IOTA_CHAIN_ID_LEN, |c| {
    c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
  });
  let mainnet_parser = tag("mainnet").map(|_| IotaNetwork::mainnet());
  let testnet_parser = tag("testnet").map(|_| IotaNetwork::testnet());
  let devnet_parser = tag("devnet").map(|_| IotaNetwork::devnet());
  let custom_parser = iota_genesis_digest.map(IotaNetwork::custom_unchecked);
  any((mainnet_parser, testnet_parser, devnet_parser, custom_parser)).process(input)
}

/// An IOTA-specific [account ID](AccountId).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "AccountId", try_from = "AccountId"))]
pub struct IotaAccountId {
  pub network: IotaNetwork,
  pub address: IotaAddress,
}

impl IotaAccountId {
  /// Returns a new [IotaAccountId] from the given [IotaNetwork] and [IotaAddress].
  pub const fn new(network: IotaNetwork, address: IotaAddress) -> Self {
    Self { network, address }
  }
  /// Parses an [IotaAccountId] from the given input string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::iota::{IotaNetwork, IotaAccountId, IotaAccountIdParsingError};
  /// #
  /// # fn main() -> Result<(), IotaAccountIdParsingError> {
  /// let iota_account = IotaAccountId::parse("iota:testnet:0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")?;
  /// assert_eq!(iota_account.address.to_string().as_str(), "0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
  /// assert_eq!(iota_account.network, IotaNetwork::testnet());
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, IotaAccountIdParsingError> {
    all_consuming(iota_account_id_parser)
      .process(input)
      .map(|(_, id)| id)
      .map_err(|e| IotaAccountIdParsingError { source: e.into_owned() })
  }
}

impl From<IotaAccountId> for AccountId {
  fn from(value: IotaAccountId) -> Self {
    AccountId::new(value.network.into(), value.address.into())
  }
}

impl TryFrom<AccountId> for IotaAccountId {
  type Error = InvalidAccountId;
  fn try_from(value: AccountId) -> Result<Self, Self::Error> {
    let network = IotaChainId::try_from(value.chain_id.clone())
      .map_err(|e| {
        let kind = match e.kind {
          InvalidChainIdKind::InvalidNamespace => InvalidAccountIdKind::InvalidChain,
          InvalidChainIdKind::InvalidReference => InvalidAccountIdKind::InvalidNetwork,
        };
        InvalidAccountId {
          account_id: value.clone(),
          kind,
        }
      })?
      .network;

    let address = IotaAddress::try_from(value.address.clone()).map_err(|_| InvalidAccountId {
      account_id: value,
      kind: InvalidAccountIdKind::InvalidAddress,
    })?;

    Ok(Self::new(network, address))
  }
}

fn iota_account_id_parser(input: &str) -> ParserResult<'_, IotaAccountId> {
  separated_pair(iota_chain_id_parser, char(':'), iota_address_parser)
    .map(|(chain_id, address): (IotaChainId, IotaAddress)| IotaAccountId::new(chain_id.network, address))
    .process(input)
}

/// An IOTA address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IotaAddress([u8; 32]);

impl IotaAddress {
  /// Returns this address' byte representation.
  pub const fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  /// Consumes this IOTA address, returning the underlying bytes.
  pub const fn into_bytes(self) -> [u8; 32] {
    self.0
  }
}

impl From<IotaAddress> for [u8; 32] {
  fn from(value: IotaAddress) -> Self {
    value.into_bytes()
  }
}

impl From<IotaAddress> for AccountAddress {
  fn from(value: IotaAddress) -> Self {
    AccountAddress::new_unchecked(value.to_string())
  }
}

impl Display for IotaAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "0x")?;
    for b in self.as_bytes() {
      write!(f, "{b:02x}")?;
    }

    Ok(())
  }
}

impl FromStr for IotaAddress {
  type Err = InvalidIotaAddress;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    all_consuming(iota_address_parser)
      .process(s)
      .map(|(_, address)| address)
      .map_err(|e| InvalidIotaAddress { source: e.into_owned() })
  }
}

impl TryFrom<AccountAddress> for IotaAddress {
  type Error = InvalidIotaAddress;
  fn try_from(value: AccountAddress) -> Result<Self, Self::Error> {
    value.as_str().parse()
  }
}

fn iota_address_parser(input: &str) -> ParserResult<'_, IotaAddress> {
  let mut address_bytes = [0; 32];
  let (rem, _) = preceded(tag("0x"), fill(lowercase_hex_digit, &mut address_bytes))(input)?;

  Ok((rem, IotaAddress(address_bytes)))
}

#[derive(Debug)]
pub struct InvalidIotaAddress {
  source: ParseError<'static>,
}

impl Display for InvalidIotaAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("invalid IOTA address")
  }
}

impl std::error::Error for InvalidIotaAddress {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IotaAccountIdParsingError {
  source: ParseError<'static>,
}

impl Display for IotaAccountIdParsingError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("failed to parse IOTA account ID")
  }
}

impl std::error::Error for IotaAccountIdParsingError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidAccountId {
  pub account_id: AccountId,
  pub kind: InvalidAccountIdKind,
}

impl Display for InvalidAccountId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "account ID `{}` is not a valid IOTA account ID: ", self.account_id)?;
    match self.kind {
      InvalidAccountIdKind::InvalidChain => write!(
        f,
        "expected `iota` chain ID's namespace, but got `{}`",
        self.account_id.chain_id.namespace
      ),
      InvalidAccountIdKind::InvalidNetwork => write!(
        f,
        "invalid network `{}`, expected `mainnet`, `testnet`, `devnet`, or an IOTA Chain Identifier",
        self.account_id.chain_id.reference
      ),
      InvalidAccountIdKind::InvalidAddress => write!(f, "invalid address `{}`", self.account_id.address),
    }
  }
}

impl std::error::Error for InvalidAccountId {}

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

/// A URL-like address used to locate arbitrary resources on an IOTA network.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IotaResourceLocator {
  pub network: IotaNetwork,
  pub object_id: IotaAddress,
  pub relative_url: RelativeUrl,
}

impl IotaResourceLocator {
  /// Parses an [IotaResourceLocator] from the given string.
  /// # Examples
  /// [IotaResourceLocator] are mainly used to address IOTA Objects:
  /// ```
  /// # use identity_chain_agnostic::iota::IotaResourceLocator;
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let iota_object = IotaResourceLocator::parse(
  ///   "iota:mainnet/0x1234567890123456789012345678901234567890123456789012345678901234",
  /// )?;
  /// # Ok(())
  /// # }
  /// ```
  /// But it can also be used to address part of an object. For instance, the content of
  /// an object's field:
  /// ```
  /// # use identity_chain_agnostic::iota::IotaResourceLocator;
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let object_stored_data = IotaResourceLocator::parse(
  ///   "iota:mainnet/0x1234567890123456789012345678901234567890123456789012345678901234/data",
  /// )?;
  /// # assert_eq!(object_stored_data.relative_url.path(), "data");
  /// # Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, ParseError<'_>> {
    all_consuming(iota_resource_locator_parser)
      .process(input)
      .map(|(_, out)| out)
  }
}

impl Display for IotaResourceLocator {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "iota:{}/{}/{}", self.network, self.object_id, self.relative_url)
  }
}

impl From<IotaResourceLocator> for OnChainResourceLocator {
  fn from(value: IotaResourceLocator) -> Self {
    let chain_id = value.network.into();
    let mut url = value.relative_url;
    url
      .set_path(&format!("{}{}", value.object_id, url.path().trim_start_matches('/')))
      .expect("valid_path");

    OnChainResourceLocator { chain_id, locator: url }
  }
}

fn iota_resource_locator_parser(input: &str) -> ParserResult<'_, IotaResourceLocator> {
  let (rem, (chain_id, object_id)) = separated_pair(iota_chain_id_parser, char('/'), iota_address_parser)(input)?;
  let (rem, maybe_relative_url) = opt(preceded(opt(char('/')), relative_url_parser))(rem)?;

  let resource_locator = IotaResourceLocator {
    network: chain_id.network,
    object_id,
    relative_url: maybe_relative_url.unwrap_or_default(),
  };

  Ok((rem, resource_locator))
}

#[cfg(test)]
mod tests {
  use super::*;

  const VALID_IOTA_CHAIN_IDS: &[&str] = &["iota:mainnet", "iota:testnet", "iota:devnet", "iota:a1b2c3d4"];

  #[test]
  fn parsing_valid_iota_chain_ids_works() {
    assert!(VALID_IOTA_CHAIN_IDS
      .iter()
      .map(|s| IotaChainId::parse(s))
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
    assert_eq!(chain_id, iota_chain_id.into());

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
