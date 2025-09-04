// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::str::FromStr;

use crate::chain_id;
use crate::parser::all_consuming;
use crate::parser::any;
use crate::parser::preceded;
use crate::parser::tag;
use crate::parser::take_while_min_max;
use crate::parser::ParseError;
use crate::parser::Parser;
use crate::parser::ParserResult;
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

pub(crate) fn iota_chain_id_parser(input: &str) -> ParserResult<'_, IotaChainId> {
  preceded(tag("iota:"), network_parser)
    .map(|network| IotaChainId { network })
    .process(input)
}

pub(crate) fn network_parser(input: &str) -> ParserResult<'_, IotaNetwork> {
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
