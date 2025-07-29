// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

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
}
