// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fmt::Display;
use std::str::FromStr;

use crate::account_id::AccountAddress;
use crate::iota::network::iota_chain_id_parser;
use crate::iota::network::InvalidChainIdKind;
use crate::iota::network::IotaChainId;
use crate::iota::network::IotaNetwork;
use crate::parser::all_consuming;
use crate::parser::char;
use crate::parser::fill;
use crate::parser::lowercase_hex_digit;
use crate::parser::preceded;
use crate::parser::separated_pair;
use crate::parser::tag;
use crate::parser::ParseError;
use crate::parser::Parser as _;
use crate::parser::ParserResult;
use crate::AccountId;

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
  /// assert_eq!(iota_account.network, IotaNetwork::Testnet);
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IotaAddress([u8; 32]);

impl Debug for IotaAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_tuple("IotaAddress").field(&self.to_string()).finish()
  }
}

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

pub(crate) fn iota_address_parser(input: &str) -> ParserResult<'_, IotaAddress> {
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
