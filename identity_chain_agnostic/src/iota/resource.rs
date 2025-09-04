// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;

use crate::iota::address::iota_address_parser;
use crate::iota::address::IotaAddress;
use crate::iota::network::iota_chain_id_parser;
use crate::iota::network::IotaNetwork;
use crate::parser::all_consuming;
use crate::parser::char;
use crate::parser::opt;
use crate::parser::preceded;
use crate::parser::separated_pair;
use crate::parser::ParseError;
use crate::parser::Parser as _;
use crate::parser::ParserResult;
use crate::resource::relative_url_parser;
use crate::resource::ChainAgnosticResourceLocator;
use crate::resource::RelativeUrl;

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

impl From<IotaResourceLocator> for ChainAgnosticResourceLocator {
  fn from(value: IotaResourceLocator) -> Self {
    let chain_id = value.network.into();
    let mut url = value.relative_url;
    url
      .set_path(&format!("{}{}", value.object_id, url.path().trim_start_matches('/')))
      .expect("valid_path");

    ChainAgnosticResourceLocator { chain_id, locator: url }
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
