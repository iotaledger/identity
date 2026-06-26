// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::str::FromStr;

use anyhow::anyhow;
use identity_core::convert::Base;
use identity_core::convert::BaseEncoding;
use serde::Deserialize;
use serde::Serialize;

/// An integrity metadata string as defined in [W3C SRI](https://www.w3.org/TR/SRI/#integrity-metadata).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct IntegrityMetadata(String);

impl IntegrityMetadata {
  /// Parses an [`IntegrityMetadata`] from a string.
  /// ## Example
  /// ```rust
  /// use identity_credential::sd_jwt_vc::metadata::IntegrityMetadata;
  ///
  /// let integrity_data = IntegrityMetadata::parse(
  ///   "sha384-dOTZf16X8p34q2/kYyEFm0jh89uTjikhnzjeLeF0FHsEaYKb1A1cv+Lyv4Hk8vHd",
  /// )
  /// .unwrap();
  /// ```
  pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
    s.parse()
  }

  /// Returns the digest algorithm's identifier string.
  /// ## Example
  /// ```rust
  /// use identity_credential::sd_jwt_vc::metadata::IntegrityMetadata;
  ///
  /// let integrity_data: IntegrityMetadata =
  ///   "sha384-dOTZf16X8p34q2/kYyEFm0jh89uTjikhnzjeLeF0FHsEaYKb1A1cv+Lyv4Hk8vHd"
  ///     .parse()
  ///     .unwrap();
  /// assert_eq!(integrity_data.alg(), "sha384");
  /// ```
  pub fn alg(&self) -> &str {
    self.0.split_once('-').unwrap().0
  }

  /// Returns the base64 encoded digest part.
  /// ## Example
  /// ```rust
  /// use identity_credential::sd_jwt_vc::metadata::IntegrityMetadata;
  ///
  /// let integrity_data: IntegrityMetadata =
  ///   "sha384-dOTZf16X8p34q2/kYyEFm0jh89uTjikhnzjeLeF0FHsEaYKb1A1cv+Lyv4Hk8vHd"
  ///     .parse()
  ///     .unwrap();
  /// assert_eq!(
  ///   integrity_data.digest(),
  ///   "dOTZf16X8p34q2/kYyEFm0jh89uTjikhnzjeLeF0FHsEaYKb1A1cv+Lyv4Hk8vHd"
  /// );
  /// ```
  pub fn digest(&self) -> &str {
    self.0.split('-').nth(1).unwrap()
  }

  /// Returns the digest's bytes.
  pub fn digest_bytes(&self) -> Vec<u8> {
    BaseEncoding::decode(self.digest(), Base::Base64).unwrap()
  }

  /// Returns the option part.
  /// ## Example
  /// ```rust
  /// use identity_credential::sd_jwt_vc::metadata::IntegrityMetadata;
  ///
  /// let integrity_data: IntegrityMetadata =
  ///   "sha384-dOTZf16X8p34q2/kYyEFm0jh89uTjikhnzjeLeF0FHsEaYKb1A1cv+Lyv4Hk8vHd"
  ///     .parse()
  ///     .unwrap();
  /// assert!(integrity_data.options().is_none());
  /// ```
  pub fn options(&self) -> Option<&str> {
    self.0.splitn(3, '-').nth(2)
  }
}

impl AsRef<str> for IntegrityMetadata {
  fn as_ref(&self) -> &str {
    self.0.as_str()
  }
}

impl Display for IntegrityMetadata {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", &self.0)
  }
}

impl FromStr for IntegrityMetadata {
  type Err = anyhow::Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::try_from(s.to_owned())
  }
}

impl TryFrom<String> for IntegrityMetadata {
  type Error = anyhow::Error;
  fn try_from(value: String) -> Result<Self, Self::Error> {
    let mut metadata_parts = value.splitn(3, '-');
    let _alg = metadata_parts
      .next()
      .ok_or_else(|| anyhow!("invalid integrity metadata"))?;
    let _digest = metadata_parts
      .next()
      .and_then(|digest| BaseEncoding::decode(digest, Base::Base64).ok())
      .ok_or_else(|| anyhow!("invalid integrity metadata"))?;
    let _options = metadata_parts.next();

    Ok(Self(value))
  }
}
