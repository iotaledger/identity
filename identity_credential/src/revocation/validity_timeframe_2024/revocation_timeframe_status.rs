// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use crate::credential::Status;
use crate::error::Error;
use crate::error::Result;
use identity_core::common::Duration;
use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::common::Value;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Serialize;

fn deserialize_status_entry_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
  D: serde::Deserializer<'de>,
{
  struct ExactStrVisitor(&'static str);
  impl Visitor<'_> for ExactStrVisitor {
    type Value = &'static str;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(formatter, "the exact string \"{}\"", self.0)
    }
    fn visit_str<E: serde::de::Error>(self, str: &str) -> Result<Self::Value, E> {
      if str == self.0 {
        Ok(self.0)
      } else {
        Err(E::custom(format!("not \"{}\"", self.0)))
      }
    }
  }

  deserializer
    .deserialize_str(ExactStrVisitor(RevocationTimeframeStatus::TYPE))
    .map(ToOwned::to_owned)
}

/// Information used to determine the current status of a [`Credential`][crate::credential::Credential]
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RevocationTimeframeStatus {
  id: Url,
  #[serde(rename = "type", deserialize_with = "deserialize_status_entry_type")]
  type_: String,
  start_validity_timeframe: Timestamp,
  end_validity_timeframe: Timestamp,
  #[serde(
    deserialize_with = "serde_aux::prelude::deserialize_option_number_from_string",
    skip_serializing_if = "Option::is_none"
  )]
  revocation_bitmap_index: Option<u32>,
}

impl RevocationTimeframeStatus {
  /// startValidityTimeframe property name.
  pub const START_TIMEFRAME_PROPERTY: &'static str = "startValidityTimeframe";
  /// endValidityTimeframe property name.
  pub const END_TIMEFRAME_PROPERTY: &'static str = "endValidityTimeframe";
  /// Type name of the revocation mechanism.
  pub const TYPE: &'static str = "RevocationTimeframe2024";
  /// index property name for [`Status`] conversion
  const INDEX_PROPERTY: &'static str = "revocationBitmapIndex";

  /// Creates a new `RevocationTimeframeStatus`.
  pub fn new(start_validity: Option<Timestamp>, duration: Duration, id: Url, index: u32) -> Result<Self> {
    let start_validity_timeframe = start_validity.unwrap_or(Timestamp::now_utc());
    let end_validity_timeframe = start_validity_timeframe
      .checked_add(duration)
      .ok_or(Error::InvalidStatus(
        "With that granularity, endValidityTimeFrame will turn out not to be in the valid range for RFC 3339"
          .to_owned(),
      ))?;

    Ok(Self {
      id,
      type_: Self::TYPE.to_owned(),
      start_validity_timeframe,
      end_validity_timeframe,
      revocation_bitmap_index: Some(index),
    })
  }

  /// Get startValidityTimeframe value.
  pub fn start_validity_timeframe(&self) -> Timestamp {
    self.start_validity_timeframe
  }

  /// Get endValidityTimeframe value.
  pub fn end_validity_timeframe(&self) -> Timestamp {
    self.end_validity_timeframe
  }

  /// Returns the [`Url`] of the `RevocationBitmapStatus`, which should resolve
  /// to a `RevocationBitmap2022` service in a DID Document.
  pub fn id(&self) -> &Url {
    &self.id
  }

  /// Returns the index of the credential in the issuer's revocation bitmap if it can be decoded.
  pub fn index(&self) -> Option<u32> {
    self.revocation_bitmap_index
  }
}

impl TryFrom<&Status> for RevocationTimeframeStatus {
  type Error = Error;
  fn try_from(status: &Status) -> Result<Self, Self::Error> {
    // serialize into String to ensure macros work properly
    // see [issue](https://github.com/iddm/serde-aux/issues/34#issuecomment-1508207530) in `serde-aux`
    let json_status: String = serde_json::to_string(&status)
      .map_err(|err| Self::Error::InvalidStatus(format!("failed to read `Status`; {}", &err.to_string())))?;
    serde_json::from_str(&json_status).map_err(|err| {
      Self::Error::InvalidStatus(format!(
        "failed to convert `Status` to `RevocationTimeframeStatus`; {}",
        &err.to_string(),
      ))
    })
  }
}

impl From<RevocationTimeframeStatus> for Status {
  fn from(revocation_timeframe_status: RevocationTimeframeStatus) -> Self {
    let mut properties = Object::new();
    properties.insert(
      RevocationTimeframeStatus::START_TIMEFRAME_PROPERTY.to_owned(),
      Value::String(revocation_timeframe_status.start_validity_timeframe().to_rfc3339()),
    );
    properties.insert(
      RevocationTimeframeStatus::END_TIMEFRAME_PROPERTY.to_owned(),
      Value::String(revocation_timeframe_status.end_validity_timeframe().to_rfc3339()),
    );
    if let Some(value) = revocation_timeframe_status.index() {
      properties.insert(
        RevocationTimeframeStatus::INDEX_PROPERTY.to_owned(),
        Value::String(value.to_string()),
      );
    }

    Status::new_with_properties(
      revocation_timeframe_status.id,
      RevocationTimeframeStatus::TYPE.to_owned(),
      properties,
    )
  }
}

/// Verifier
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierRevocationTimeframeStatus(pub(crate) RevocationTimeframeStatus);

impl TryFrom<Status> for VerifierRevocationTimeframeStatus {
  type Error = Error;

  fn try_from(status: Status) -> Result<Self> {
    Ok(Self((&status).try_into().map_err(|err: Error| {
      Self::Error::InvalidStatus(format!(
        "failed to convert `Status` to `VerifierRevocationTimeframeStatus`; {}",
        &err.to_string()
      ))
    })?))
  }
}

impl From<VerifierRevocationTimeframeStatus> for Status {
  fn from(status: VerifierRevocationTimeframeStatus) -> Self {
    status.0.into()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const EXAMPLE_SERIALIZED: &str = r#"{
    "id": "did:iota:snd:0xae6ccfdb155a69e0ef153fb5fcfd50c08a8fee36babe1f7d71dede8f4e202432#my-revocation-service",
    "startValidityTimeframe": "2024-03-19T13:57:50Z",
    "endValidityTimeframe": "2024-03-19T13:58:50Z",
    "revocationBitmapIndex": "5",
    "type": "RevocationTimeframe2024"
  }"#;

  fn get_example_status() -> anyhow::Result<RevocationTimeframeStatus> {
    let duration = Duration::minutes(1);
    let service_url = Url::parse(
      "did:iota:snd:0xae6ccfdb155a69e0ef153fb5fcfd50c08a8fee36babe1f7d71dede8f4e202432#my-revocation-service",
    )?;
    let credential_index: u32 = 5;
    let start_validity_timeframe = Timestamp::parse("2024-03-19T13:57:50Z")?;

    Ok(RevocationTimeframeStatus::new(
      Some(start_validity_timeframe),
      duration,
      service_url,
      credential_index,
    )?)
  }

  #[test]
  fn revocation_timeframe_status_serialization_works() -> anyhow::Result<()> {
    let status = get_example_status()?;

    let serialized = serde_json::to_string(&status).expect("Failed to deserialize");
    dbg!(&serialized);

    Ok(())
  }

  #[test]
  fn revocation_timeframe_status_deserialization_works() -> anyhow::Result<()> {
    let status = get_example_status()?;
    let deserialized =
      serde_json::from_str::<RevocationTimeframeStatus>(EXAMPLE_SERIALIZED).expect("Failed to deserialize");

    assert_eq!(status, deserialized);

    Ok(())
  }
}
