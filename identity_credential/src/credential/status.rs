// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::OneOrMany;
use serde::Deserialize;
use serde::Serialize;

use identity_core::common::Object;
use identity_core::common::Url;

/// Information used to determine the current status of a [`Credential`][crate::credential::Credential].
///
/// [More Info](https://www.w3.org/TR/vc-data-model/#status)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Status<T = Object> {
  /// A Url identifying the credential status.
  pub id: Url,
  /// The type(s) of the credential status.
  #[serde(rename = "type")]
  pub type_: String,
  /// Additional properties of the credential status.
  #[serde(flatten)]
  pub properties: T,
}

impl Status<Object> {
  /// Creates a new `Status`.
  pub fn new(id: Url, type_: String) -> Self {
    Self::new_with_properties(id, type_, Object::new())
  }
}

impl<T> Status<T> {
  /// Creates a new `Status` with the given `properties`.
  pub fn new_with_properties(id: Url, type_: String, properties: T) -> Self {
    Self { id, type_, properties }
  }
}

/// VC Data Model 2.0 [credential status](https://www.w3.org/TR/vc-data-model-2.0/#status).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatusV2<T = Object> {
  /// Optional ID for this `credentialStatus`.
  pub id: Option<Url>,
  /// Types of status information.
  #[serde(rename = "type")]
  pub type_: OneOrMany<String>,
  /// Properties depending on type.
  #[serde(flatten)]
  pub properties: T,
}

impl<T> From<Status<T>> for StatusV2<T> {
  fn from(value: Status<T>) -> Self {
    Self {
      id: Some(value.id),
      type_: OneOrMany::One(value.type_),
      properties: value.properties,
    }
  }
}

impl<T> TryFrom<StatusV2<T>> for Status<T> {
  type Error = StatusConversionError;
  fn try_from(value: StatusV2<T>) -> Result<Self, Self::Error> {
    Ok(Self {
      id: value.id.ok_or(StatusConversionError::MissingId)?,
      type_: value.type_.into_vec().swap_remove(0),
      properties: value.properties,
    })
  }
}

/// The error resulting from a failed conversion of a [`StatusV2`] into a [`Status`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StatusConversionError {
  /// Property `id` is missing.
  #[error("missing property `id`")]
  MissingId,
}

impl<T> Sealed for Status<T> {}
impl<T> StatusT for Status<T> {
  type Properties = T;
  fn id(&self) -> Option<&Url> {
    Some(&self.id)
  }
  fn type_(&self) -> &[String] {
    std::slice::from_ref(&self.type_)
  }
  fn properties(&self) -> &Self::Properties {
    &self.properties
  }
}

impl<T> Sealed for StatusV2<T> {}
impl<T> StatusT for StatusV2<T> {
  type Properties = T;
  fn id(&self) -> Option<&Url> {
    self.id.as_ref()
  }
  fn type_(&self) -> &[String] {
    self.type_.as_slice()
  }
  fn properties(&self) -> &Self::Properties {
    &self.properties
  }
}

trait Sealed {}

/// A `credentialStatus`.
#[allow(private_bounds)]
pub trait StatusT: Sealed {
  /// Unknown properties type.
  type Properties;

  /// `credentialStatus.id` property.
  fn id(&self) -> Option<&Url>;
  /// `credentialStatus.type` property.
  fn type_(&self) -> &[String];
  /// All other properties of the status object.
  fn properties(&self) -> &Self::Properties;
}

#[cfg(test)]
mod tests {
  use identity_core::convert::FromJson;

  use super::*;

  const JSON: &str = include_str!("../../tests/fixtures/status-1.json");

  #[test]
  fn test_from_json() {
    let status: Status = Status::from_json(JSON).unwrap();
    assert_eq!(status.id.as_str(), "https://example.edu/status/24");
    assert_eq!(status.type_, "CredentialStatusList2017");
  }
}
