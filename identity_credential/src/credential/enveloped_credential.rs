// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::ops::Deref;

use identity_core::common::Context;
use identity_core::common::DataUrl;
use identity_core::common::InvalidDataUrl;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;

use crate::credential::credential_v2::deserialize_vc2_0_context;
use crate::credential::CredentialV2;

const ENVELOPED_VC_TYPE: &str = "EnvelopedVerifiableCredential";

fn deserialize_enveloped_vc_type<'de, D>(deserializer: D) -> Result<Box<str>, D::Error>
where
  D: Deserializer<'de>,
{
  use serde::de::Error;
  use serde::de::Unexpected;

  let str = <&'de str>::deserialize(deserializer)?;
  if str == ENVELOPED_VC_TYPE {
    Ok(ENVELOPED_VC_TYPE.to_owned().into_boxed_str())
  } else {
    Err(Error::invalid_value(
      Unexpected::Str(str),
      &format!("\"{}\"", ENVELOPED_VC_TYPE).as_str(),
    ))
  }
}

/// An Enveloped Verifiable Credential as defined in
/// [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EnvelopedVc {
  /// The set of JSON-LD contexts that apply to this object.
  #[serde(rename = "@context", deserialize_with = "deserialize_vc2_0_context")]
  context: OneOrMany<Context>,
  /// [VcDataUrl] containing the actual Verifiable Credential.
  pub id: VcDataUrl,
  /// The type of this object, which is always "EnvelopedVerifiableCredential".
  #[serde(rename = "type", deserialize_with = "deserialize_enveloped_vc_type")]
  type_: Box<str>,
  /// Additional properties.
  #[serde(flatten)]
  pub properties: Object,
}

impl EnvelopedVc {
  /// Constructs a new [EnvelopedVc] with the given `id`.
  pub fn new(id: VcDataUrl) -> Self {
    Self {
      context: OneOrMany::One(CredentialV2::<()>::base_context().clone()),
      id,
      type_: ENVELOPED_VC_TYPE.to_owned().into_boxed_str(),
      properties: Object::default(),
    }
  }

  /// The value of this object's "type" property, which is always "EnvelopedVerifiableCredential".
  pub fn type_(&self) -> &str {
    &self.type_
  }

  /// The value of this object's "@context" property.
  pub fn context(&self) -> &[Context] {
    self.context.as_slice()
  }

  /// Sets the value of this object's "@context" property.
  /// # Notes
  /// This method will always ensure the very first context is "https://www.w3.org/ns/credentials/v2"
  /// and that no duplicated contexts are present.
  /// # Example
  /// ```
  /// # use identity_credential::credential::{EnvelopedVc, VcDataUrl};
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut enveloped_vc = EnvelopedVc::new(VcDataUrl::parse("data:application/vc,QzVjV...RMjU")?);
  /// enveloped_vc.set_context(vec![]);
  /// assert_eq!(
  ///   enveloped_vc.context(),
  ///   &["https://www.w3.org/ns/credentials/v2"]
  /// );
  /// # Ok(())
  /// # }
  /// ```
  pub fn set_context(&mut self, contexts: impl IntoIterator<Item = Context>) {
    use itertools::Itertools;

    let contexts = std::iter::once(CredentialV2::<()>::base_context().clone())
      .chain(contexts)
      .unique()
      .collect_vec();

    self.context = contexts.into();
  }
}

/// A [DataUrl] encoding a VC within it (recognized through the use of the "application/vc" media type)
/// for use as the `id` of an [EnvelopedVc].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct VcDataUrl(DataUrl);

impl VcDataUrl {
  /// Parses the given input string as a [VcDataUrl].
  /// # Example
  /// ```
  /// # use identity_credential::credential::{VcDataUrl, VcDataUrlParsingError};
  /// # fn main() -> Result<(), VcDataUrlParsingError> {
  /// let plaintext_vc_data_url = VcDataUrl::parse("data:application/vc;base64,eyVjV...RMjU")?;
  /// let jwt_vc_data_url = VcDataUrl::parse("data:application/vc+jwt,eyJraWQiO...zhwGfQ")?;
  /// let sd_jwt_vc_data_url = VcDataUrl::parse("data:application/vc+sd-jwt,QzVjV...RMjU")?;
  /// #   Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, VcDataUrlParsingError> {
    let data_url = DataUrl::parse(input)?;

    if data_url.media_type().starts_with("application/vc") {
      Ok(Self(data_url))
    } else {
      Err(VcDataUrlParsingError::InvalidMediaType(InvalidMediaType {
        got: data_url.media_type().to_string(),
      }))
    }
  }
}

impl Deref for VcDataUrl {
  type Target = DataUrl;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl TryFrom<DataUrl> for VcDataUrl {
  type Error = InvalidMediaType;

  fn try_from(value: DataUrl) -> Result<Self, Self::Error> {
    if value.media_type().starts_with("application/vc") {
      Ok(Self(value))
    } else {
      Err(InvalidMediaType {
        got: value.media_type().to_string(),
      })
    }
  }
}

impl From<VcDataUrl> for DataUrl {
  fn from(value: VcDataUrl) -> Self {
    value.0
  }
}

impl Display for VcDataUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// Errors that can occur when parsing a [VcDataUrl].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VcDataUrlParsingError {
  /// The input string did not conform to the [DataUrl] format.
  #[error(transparent)]
  NotADataUrl(#[from] InvalidDataUrl),
  /// The [DataUrl] does not have a valid media type for a VC.
  #[error(transparent)]
  InvalidMediaType(#[from] InvalidMediaType),
}

/// Error indicating that a [DataUrl] does not have a valid media type for a VC.
#[derive(Debug, thiserror::Error)]
#[error("invalid media type `{got}`: expected `application/vc` or related media type")]
#[non_exhaustive]
pub struct InvalidMediaType {
  /// The invalid media type that was found.
  pub got: String,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn serde_roundtrip() {
    let vc_data_url = VcDataUrl::parse("data:application/vc,QzVjV...RMjU").unwrap();
    let enveloped_vc = EnvelopedVc::new(vc_data_url.clone());

    let serialized = serde_json::to_string(&enveloped_vc).unwrap();
    let deserialized: EnvelopedVc = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.type_(), ENVELOPED_VC_TYPE);
    assert_eq!(deserialized.id, vc_data_url);
    assert_eq!(deserialized.context(), &[CredentialV2::<()>::base_context().clone()]);
  }

  #[test]
  fn deserialization_of_spec_example() {
    let json = r#"
{
  "@context": "https://www.w3.org/ns/credentials/v2",
  "id": "data:application/vc+sd-jwt,QzVjV...RMjU",
  "type": "EnvelopedVerifiableCredential"
}
    "#;

    let _enveloped_vc: EnvelopedVc = serde_json::from_str(json).unwrap();
  }

  #[test]
  fn deserialization_of_invalid_type_fails() {
    let err = deserialize_enveloped_vc_type(&mut serde_json::Deserializer::from_str("\"InvalidType\"")).unwrap_err();
    assert_eq!(
      err.to_string(),
      "invalid value: string \"InvalidType\", expected \"EnvelopedVerifiableCredential\""
    );
  }
}
