// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use crate::jose::jwk::CompositeJwk;
use crate::jose::jwk::Jwk;
use core::fmt::Debug;
use core::fmt::Formatter;
use identity_core::convert::BaseEncoding;
use serde::de::Visitor;
use serde::ser::SerializeMap;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value;

use crate::error::Error;
use crate::error::Result;

/// Supported verification method data formats.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum MethodData {
  /// Verification Material in multibase encoding.
  PublicKeyMultibase(String),
  /// Verification Material in base58 encoding.
  PublicKeyBase58(String),
  /// Verification Material in the JSON Web Key format.
  PublicKeyJwk(Jwk),
  /// Verification Material containing two keys in JSON Web Key format, one traditional and one PQ.
  CompositeJwk(CompositeJwk),
  /// Arbitrary verification material.
  #[serde(untagged)]
  Custom(CustomMethodData),
}

impl MethodData {
  /// Creates a new `MethodData` variant with base58-encoded content.
  pub fn new_base58(data: impl AsRef<[u8]>) -> Self {
    Self::PublicKeyBase58(BaseEncoding::encode_base58(&data))
  }

  /// Creates a new `MethodData` variant with [Multibase]-encoded content.
  ///
  /// [Multibase]: https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
  pub fn new_multibase(data: impl AsRef<[u8]>) -> Self {
    Self::PublicKeyMultibase(BaseEncoding::encode_multibase(&data, None))
  }

  /// Creates a new `MethodData` variant from custom data.
  pub fn new_custom(data: impl Into<CustomMethodData>) -> Self {
    Self::Custom(data.into())
  }

  /// Returns a `Vec<u8>` containing the decoded bytes of the `MethodData`.
  ///
  /// This is generally a public key identified by a `MethodType` value.
  ///
  /// # Errors
  /// Decoding will fail if `MethodData` is a [`Jwk`], has invalid content or cannot be
  /// represented as a vector of bytes.
  pub fn try_decode(&self) -> Result<Vec<u8>> {
    match self {
      Self::PublicKeyJwk(_) | Self::Custom(_) | Self::CompositeJwk(_) => Err(Error::InvalidMethodDataTransformation(
        "method data is not base encoded",
      )),
      Self::PublicKeyMultibase(input) => {
        BaseEncoding::decode_multibase(input).map_err(|_| Error::InvalidKeyDataMultibase)
      }
      Self::PublicKeyBase58(input) => BaseEncoding::decode_base58(input).map_err(|_| Error::InvalidKeyDataBase58),
    }
  }

  /// Returns the wrapped `CompositePublicKey` if the format is [`MethodData::CompositePublicKey`].
  pub fn composite_public_key(&self) -> Option<&CompositeJwk> {
    if let Self::CompositeJwk(ref c) = self {
      Some(c)
    } else {
      None
    }
  }

  /// Fallible version of [`Self::composite_public_key`](Self::composite_public_key).
  pub fn try_composite_public_key(&self) -> Result<&CompositeJwk> {
    self.composite_public_key().ok_or(Error::NotCompositePublicKey)
  }

  /// Returns the wrapped `Jwk` if the format is [`MethodData::PublicKeyJwk`].
  pub fn public_key_jwk(&self) -> Option<&Jwk> {
    if let Self::PublicKeyJwk(ref jwk) = self {
      Some(jwk)
    } else {
      None
    }
  }

  /// Fallible version of [`Self::public_key_jwk`](Self::public_key_jwk()).
  pub fn try_public_key_jwk(&self) -> Result<&Jwk> {
    self.public_key_jwk().ok_or(Error::NotPublicKeyJwk)
  }

  /// Returns the custom method data, if any.
  pub fn custom(&self) -> Option<&CustomMethodData> {
    if let Self::Custom(method_data) = self {
      Some(method_data)
    } else {
      None
    }
  }
}

impl Debug for MethodData {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::PublicKeyJwk(inner) => f.write_fmt(format_args!("PublicKeyJwk({inner:#?})")),
      Self::PublicKeyMultibase(inner) => f.write_fmt(format_args!("PublicKeyMultibase({inner})")),
      Self::PublicKeyBase58(inner) => f.write_fmt(format_args!("PublicKeyBase58({inner})")),
      Self::CompositeJwk(inner) => f.write_fmt(format_args!("CompositePublicKey({inner:#?})")),
      Self::Custom(CustomMethodData { name, data }) => f.write_fmt(format_args!("{name}({data})")),
    }
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Custom verification method.
pub struct CustomMethodData {
  /// Verification method's name.
  pub name: String,
  /// Verification method's data.
  pub data: Value,
}

impl Serialize for CustomMethodData {
  fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry(&self.name, &self.data)?;
    map.end()
  }
}

impl<'de> Deserialize<'de> for CustomMethodData {
  fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer.deserialize_map(CustomMethodDataVisitor)
  }
}

struct CustomMethodDataVisitor;

impl<'de> Visitor<'de> for CustomMethodDataVisitor {
  type Value = CustomMethodData;
  fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("\"<any property name>\": <any json value>")
  }
  fn visit_map<A>(self, mut map: A) -> std::prelude::v1::Result<Self::Value, A::Error>
  where
    A: serde::de::MapAccess<'de>,
  {
    let mut custom_method_data = CustomMethodData {
      name: String::default(),
      data: Value::Null,
    };
    while let Some((name, data)) = map.next_entry::<String, Value>()? {
      custom_method_data = CustomMethodData { name, data };
    }

    Ok(custom_method_data)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn serialize_custom_method_data() {
    let custom = MethodData::Custom(CustomMethodData {
      name: "anArbitraryMethod".to_owned(),
      data: json!({"a": 1, "b": 2}),
    });
    let target_str = json!({
      "anArbitraryMethod": {"a": 1, "b": 2},
    })
    .to_string();
    assert_eq!(serde_json::to_string(&custom).unwrap(), target_str);
  }
  #[test]
  fn deserialize_custom_method_data() {
    let inner_data = json!({
        "firstCustomField": "a random string",
        "secondCustomField": 420,
    });
    let json_method_data = json!({
      "myCustomVerificationMethod": &inner_data,
    });
    let custom = serde_json::from_value::<MethodData>(json_method_data.clone()).unwrap();
    let target_method_data = MethodData::Custom(CustomMethodData {
      name: "myCustomVerificationMethod".to_owned(),
      data: inner_data,
    });
    assert_eq!(custom, target_method_data);
  }
}
