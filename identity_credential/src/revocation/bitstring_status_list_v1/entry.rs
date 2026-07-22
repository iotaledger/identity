// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types for the [`BitstringStatusListEntry`], the `credentialStatus` object embedded in a
//! [Verifiable Credential](crate::credential::Credential) to reference an entry inside a
//! [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/).
//!
//! An entry points at a specific bit (or group of bits) within a hosted status list credential
//! through its [`statusListCredential`](BitstringStatusListEntry::status_list_credential) URL and
//! [`statusListIndex`](BitstringStatusListEntry::status_list_index). The
//! [`statusPurpose`](BitstringStatusListEntry::status_purpose) describes what that bit encodes
//! (e.g. revocation or suspension).
//!
//! Entries are created with the [`BitstringStatusListEntryBuilder`]:
//!
//! ```
//! use identity_core::common::Url;
//! use identity_credential::revocation::bitstring_status_list_v1::entry::BitstringStatusListEntryBuilder;
//! use identity_credential::revocation::bitstring_status_list_v1::entry::StatusPurpose;
//!
//! let entry = BitstringStatusListEntryBuilder::new()
//!   .status_purpose(StatusPurpose::Revocation)
//!   .index(94567)
//!   .credential(Url::parse("https://example.com/credentials/status/3")?)
//!   .build()?;
//!
//! assert_eq!(entry.status_purpose(), &StatusPurpose::Revocation);
//! assert_eq!(entry.status_list_index(), 94567);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::borrow::Cow;
use std::sync::LazyLock;

use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Url;
use serde::de::Error as _;
use serde::de::Unexpected;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value;

/// Value of the `type` property, as defined in [Bitstring Status List Entry](https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry).
pub const TYPE: &str = "BitstringStatusListEntry";
static DEFAULT_STATUS_MESSAGE: LazyLock<[StatusMessage; 2]> =
  LazyLock::new(|| [StatusMessage::new(0, "unset"), StatusMessage::new(1, "set")]);

/// A single entry in a [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/).
/// Used as a value of the `credentialStatus` property in a [Verifiable Credential](crate::credential::Credential).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntry {
  id: Option<Url>,
  #[serde(rename = "type")]
  type_: &'static str,
  status_purpose: StatusPurpose,
  #[serde(serialize_with = "serialize_number_as_string")]
  status_list_index: usize,
  status_list_credential: Url,
  #[serde(skip_serializing_if = "Option::is_none")]
  status_size: Option<usize>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  status_message: Vec<StatusMessage>,
  #[serde(skip_serializing_if = "OneOrMany::is_empty")]
  status_reference: OneOrMany<Url>,
}

impl BitstringStatusListEntry {
  /// Returns the optional `id` of the entry.
  pub fn id(&self) -> Option<&Url> {
    self.id.as_ref()
  }

  /// Returns the `type` of the entry, which is always equal to `BitstringStatusListEntry`.
  pub fn type_(&self) -> &'static str {
    self.type_
  }

  /// Returns the `statusPurpose` of the entry, which describes what the bit encodes (e.g. revocation or suspension).
  pub fn status_purpose(&self) -> &StatusPurpose {
    &self.status_purpose
  }

  /// Returns the `statusListIndex` of the entry, which is the index of the status contained within the status list
  /// credential.
  pub fn status_list_index(&self) -> usize {
    self.status_list_index
  }

  /// Returns the `statusListCredential` of the entry, which is the URL of the status list credential.
  pub fn status_list_credential(&self) -> &Url {
    &self.status_list_credential
  }

  /// Returns the `statusMessage` of the entry, which is an optional array of status messages associated with the status
  /// list entry. When no entries are present, the status list entry is considered to be a simple "set" / "unset"
  /// status.
  pub fn status_message(&self) -> &[StatusMessage] {
    if self.status_message.is_empty() {
      DEFAULT_STATUS_MESSAGE.as_slice()
    } else {
      &self.status_message
    }
  }

  /// Returns the size of this entry's status in bits.
  pub fn status_size(&self) -> usize {
    self.status_message().len().trailing_zeros() as usize
  }

  /// Returns the `statusReference` of the entry, which is an optional array of URLs referencing additional information
  /// about the status.
  pub fn status_reference(&self) -> &[Url] {
    self.status_reference.as_slice()
  }
}

/// The purpose of the status list entry, which describes what the bit encodes (e.g. revocation or suspension).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase", untagged)]
pub enum StatusPurpose {
  /// Used to signal that an updated verifiable credential is available via the credential's refresh service feature.
  /// This status does not invalidate the verifiable credential and is not reversible
  Refresh,
  /// Used to cancel the validity of a verifiable credential. This status is not reversible.
  Revocation,
  /// Used to temporarily prevent the acceptance of a verifiable credential. This status is reversible.
  Suspension,
  /// Used to convey an arbitrary message related to the status of the verifiable credential.
  Message,
  /// Arbitrary status purpose.
  Custom(String),
}

impl StatusPurpose {
  /// Returns the string representation of the status purpose.
  pub fn as_str(&self) -> &str {
    match self {
      StatusPurpose::Refresh => "refresh",
      StatusPurpose::Revocation => "revocation",
      StatusPurpose::Suspension => "suspension",
      StatusPurpose::Message => "message",
      StatusPurpose::Custom(custom) => custom.as_str(),
    }
  }
}

impl<'a, T> From<T> for StatusPurpose
where
  T: Into<Cow<'a, str>>,
{
  fn from(value: T) -> Self {
    let value = value.into();
    match value.as_ref() {
      "refresh" => StatusPurpose::Refresh,
      "revocation" => StatusPurpose::Revocation,
      "suspension" => StatusPurpose::Suspension,
      "message" => StatusPurpose::Message,
      _ => StatusPurpose::Custom(value.to_string()),
    }
  }
}

/// A status message associated with a status list entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct StatusMessage {
  /// Status ID.
  #[serde(serialize_with = "serialize_status_message")]
  pub status: usize,
  /// Status debug information.
  pub message: String,
  /// Arbitrary addicitional properties.
  #[serde(flatten)]
  pub properties: Object,
}

impl StatusMessage {
  /// Returns a new [StatusMessage] with the provided `status` and `message`.
  pub fn new(status: usize, message: impl Into<String>) -> Self {
    Self {
      status,
      message: message.into(),
      properties: Object::new(),
    }
  }
}

/// Builder structure for [BitstringStatusListEntry].
#[derive(Debug, Default)]
pub struct BitstringStatusListEntryBuilder {
  id: Option<Url>,
  status_purpose: Option<StatusPurpose>,
  status_list_index: Option<usize>,
  status_list_credential: Option<Url>,
  status_message: Vec<StatusMessage>,
  status_reference: OneOrMany<Url>,
}

impl BitstringStatusListEntryBuilder {
  /// Returns a new [BitstringStatusListEntryBuilder].
  pub fn new() -> Self {
    Self::default()
  }

  /// Sets the optional ID for this entry.
  pub fn id(mut self, id: Url) -> Self {
    self.id = Some(id);
    self
  }

  /// Sets the purpose for this entry.
  pub fn status_purpose(mut self, status_purpose: impl Into<StatusPurpose>) -> Self {
    self.status_purpose = Some(status_purpose.into());
    self
  }

  /// Sets the index of this entry.
  pub fn index(mut self, status_list_index: usize) -> Self {
    self.status_list_index = Some(status_list_index);
    self
  }

  /// Sets the status list credentials of this entry.
  pub fn credential(mut self, status_list_credential: Url) -> Self {
    self.status_list_credential = Some(status_list_credential);
    self
  }

  /// Sets custom messages of this entry.
  pub fn messages(mut self, messages: impl IntoIterator<Item = StatusMessage>) -> Self {
    self.status_message = messages.into_iter().collect();
    self
  }

  /// Sets the custom messages of this entry.
  /// The messages will be assigned a stutus based on their position, starting from `0x0` to `0x<N - 1>`
  /// where N is the length of the given list.
  pub fn ordered_messages(mut self, messages: impl IntoIterator<Item = String>) -> Self {
    self.status_message = messages
      .into_iter()
      .enumerate()
      .map(|(status, message)| StatusMessage::new(status, message))
      .collect();
    self
  }

  /// Sets the references of this entry.
  pub fn references(mut self, references: impl Into<OneOrMany<Url>>) -> Self {
    self.status_reference = references.into();
    self
  }

  /// Consumes this builder returning a [BitstringStatusListEntry].
  /// ## Errors
  /// - [BuilderError::MissingField] is returned when any of the mandatory properties has not being supplied;
  /// - [BuilderError::InvalidStatusMessagesCount] is returned if an invalid number of messages have been set. Messages
  ///   must be a power of 2 greater than 1.
  pub fn build(self) -> Result<BitstringStatusListEntry, BuilderError> {
    let status_size = match self.status_message.len() {
      0 | 2 => None,
      len if len > 1 && len.is_power_of_two() => Some(len.trailing_zeros() as usize),
      invalid_len => return Err(BuilderError::InvalidStatusMessagesCount(invalid_len)),
    };
    let status_purpose = self.status_purpose.ok_or(BuilderError::MissingField("statusPurpose"))?;
    let status_list_index = self
      .status_list_index
      .ok_or(BuilderError::MissingField("statusListIndex"))?;
    let status_list_credential = self
      .status_list_credential
      .ok_or(BuilderError::MissingField("statusListCredential"))?;

    Ok(BitstringStatusListEntry {
      id: self.id,
      type_: TYPE,
      status_purpose,
      status_list_index,
      status_list_credential,
      status_size,
      status_message: self.status_message,
      status_reference: self.status_reference,
    })
  }
}

/// Error that may be returned by [BitstringStatusListEntryBuilder::build].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuilderError {
  /// A mandatory field was not supplied.
  #[error("missing required field `{0}`")]
  MissingField(&'static str),
  /// Invalid number of messages.
  #[error("invalid number of status messages, expected a power of two, got {0}")]
  InvalidStatusMessagesCount(usize),
}

impl<'de> Deserialize<'de> for StatusMessage {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let mut properties = Object::deserialize(deserializer)?;
    let Value::String(status) = properties
      .remove("status")
      .ok_or_else(|| D::Error::missing_field("status"))?
    else {
      return Err(D::Error::invalid_type(
        Unexpected::Other("non-string"),
        &"hex-encoded integer",
      ));
    };
    let status = usize::from_str_radix(status.trim_start_matches("0x"), 16)
      .map_err(|_| D::Error::invalid_value(Unexpected::Str(&status), &"hex-encoded integer"))?;

    let message = properties
      .remove("message")
      .ok_or_else(|| D::Error::missing_field("message"))?
      .as_str()
      .ok_or_else(|| D::Error::invalid_type(Unexpected::Other("non-string"), &"string"))?
      .to_owned();

    Ok(Self {
      status,
      message,
      properties,
    })
  }
}

fn serialize_status_message<S>(status: &usize, serializer: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  serializer.serialize_str(&format!("{status:#x}"))
}

fn serialize_number_as_string<S>(value: &usize, serializer: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  serializer.serialize_str(&value.to_string())
}

impl<'de> Deserialize<'de> for BitstringStatusListEntry {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Helper<'a> {
      id: Option<Url>,
      #[serde(rename = "type")]
      type_: &'a str,
      status_purpose: StatusPurpose,
      status_list_index: &'a str,
      status_list_credential: Url,
      status_size: Option<usize>,
      #[serde(default)]
      status_message: Vec<StatusMessage>,
      #[serde(default)]
      status_reference: OneOrMany<Url>,
    }

    let helper = Helper::deserialize(deserializer)?;

    // Property type must be equal to "BitstringStatusListEntry".
    if helper.type_ != TYPE {
      return Err(serde::de::Error::invalid_value(Unexpected::Str(helper.type_), &TYPE));
    }

    // When statusSize is present, it must be a positive integer and the number of status messages must be equal to
    // 2^statusSize.
    if let Some(size) = helper.status_size {
      if size == 0 {
        return Err(serde::de::Error::invalid_value(
          Unexpected::Unsigned(size as u64),
          &"positive integer",
        ));
      }

      let expected_message_count = 2_usize.pow(size as u32);
      if helper.status_message.len() != expected_message_count {
        return Err(serde::de::Error::invalid_length(
          helper.status_message.len(),
          &format!("{} status messages for statusSize {}", expected_message_count, size).as_str(),
        ));
      }
    } else {
      // When statusSize is not present, the number of status messages must be equal to 2 or 0 (implicit "set" /
      // "unset").
      if !(helper.status_message.is_empty() || helper.status_message.len() == 2) {
        return Err(serde::de::Error::invalid_length(
          helper.status_message.len(),
          &"2 status messages for statusSize 1",
        ));
      }
    }

    let status_list_index = helper.status_list_index.parse().map_err(|_| {
      serde::de::Error::invalid_value(
        Unexpected::Str(helper.status_list_index),
        &"base 10 integer, expressed as a string",
      )
    })?;

    Ok(Self {
      id: helper.id,
      type_: TYPE,
      status_purpose: helper.status_purpose,
      status_list_index,
      status_list_credential: helper.status_list_credential,
      status_size: helper.status_size,
      status_message: helper.status_message,
      status_reference: helper.status_reference,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const VALID_ENTRY_JSON_1: &str = include_str!("./fixtures/entry-1.json");
  const VALID_ENTRY_JSON_2: &str = include_str!("./fixtures/entry-2.json");
  const VALID_ENTRY_JSON_3: &str = include_str!("./fixtures/entry-3.json");

  #[test]
  fn serialization_and_deserialization_of_valid_status_list_entry_works() {
    for entry_json in [VALID_ENTRY_JSON_1, VALID_ENTRY_JSON_2, VALID_ENTRY_JSON_3] {
      let entry: BitstringStatusListEntry = serde_json::from_str(entry_json).unwrap();
      let serialized_entry = serde_json::to_string(&entry).unwrap();
      let deserialized_entry: BitstringStatusListEntry = serde_json::from_str(&serialized_entry).unwrap();
      assert_eq!(entry, deserialized_entry);
    }
  }

  #[test]
  fn deserialization_of_entry_with_invalid_type_fails() {
    let err =
      serde_json::from_str::<BitstringStatusListEntry>(include_str!("./fixtures/entry-invalid-type.json")).unwrap_err();
    assert_eq!(
      err.to_string(),
      "invalid value: string \"InvalidType\", expected BitstringStatusListEntry"
    );
  }

  #[test]
  fn deserialization_of_entry_with_wrong_number_of_status_messages_fails() {
    let err = serde_json::from_str::<BitstringStatusListEntry>(include_str!(
      "./fixtures/entry-invalid-status-message-count.json"
    ))
    .unwrap_err();
    assert_eq!(
      err.to_string(),
      "invalid length 3, expected 4 status messages for statusSize 2"
    );
  }

  #[test]
  fn building_valid_entry_works() {
    let entry = BitstringStatusListEntryBuilder::new()
      .credential(Url::parse("https://example.com/status/1").unwrap())
      .index(0)
      .status_purpose("revocation")
      .build()
      .unwrap();

    assert_eq!(entry.status_purpose(), &StatusPurpose::Revocation);
    assert_eq!(entry.status_message(), DEFAULT_STATUS_MESSAGE.as_slice());
    assert_eq!(entry.status_size(), 1)
  }

  #[test]
  fn building_without_purpose_fails() {
    let err = BitstringStatusListEntryBuilder::new()
      .credential(Url::parse("https://example.com/status/1").unwrap())
      .index(0)
      .build()
      .unwrap_err();

    std::assert_matches!(err, BuilderError::MissingField("statusPurpose"));
  }

  #[test]
  fn building_without_index_fails() {
    let err = BitstringStatusListEntryBuilder::new()
      .credential(Url::parse("https://example.com/status/1").unwrap())
      .status_purpose(StatusPurpose::Revocation)
      .build()
      .unwrap_err();

    std::assert_matches!(err, BuilderError::MissingField("statusListIndex"));
  }

  #[test]
  fn building_without_credential_fails() {
    let err = BitstringStatusListEntryBuilder::new()
      .index(0)
      .status_purpose(StatusPurpose::Revocation)
      .build()
      .unwrap_err();

    std::assert_matches!(err, BuilderError::MissingField("statusListCredential"));
  }

  #[test]
  fn building_with_wrong_message_count_fails() {
    let err = BitstringStatusListEntryBuilder::new()
      .credential(Url::parse("https://example.com/status/1").unwrap())
      .status_purpose(StatusPurpose::Revocation)
      .index(0)
      .ordered_messages(["revoked".to_owned()])
      .build()
      .unwrap_err();

    std::assert_matches!(err, BuilderError::InvalidStatusMessagesCount(1));
  }
}
