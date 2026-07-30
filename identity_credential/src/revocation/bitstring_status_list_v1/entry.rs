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
//! use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListEntryBuilder;
//! use identity_credential::revocation::bitstring_status_list_v1::StatusPurpose;
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

use std::sync::LazyLock;

use identity_core::common::OneOrMany;
use identity_core::common::Url;
use serde::de::Unexpected;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value;

use crate::credential::Status;
use crate::revocation::bitstring_status_list_v1::StatusMessage;
use crate::revocation::bitstring_status_list_v1::StatusPurpose;

/// Value of the `type` property, as defined in [Bitstring Status List Entry](https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry).
pub const ENTRY_TYPE: &str = "BitstringStatusListEntry";
/// The greatest `statusSize` an entry may declare: a status is read into a `usize`, and the number
/// of values it can take — `2^statusSize` — must itself be representable.
const MAXIMUM_STATUS_SIZE: usize = usize::BITS as usize - 1;
static DEFAULT_STATUS_MESSAGES: LazyLock<[StatusMessage; 2]> =
  LazyLock::new(|| [StatusMessage::new(0, "unset"), StatusMessage::new(1, "set")]);

/// A single entry in a [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/).
/// Used as a value of the `credentialStatus` property in a [Verifiable Credential](crate::credential::Credential).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntry {
  #[serde(skip_serializing_if = "Option::is_none")]
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
      DEFAULT_STATUS_MESSAGES.as_slice()
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
  /// The messages will be assigned a status based on their position, starting from `0x0` to `0x<N - 1>`
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
      // `statusSize` defaults to 1 and the specification does not require it to accompany
      // `statusMessage`, so a "set" / "unset" entry can leave it out altogether.
      0 | 2 => None,
      // A single message would make for a zero-bit status.
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
      type_: ENTRY_TYPE,
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
  #[error("invalid number of status messages, expected a power of two greater than 1, got {0}")]
  InvalidStatusMessagesCount(usize),
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
    struct Helper {
      id: Option<Url>,
      #[serde(rename = "type")]
      type_: String,
      status_purpose: StatusPurpose,
      status_list_index: String,
      status_list_credential: Url,
      status_size: Option<usize>,
      #[serde(default)]
      status_message: Vec<StatusMessage>,
      #[serde(default)]
      status_reference: OneOrMany<Url>,
    }

    let helper = Helper::deserialize(deserializer)?;

    // Property type must be equal to "BitstringStatusListEntry".
    if helper.type_ != ENTRY_TYPE {
      return Err(serde::de::Error::invalid_value(
        Unexpected::Str(&helper.type_),
        &ENTRY_TYPE,
      ));
    }

    // `statusSize` counts the bits of a status, so it must be a positive integer; the upper bound is
    // ours, as a status is read into a `usize`. It defaults to 1 when absent.
    let status_size = helper.status_size.unwrap_or(1);
    if !(1..=MAXIMUM_STATUS_SIZE).contains(&status_size) {
      return Err(serde::de::Error::invalid_value(
        Unexpected::Unsigned(status_size as u64),
        &format!("integer between 1 and {MAXIMUM_STATUS_SIZE}").as_str(),
      ));
    }

    // `statusMessage` must name each of the `2^statusSize` values a status can take. It may be left
    // out entirely for a single-bit status, which is then an implicit "set" / "unset".
    let expected_message_count = 1usize << status_size;
    let message_count = helper.status_message.len();
    let omitted = message_count == 0 && status_size == 1;
    if message_count != expected_message_count && !omitted {
      return Err(serde::de::Error::invalid_length(
        message_count,
        &format!(
          "{}{expected_message_count} status messages for statusSize {status_size}",
          if status_size == 1 { "0 or " } else { "" },
        )
        .as_str(),
      ));
    }

    let status_list_index = helper.status_list_index.parse().map_err(|_| {
      serde::de::Error::invalid_value(
        Unexpected::Str(&helper.status_list_index),
        &"base 10 integer, expressed as a string",
      )
    })?;

    Ok(Self {
      id: helper.id,
      type_: ENTRY_TYPE,
      status_purpose: helper.status_purpose,
      status_list_index,
      status_list_credential: helper.status_list_credential,
      status_size: helper.status_size,
      status_message: helper.status_message,
      status_reference: helper.status_reference,
    })
  }
}

impl TryFrom<&Status> for BitstringStatusListEntry {
  type Error = serde_json::Error;
  fn try_from(status: &Status) -> Result<Self, Self::Error> {
    serde_json::to_value(status).and_then(serde_json::from_value)
  }
}

impl From<BitstringStatusListEntry> for Status {
  fn from(entry: BitstringStatusListEntry) -> Self {
    // A `Status` must be identified, whereas an entry's `id` is optional; the status list
    // credential it points to identifies it well enough in that case. A `Status` converted to an
    // entry and back therefore gains an `id`.
    let id = entry.id.clone().unwrap_or_else(|| entry.status_list_credential.clone());
    let type_ = entry.type_.to_owned();

    let Value::Object(mut properties) =
      serde_json::to_value(entry).expect("a status list entry serializes to a JSON object")
    else {
      unreachable!("a status list entry serializes to a JSON object")
    };
    // `id` and `type` are named fields of `Status` rather than part of its properties.
    properties.remove("id");
    properties.remove("type");

    Status::new_with_properties(id, type_, properties.into_iter().collect())
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
  fn conversion_to_and_from_a_credential_status_works() {
    for entry_json in [VALID_ENTRY_JSON_1, VALID_ENTRY_JSON_2, VALID_ENTRY_JSON_3] {
      let entry: BitstringStatusListEntry = serde_json::from_str(entry_json).unwrap();

      let status = Status::from(entry.clone());
      assert_eq!(status.type_, ENTRY_TYPE);
      assert_eq!(Some(&status.id), entry.id());
      assert_eq!(BitstringStatusListEntry::try_from(&status).unwrap(), entry);
    }
  }

  #[test]
  fn an_entry_without_an_id_borrows_the_status_list_url_when_converted_to_a_status() {
    let status_list = Url::parse("https://example.com/status/1").unwrap();
    let entry = BitstringStatusListEntryBuilder::new()
      .credential(status_list.clone())
      .index(0)
      .status_purpose(StatusPurpose::Revocation)
      .build()
      .unwrap();
    assert_eq!(entry.id(), None);
    // An id-less entry must not serialize `"id": null`, which is what would reach `Status`.
    assert!(serde_json::to_value(&entry).unwrap().get("id").is_none());

    let status = Status::from(entry);

    assert_eq!(status.id, status_list);
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
    assert_eq!(entry.status_message(), DEFAULT_STATUS_MESSAGES.as_slice());
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
