// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the [Bitstring Status List v1](https://www.w3.org/TR/vc-bitstring-status-list/) revocation method.

use std::borrow::Cow;

use identity_core::common::Object;
use serde::de::Error as _;
use serde::de::Unexpected;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

pub mod credential;
pub mod entry;

pub use credential::BitstringStatusListCredential;
pub use credential::BitstringStatusListCredentialBuilder;
pub use credential::EntryStatus;
pub use credential::StatusListMut;
pub use credential::CREDENTIAL_TYPE;
pub use entry::BitstringStatusListEntry;
pub use entry::BitstringStatusListEntryBuilder;
pub use entry::ENTRY_TYPE;

/// The purpose of the status list entry, which describes what the bit encodes (e.g. revocation or suspension).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

impl Serialize for StatusPurpose {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

impl<'de> Deserialize<'de> for StatusPurpose {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    String::deserialize(deserializer).map(StatusPurpose::from)
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatusMessage {
  /// Status ID.
  #[serde(
    serialize_with = "serialize_status_message",
    deserialize_with = "deserialize_status_message"
  )]
  pub status: usize,
  /// Status debug information.
  pub message: String,
  /// Arbitrary additional properties.
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

fn serialize_status_message<S>(status: &usize, serializer: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  serializer.serialize_str(&format!("{status:#x}"))
}

fn deserialize_status_message<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
  D: Deserializer<'de>,
{
  let s = String::deserialize(deserializer)?;
  s.strip_prefix("0x")
    .and_then(|digits| usize::from_str_radix(digits, 16).ok())
    .ok_or_else(|| D::Error::invalid_value(Unexpected::Str(&s), &"hex literal"))
}

/// The value a status list entry can be set to, through [`StatusListMut::set_entry`].
#[derive(Debug, Clone)]
pub enum StatusValue<'a> {
  /// The value of a single-bit entry, i.e. of a `revocation`, `suspension` or `refresh` entry.
  Flag(bool),
  /// One of the statuses named by a `message` entry's [`StatusMessage`]s.
  Message(&'a StatusMessage),
}

impl From<bool> for StatusValue<'_> {
  fn from(value: bool) -> Self {
    Self::Flag(value)
  }
}

impl<'a> From<&'a StatusMessage> for StatusValue<'a> {
  fn from(value: &'a StatusMessage) -> Self {
    Self::Message(value)
  }
}

impl<'a> From<StatusValue<'a>> for usize {
  fn from(value: StatusValue<'a>) -> Self {
    match value {
      StatusValue::Flag(b) => b as usize,
      StatusValue::Message(message) => message.status,
    }
  }
}
