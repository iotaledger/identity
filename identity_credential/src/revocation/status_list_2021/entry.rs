// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Url;
use serde::de::Error;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Serialize;

use crate::credential::Status;

use super::credential::StatusPurpose;

const CREDENTIAL_STATUS_TYPE: &str = "StatusList2021Entry";

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
    fn visit_str<E: Error>(self, str: &str) -> Result<Self::Value, E> {
      if str == self.0 {
        Ok(self.0)
      } else {
        Err(E::custom(format!("not \"{}\"", self.0)))
      }
    }
  }

  deserializer
    .deserialize_str(ExactStrVisitor(CREDENTIAL_STATUS_TYPE))
    .map(ToOwned::to_owned)
}

/// Serialize usize as string.
fn serialize_number_as_string<S>(value: &usize, serializer: S) -> Result<S::Ok, S::Error>
where
  S: serde::Serializer,
{
  serializer.serialize_str(&value.to_string())
}

/// [StatusList2021Entry](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021entry) implementation.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StatusList2021Entry {
  id: Url,
  #[serde(rename = "type", deserialize_with = "deserialize_status_entry_type")]
  type_: String,
  status_purpose: StatusPurpose,
  #[serde(
    deserialize_with = "serde_aux::prelude::deserialize_number_from_string",
    serialize_with = "serialize_number_as_string"
  )]
  status_list_index: usize,
  status_list_credential: Url,
}

impl TryFrom<&Status> for StatusList2021Entry {
  type Error = serde_json::Error;
  fn try_from(status: &Status) -> Result<Self, Self::Error> {
    let json_status = serde_json::to_value(status)?;
    serde_json::from_value(json_status)
  }
}

impl From<StatusList2021Entry> for Status {
  fn from(entry: StatusList2021Entry) -> Self {
    let json_status = serde_json::to_value(entry).unwrap(); // Safety: shouldn't go out of memory
    serde_json::from_value(json_status).unwrap() // Safety: `StatusList2021Entry` is a credential status
  }
}

impl StatusList2021Entry {
  /// Creates a new [`StatusList2021Entry`].
  pub fn new(status_list: Url, purpose: StatusPurpose, index: usize, id: Option<Url>) -> Self {
    let id = id.unwrap_or_else(|| {
      let mut id = status_list.clone();
      id.set_fragment(None);
      id
    });

    Self {
      id,
      type_: CREDENTIAL_STATUS_TYPE.to_owned(),
      status_purpose: purpose,
      status_list_credential: status_list,
      status_list_index: index,
    }
  }

  /// Returns this `credentialStatus`'s `id`.
  pub const fn id(&self) -> &Url {
    &self.id
  }

  /// Returns the purpose of this entry.
  pub const fn purpose(&self) -> StatusPurpose {
    self.status_purpose
  }

  /// Returns the index of this entry.
  pub const fn index(&self) -> usize {
    self.status_list_index
  }

  /// Returns the referenced [`StatusList2021Credential`]'s [`Url`].
  pub const fn status_list_credential(&self) -> &Url {
    &self.status_list_credential
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const STATUS_LIST_ENTRY_SAMPLE: &str = r#"
{
    "id": "https://example.com/credentials/status/3#94567",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://example.com/credentials/status/3"
}"#;

  #[test]
  fn entry_deserialization_works() {
    let deserialized =
      serde_json::from_str::<StatusList2021Entry>(STATUS_LIST_ENTRY_SAMPLE).expect("Failed to deserialize");
    let status = StatusList2021Entry::new(
      Url::parse("https://example.com/credentials/status/3").unwrap(),
      StatusPurpose::Revocation,
      94567,
      Url::parse("https://example.com/credentials/status/3#94567").ok(),
    );
    assert_eq!(status, deserialized);
  }

  #[test]
  #[should_panic]
  fn deserializing_wrong_status_type_fails() {
    let status = serde_json::json!({
      "id": "https://example.com/credentials/status/3#94567",
      "type": "Whatever2024",
      "statusPurpose": "revocation",
      "statusListIndex": "94567",
      "statusListCredential": "https://example.com/credentials/status/3"
    });
    serde_json::from_value::<StatusList2021Entry>(status).expect("wrong type");
  }

  #[test]
  fn test_status_list_index_serialization() {
    let base_url = Url::parse("https://example.com/credentials/status/3").unwrap();

    let entry1 = StatusList2021Entry::new(base_url.clone(), StatusPurpose::Revocation, 94567, None);
    let json1 = serde_json::to_value(&entry1).unwrap();
    assert_eq!(json1["statusListIndex"], "94567");
  }
}
