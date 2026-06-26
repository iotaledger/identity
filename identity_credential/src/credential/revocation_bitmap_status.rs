// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use identity_core::common::Object;
use identity_core::common::Url;
use identity_core::common::Value;
use identity_did::DIDUrl;

use crate::credential::Status;
use crate::error::Error;
use crate::error::Result;

/// Information used to determine the current status of a [`Credential`][crate::credential::Credential]
/// using the `RevocationBitmap2022` specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationBitmapStatus(Status);

impl RevocationBitmapStatus {
  const INDEX_PROPERTY: &'static str = "revocationBitmapIndex";
  /// Type name of the revocation bitmap.
  pub const TYPE: &'static str = "RevocationBitmap2022";

  /// Creates a new `RevocationBitmapStatus`.
  ///
  /// The query of the `id` url is overwritten where "index" is set to `index`.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_credential::credential::RevocationBitmapStatus;
  /// # use identity_did::DIDUrl;
  /// # use identity_did::CoreDID;
  /// let did_url: DIDUrl = DIDUrl::parse("did:method:0xffff#revocation-1").unwrap();
  /// let status: RevocationBitmapStatus = RevocationBitmapStatus::new(did_url, 5);
  /// assert_eq!(
  ///   status.id().unwrap().to_string(),
  ///   "did:method:0xffff?index=5#revocation-1"
  /// );
  /// assert_eq!(status.index().unwrap(), 5);
  /// ```
  pub fn new(mut id: DIDUrl, index: u32) -> Self {
    id.set_query(Some(&format!("index={index}")))
      .expect("the string should be non-empty and a valid URL query");

    let mut object = Object::new();
    object.insert(Self::INDEX_PROPERTY.to_owned(), Value::String(index.to_string()));
    RevocationBitmapStatus(Status::new_with_properties(
      Url::from(id),
      Self::TYPE.to_owned(),
      object,
    ))
  }

  /// Returns the [`DIDUrl`] of the `RevocationBitmapStatus`, which should resolve
  /// to a `RevocationBitmap2022` service in a DID Document.
  pub fn id(&self) -> Result<DIDUrl> {
    DIDUrl::parse(self.0.id.as_str())
      .map_err(|err| Error::InvalidStatus(format!("invalid DID Url '{}': {:?}", self.0.id, err)))
  }

  /// Returns the index of the credential in the issuer's revocation bitmap if it can be decoded.
  pub fn index(&self) -> Result<u32> {
    if let Some(Value::String(index)) = self.0.properties.get(Self::INDEX_PROPERTY) {
      try_index_to_u32(index, Self::INDEX_PROPERTY)
    } else {
      Err(Error::InvalidStatus(format!(
        "expected {} to be an unsigned 32-bit integer expressed as a string",
        Self::INDEX_PROPERTY
      )))
    }
  }
}

impl TryFrom<Status> for RevocationBitmapStatus {
  type Error = Error;

  fn try_from(status: Status) -> Result<Self> {
    if status.type_ != Self::TYPE {
      return Err(Error::InvalidStatus(format!(
        "expected type '{}', got '{}'",
        Self::TYPE,
        status.type_
      )));
    }

    let revocation_bitmap_index: &Value =
      if let Some(revocation_bitmap_index) = status.properties.get(Self::INDEX_PROPERTY) {
        revocation_bitmap_index
      } else {
        return Err(Error::InvalidStatus(format!(
          "missing required property '{}'",
          Self::INDEX_PROPERTY
        )));
      };

    let revocation_bitmap_index: u32 = if let Value::String(index) = revocation_bitmap_index {
      try_index_to_u32(index, Self::INDEX_PROPERTY)?
    } else {
      return Err(Error::InvalidStatus(format!(
        "property '{}' is not a string",
        Self::INDEX_PROPERTY
      )));
    };

    // If the index query is present it must match the revocationBitmapIndex.
    // It is allowed not to be present to maintain backwards-compatibility
    // with an earlier version of the RevocationBitmap spec.
    for pair in status.id.query_pairs() {
      if pair.0 == "index" {
        let index: u32 = try_index_to_u32(pair.1.as_ref(), "value of index query")?;
        if index != revocation_bitmap_index {
          return Err(Error::InvalidStatus(format!(
            "value of index query `{index}` does not match revocationBitmapIndex `{revocation_bitmap_index}`"
          )));
        }
      }
    }

    Ok(Self(status))
  }
}

impl From<RevocationBitmapStatus> for Status {
  fn from(status: RevocationBitmapStatus) -> Self {
    status.0
  }
}

/// Attempts to convert the given index string to a u32.
pub fn try_index_to_u32(index: &str, name: &str) -> Result<u32> {
  u32::from_str(index).map_err(|err| {
    Error::InvalidStatus(format!(
      "{name} cannot be converted to an unsigned, 32-bit integer: {err}",
    ))
  })
}

#[cfg(test)]
mod tests {
  use identity_core::common::Object;
  use identity_core::common::Url;
  use identity_core::common::Value;
  use identity_core::convert::FromJson;
  use identity_did::DIDUrl;

  use crate::Error;

  use super::RevocationBitmapStatus;
  use super::Status;

  #[test]
  fn test_embedded_status_invariants() {
    let url: Url = Url::parse("did:method:0xabcd?index=0#revocation").unwrap();
    let did_url: DIDUrl = DIDUrl::parse(url.clone().into_string()).unwrap();
    let revocation_list_index: u32 = 0;
    let embedded_revocation_status: RevocationBitmapStatus =
      RevocationBitmapStatus::new(did_url, revocation_list_index);

    let object: Object = Object::from([(
      RevocationBitmapStatus::INDEX_PROPERTY.to_owned(),
      Value::String(revocation_list_index.to_string()),
    )]);
    let status: Status =
      Status::new_with_properties(url.clone(), RevocationBitmapStatus::TYPE.to_owned(), object.clone());
    assert_eq!(embedded_revocation_status, status.try_into().unwrap());

    let status_missing_property: Status =
      Status::new_with_properties(url.clone(), RevocationBitmapStatus::TYPE.to_owned(), Object::new());
    assert!(RevocationBitmapStatus::try_from(status_missing_property).is_err());

    let status_wrong_type: Status = Status::new_with_properties(url, "DifferentType".to_owned(), object);
    assert!(RevocationBitmapStatus::try_from(status_wrong_type).is_err());
  }

  #[test]
  fn test_revocation_bitmap_status_index_query() {
    // index is set.
    let did_url: DIDUrl = DIDUrl::parse("did:method:0xffff#rev-0").unwrap();
    let revocation_status: RevocationBitmapStatus = RevocationBitmapStatus::new(did_url, 250);
    assert_eq!(revocation_status.id().unwrap().query().unwrap(), "index=250");

    // index is overwritten.
    let did_url: DIDUrl = DIDUrl::parse("did:method:0xffff?index=300#rev-0").unwrap();
    let revocation_status: RevocationBitmapStatus = RevocationBitmapStatus::new(did_url, 250);
    assert_eq!(revocation_status.id().unwrap().query().unwrap(), "index=250");
  }

  #[test]
  fn test_revocation_bitmap_status_index_requirements() {
    // INVALID: index mismatch in id and property.
    let status: Status = Status::from_json_value(serde_json::json!({
      "id": "did:method:0xffff?index=10#rev-0",
      "type": RevocationBitmapStatus::TYPE,
      RevocationBitmapStatus::INDEX_PROPERTY: "5",
    }))
    .unwrap();

    assert!(matches!(
      RevocationBitmapStatus::try_from(status).unwrap_err(),
      Error::InvalidStatus(_)
    ));

    // VALID: index matches in id and property.
    let status: Status = Status::from_json_value(serde_json::json!({
      "id": "did:method:0xffff?index=5#rev-0",
      "type": RevocationBitmapStatus::TYPE,
      RevocationBitmapStatus::INDEX_PROPERTY: "5",
    }))
    .unwrap();
    assert!(RevocationBitmapStatus::try_from(status).is_ok());

    // VALID: missing index in id is allowed to be backwards-compatible.
    let status: Status = Status::from_json_value(serde_json::json!({
      "id": "did:method:0xffff#rev-0",
      "type": RevocationBitmapStatus::TYPE,
      RevocationBitmapStatus::INDEX_PROPERTY: "5",
    }))
    .unwrap();
    assert!(RevocationBitmapStatus::try_from(status).is_ok());
  }
}
