// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::convert::FmtJson;
use serde::Deserialize;
use serde::Serialize;

/// Additional attributes related to a [`IotaDocument`][crate::IotaDocument].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct IotaDocumentMetadata {
  /// The timestamp of document creation.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub created: Option<Timestamp>,
  /// The timestamp of the last update to the document.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub updated: Option<Timestamp>,
  /// Signals whether the document is deactivated.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub deactivated: Option<bool>,
  #[serde(flatten)]
  properties: Object,
}

impl IotaDocumentMetadata {
  /// Creates a new `IotaDocumentMetadata` with the current system datetime used for `created`
  /// and `updated` timestamps.
  pub fn new() -> Self {
    let now: Timestamp = Timestamp::now_utc();
    Self {
      created: Some(now),
      updated: Some(now),
      deactivated: None,
      properties: Object::default(),
    }
  }

  /// Returns a reference to the custom metadata properties.
  pub fn properties(&self) -> &Object {
    &self.properties
  }

  /// Returns a mutable reference to the custom metadata properties.
  pub fn properties_mut(&mut self) -> &mut Object {
    &mut self.properties
  }
}

impl Default for IotaDocumentMetadata {
  fn default() -> Self {
    Self::new()
  }
}

impl Display for IotaDocumentMetadata {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    self.fmt_json(f)
  }
}
