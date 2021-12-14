// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result as FmtResult;

use serde::Deserialize;
use serde::Serialize;

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::convert::FmtJson;
use identity_core::crypto::Signature;

use crate::tangle::MessageId;
use crate::tangle::MessageIdExt;

/// Additional attributes related to an IOTA DID Document.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct IotaDocumentMetadata {
  pub created: Timestamp,
  pub updated: Timestamp,
  #[serde(
    rename = "previousMessageId",
    default = "MessageId::null",
    skip_serializing_if = "MessageIdExt::is_null"
  )]
  pub previous_message_id: MessageId,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proof: Option<Signature>,
  pub properties: Object,
}

impl IotaDocumentMetadata {
  /// Creates a new `IotaDocumentMetadata` with the current system datetime used for `created` and
  /// `updated` timestamps.
  pub fn new() -> Self {
    let now: Timestamp = Timestamp::now_utc();
    Self {
      created: now,
      updated: now,
      previous_message_id: MessageId::null(),
      proof: None,
      properties: Object::default(),
    }
  }
}

impl Default for IotaDocumentMetadata {
  fn default() -> Self {
    Self::new()
  }
}

impl Display for IotaDocumentMetadata {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    self.fmt_json(f)
  }
}
