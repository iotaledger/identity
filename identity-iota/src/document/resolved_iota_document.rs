// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result as FmtResult;

use serde::Deserialize;
use serde::Serialize;

use identity_core::convert::FmtJson;

use crate::did::IotaDID;
use crate::diff::DiffMessage;
use crate::document::IotaDocument;
use crate::error::Result;
use crate::tangle::MessageId;
use crate::tangle::MessageIdExt;
use crate::tangle::TangleRef;

/// An IOTA DID document resolved from the Tangle. Represents an integration chain message possibly
/// merged with one or more diff messages.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ResolvedIotaDocument {
  #[serde(flatten)]
  pub document: IotaDocument,

  /// [`MessageId`] of this integration chain document.
  #[serde(
    rename = "integrationMessageId",
    default = "MessageId::null",
    skip_serializing_if = "MessageIdExt::is_null"
  )]
  pub integration_message_id: MessageId,

  /// [`MessageId`] of the last diff chain message merged into this during resolution, or null.
  #[serde(
    rename = "diffMessageId",
    default = "MessageId::null",
    skip_serializing_if = "MessageIdExt::is_null"
  )]
  pub diff_message_id: MessageId,
  // TODO: version_id
}

impl ResolvedIotaDocument {
  /// Attempts to merge changes from a [`DiffMessage`] into this document and
  /// updates the [`ResolvedIotaDocument::diff_message_id`].
  ///
  /// If merging fails the document remains unmodified, otherwise this represents
  /// the merged document state.
  ///
  /// See [`IotaDocument::merge_diff`].
  ///
  /// # Errors
  ///
  /// Fails if the merge operation or signature verification on the diff fails.
  pub fn merge_diff_message(&mut self, diff_message: &DiffMessage) -> Result<()> {
    self.document.merge_diff(diff_message)?;
    self.diff_message_id = diff_message.message_id;

    Ok(())
  }
}

impl TangleRef for ResolvedIotaDocument {
  fn did(&self) -> &IotaDID {
    self.document.id()
  }

  fn message_id(&self) -> &MessageId {
    &self.integration_message_id
  }

  fn set_message_id(&mut self, message_id: MessageId) {
    self.integration_message_id = message_id;
  }

  fn previous_message_id(&self) -> &MessageId {
    &self.document.metadata.previous_message_id
  }

  fn set_previous_message_id(&mut self, message_id: MessageId) {
    self.document.metadata.previous_message_id = message_id;
  }
}

impl Display for ResolvedIotaDocument {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    self.fmt_json(f)
  }
}

impl From<IotaDocument> for ResolvedIotaDocument {
  fn from(document: IotaDocument) -> Self {
    Self {
      document,
      integration_message_id: MessageId::null(),
      diff_message_id: MessageId::null(),
    }
  }
}
