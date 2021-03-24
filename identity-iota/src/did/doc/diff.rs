// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::convert::FromJson;
use identity_core::convert::SerdeInto;
use identity_core::convert::ToJson;
use identity_core::crypto::SetSignature;
use identity_core::crypto::Signature;
use identity_core::crypto::TrySignature;
use identity_core::crypto::TrySignatureMut;
use identity_core::diff::Diff;
use identity_did::diff::DiffDocument;
use identity_did::document::Document as CoreDocument;

use crate::client::Client;
use crate::client::Network;
use crate::did::Document;
use crate::did::DID;
use crate::error::Error;
use crate::error::Result;
use crate::tangle::MessageId;
use crate::tangle::TangleRef;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DocumentDiff {
  pub(crate) did: DID,
  pub(crate) diff: String,
  pub(crate) previous_message_id: MessageId,
  pub(crate) proof: Option<Signature>,
  #[serde(skip)]
  pub(crate) message_id: MessageId,
}

impl DocumentDiff {
  pub fn new(current: &Document, updated: &Document, previous_message_id: MessageId) -> Result<Self> {
    let a: CoreDocument = current.serde_into()?;
    let b: CoreDocument = updated.serde_into()?;
    let diff: String = Diff::diff(&a, &b)?.to_json()?;

    Ok(Self {
      did: current.id().clone(),
      previous_message_id,
      diff,
      proof: None,
      message_id: MessageId::NONE,
    })
  }

  /// Returns the DID of associated DID Document.
  pub fn id(&self) -> &DID {
    &self.did
  }

  /// Returns the raw contents of the DID Document diff.
  pub fn diff(&self) -> &str {
    &*self.diff
  }

  /// Returns the Tangle message id of the previous DID Document diff.
  pub fn previous_message_id(&self) -> &MessageId {
    &self.previous_message_id
  }

  /// Returns a reference to the DID Document proof.
  pub fn proof(&self) -> Option<&Signature> {
    self.proof.as_ref()
  }

  /// Returns a new DID Document which is the result of merging `self`
  /// with the given Document.
  pub fn merge(&self, document: &Document) -> Result<Document> {
    let data: DiffDocument = DiffDocument::from_json(&self.diff)?;
    let core: CoreDocument = document.serde_into()?;
    let this: CoreDocument = Diff::merge(&core, data)?;

    Ok(this.serde_into()?)
  }

  /// Publishes the DID Document diff to the Tangle
  ///
  /// Uses the provided [`client`][``Client``] or a default `Client` based on
  /// the DID network.
  pub async fn publish<'client, C>(&mut self, message_id: &MessageId, client: C) -> Result<()>
  where
    C: Into<Option<&'client Client>>,
  {
    let network: Network = (&self.did).into();

    // Publish the DID Document diff to the Tangle.
    let message: MessageId = match client.into() {
      Some(client) if client.network() == network => client.publish_diff(message_id, self).await?,
      Some(_) => return Err(Error::InvalidDIDNetwork),
      None => Client::from_network(network)?.publish_diff(message_id, self).await?,
    };

    // Update the `self` with the `MessageId` of the bundled transaction.
    self.set_message_id(message);

    Ok(())
  }
}

impl TangleRef for DocumentDiff {
  fn message_id(&self) -> &MessageId {
    &self.message_id
  }

  fn set_message_id(&mut self, message_id: MessageId) {
    self.message_id = message_id;
  }

  fn previous_message_id(&self) -> &MessageId {
    &self.previous_message_id
  }

  fn set_previous_message_id(&mut self, message_id: MessageId) {
    self.previous_message_id = message_id;
  }
}

impl TrySignature for DocumentDiff {
  fn signature(&self) -> Option<&Signature> {
    self.proof.as_ref()
  }
}

impl TrySignatureMut for DocumentDiff {
  fn signature_mut(&mut self) -> Option<&mut Signature> {
    self.proof.as_mut()
  }
}

impl SetSignature for DocumentDiff {
  fn set_signature(&mut self, value: Signature) {
    self.proof = Some(value);
  }
}
