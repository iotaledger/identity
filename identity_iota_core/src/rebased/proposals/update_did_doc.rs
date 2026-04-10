// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::rebased::iota::package::identity_package_id;
use crate::rebased::iota::package::identity_package_id_blocking;
use std::marker::PhantomData;

use crate::rebased::iota::move_calls;
use crate::rebased::migration::ControllerToken;
use crate::IotaDocument;
use async_trait::async_trait;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_type::MoveType;
use product_core::move_type::UnknownTypeForNetwork;
use product_core::network::Network;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::migration::OnChainIdentity;
use crate::rebased::migration::Proposal;
use crate::rebased::Error;

use super::CreateProposal;
use super::ExecuteProposal;
use super::ProposalT;

/// Proposal's action for updating a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "UpdateValue::<Option<Vec<u8>>>", from = "UpdateValue::<Option<Vec<u8>>>")]
pub struct UpdateDidDocument(Option<Vec<u8>>);

impl MoveType for UpdateDidDocument {
  fn move_type(network: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    let package = match network {
      Network::Mainnet => "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08",
      Network::Testnet => "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
      Network::Devnet => "0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103",
      _ => identity_package_id_blocking(network)
        .map_err(|_| UnknownTypeForNetwork::new("Send", network))?
        .to_string()
        .as_str(),
    };

    Ok(
      format!("{package}::update_value_proposal::UpdateValue<0x1::option::Option<vector<u8>>>")
        .parse()
        .expect("valid TypeTag"),
    )
  }
}

impl UpdateDidDocument {
  /// Creates a new [`UpdateDidDocument`] action.
  pub fn new(document: IotaDocument) -> Self {
    Self(Some(document.pack().expect("a valid IotaDocument is packable")))
  }

  /// Creates a new [`UpdateDidDocument`] action to deactivate the DID Document.
  pub fn deactivate() -> Self {
    Self(Some(vec![]))
  }

  /// Creates a new [`UpdateDidDocument`] action to delete the DID Document.
  pub fn delete() -> Self {
    Self(None)
  }

  /// Returns the serialized DID document bytes.
  pub fn did_document_bytes(&self) -> Option<&[u8]> {
    self.0.as_deref()
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl ProposalT for Proposal<UpdateDidDocument> {
  type Action = UpdateDidDocument;
  type Output = ();

  async fn create<'i>(
    action: Self::Action,
    expiration: Option<u64>,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<CreateProposal<'i, Self::Action>>, Error> {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }
    if identity.has_deleted_did() {
      return Err(Error::Identity("cannot update a deleted DID Document".into()));
    }

    let package = identity_package_id(client.network()).await?;
    let sender_vp = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("controller exists");
    let chained_execution = sender_vp >= identity.threshold();
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());

    move_calls::identity::propose_update(
      &mut ptb,
      identity.id(),
      controller_token,
      action.0.as_deref(),
      expiration,
      package,
    );

    Ok(OperationBuilder::new(CreateProposal {
      identity,
      tx: ptb,
      chained_execution,
      _action: PhantomData,
    }))
  }

  async fn into_tx<'i>(
    self,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<ExecuteProposal<'i, Self::Action>>, Error> {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }
    if identity.has_deleted_did() {
      return Err(Error::Identity("cannot update a deleted DID Document".into()));
    }

    let proposal_id = self.id();
    let package = identity_package_id(client.network()).await?;
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());

    // We need to check the capability again here, as the proposal could have been created with a token that has since
    // been revoked.

    move_calls::identity::execute_update(&mut ptb, identity.id(), controller_token, proposal_id, package);

    Ok(OperationBuilder::new(ExecuteProposal {
      identity,
      tx: ptb,
      _action: PhantomData,
    }))
  }

  fn parse_tx_effects(_tx_response: &TransactionEffects) -> Result<Self::Output, Error> {
    Ok(())
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateValue<V> {
  new_value: V,
}

impl From<UpdateDidDocument> for UpdateValue<Option<Vec<u8>>> {
  fn from(value: UpdateDidDocument) -> Self {
    Self { new_value: value.0 }
  }
}

impl From<UpdateValue<Option<Vec<u8>>>> for UpdateDidDocument {
  fn from(value: UpdateValue<Option<Vec<u8>>>) -> Self {
    UpdateDidDocument(value.new_value)
  }
}
