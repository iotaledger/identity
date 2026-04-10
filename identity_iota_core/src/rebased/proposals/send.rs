// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::rebased::iota::package::identity_package_id;
use crate::rebased::iota::package::identity_package_id_blocking;
use async_trait::async_trait;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_type::MoveType;
use product_core::move_type::UnknownTypeForNetwork;
use product_core::network::Network;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::iota::move_calls;
use crate::rebased::migration::ControllerToken;
use crate::rebased::migration::OnChainIdentity;
use crate::rebased::Error;

use super::CreateProposal;
use super::ExecuteProposal;
use super::Proposal;
use super::ProposalBuilder;
use super::ProposalT;

/// An action used to transfer [`crate::migration::OnChainIdentity`]-owned assets to other addresses.
#[derive(Debug, Clone, Deserialize, Default, Serialize)]
#[serde(from = "IotaSendAction", into = "IotaSendAction")]
pub struct SendAction(Vec<(ObjectId, Address)>);

impl MoveType for SendAction {
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

    format!("{package}::transfer_proposal::Send")
      .parse()
      .expect("valid TypeTag")
  }
}

impl SendAction {
  /// Adds to the list of object to send the object with ID `object_id` and send it to address `recipient`.
  pub fn send_object(&mut self, object_id: ObjectId, recipient: Address) {
    self.0.push((object_id, recipient));
  }

  /// Adds multiple objects to the list of objects to send.
  pub fn send_objects<I>(&mut self, objects: I)
  where
    I: IntoIterator<Item = (ObjectId, Address)>,
  {
    objects
      .into_iter()
      .for_each(|(obj_id, recp)| self.send_object(obj_id, recp));
  }
}

impl AsRef<[(ObjectId, Address)]> for SendAction {
  fn as_ref(&self) -> &[(ObjectId, Address)] {
    &self.0
  }
}

impl ProposalBuilder<'_, '_, SendAction> {
  /// Adds one object to the list of objects to send.
  pub fn object(mut self, object_id: ObjectId, recipient: Address) -> Self {
    self.send_object(object_id, recipient);
    self
  }

  /// Adds multiple objects to the list of objects to send.
  pub fn objects<I>(mut self, objects: I) -> Self
  where
    I: IntoIterator<Item = (ObjectId, Address)>,
  {
    self.send_objects(objects);
    self
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl ProposalT for Proposal<SendAction> {
  type Action = SendAction;
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
    let package = identity_package_id(client.network()).await?;
    let can_execute = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("controller_cap is for this identity")
      >= identity.threshold();
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());
    if can_execute {
      // Construct a list of `(ObjectId, TypeTag)` from the list of objects to send.
      let object_type_list = super::object_type_for_ids(client, action.0.iter().map(|(id, _)| *id)).await?;
      move_calls::identity::create_and_execute_send(
        &mut ptb,
        identity.id(),
        controller_token,
        action.0,
        expiration,
        object_type_list,
        package,
        client.network(),
      )
    } else {
      move_calls::identity::propose_send(
        &mut ptb,
        identity.id(),
        controller_token,
        action.0,
        expiration,
        package,
        client.network(),
      )
    }

    Ok(OperationBuilder::new(CreateProposal {
      identity,
      tx: ptb,
      chained_execution: can_execute,
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

    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());
    let proposal_id = self.id();

    // Construct a list of `(ObjectRef, TypeTag)` from the list of objects to send.
    let object_type_list =
      super::object_type_for_ids(client, self.into_action().0.into_iter().map(|(id, _)| *id)).await?;
    let package = identity_package_id(client.network()).await?;

    move_calls::identity::execute_send(
      &mut ptb,
      identity.id(),
      controller_token,
      proposal_id,
      object_type_list,
      package,
      client.network(),
    );

    Ok(OperationBuilder::new(ExecuteProposal {
      identity,
      tx: ptb,
      _action: PhantomData,
    }))
  }

  fn parse_tx_effects(_effects: &TransactionEffects) -> Result<Self::Output, Error> {
    Ok(())
  }
}

#[derive(Debug, Deserialize, Serialize)]
struct IotaSendAction {
  objects: Vec<ObjectId>,
  recipients: Vec<Address>,
}

impl From<IotaSendAction> for SendAction {
  fn from(value: IotaSendAction) -> Self {
    let IotaSendAction { objects, recipients } = value;
    let transfer_map = objects.into_iter().zip(recipients).collect();
    SendAction(transfer_map)
  }
}

impl From<SendAction> for IotaSendAction {
  fn from(action: SendAction) -> Self {
    let (objects, recipients) = action.0.into_iter().unzip();
    Self { objects, recipients }
  }
}
