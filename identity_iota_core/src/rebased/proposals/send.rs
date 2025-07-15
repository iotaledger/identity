// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::rebased::iota::package::identity_package_id;
use async_trait::async_trait;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::TypeTag;
use iota_interaction::MoveType;
use iota_interaction::OptionalSync;
use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::TransactionBuilder;
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
pub struct SendAction(Vec<(ObjectID, IotaAddress)>);

impl MoveType for SendAction {
  fn move_type(package: ObjectID) -> TypeTag {
    use std::str::FromStr;

    TypeTag::from_str(&format!("{package}::transfer_proposal::Send")).expect("valid move type")
  }
}

impl SendAction {
  /// Adds to the list of object to send the object with ID `object_id` and send it to address `recipient`.
  pub fn send_object(&mut self, object_id: ObjectID, recipient: IotaAddress) {
    self.0.push((object_id, recipient));
  }

  /// Adds multiple objects to the list of objects to send.
  pub fn send_objects<I>(&mut self, objects: I)
  where
    I: IntoIterator<Item = (ObjectID, IotaAddress)>,
  {
    objects
      .into_iter()
      .for_each(|(obj_id, recp)| self.send_object(obj_id, recp));
  }
}

impl AsRef<[(ObjectID, IotaAddress)]> for SendAction {
  fn as_ref(&self) -> &[(ObjectID, IotaAddress)] {
    &self.0
  }
}

impl ProposalBuilder<'_, '_, SendAction> {
  /// Adds one object to the list of objects to send.
  pub fn object(mut self, object_id: ObjectID, recipient: IotaAddress) -> Self {
    self.send_object(object_id, recipient);
    self
  }

  /// Adds multiple objects to the list of objects to send.
  pub fn objects<I>(mut self, objects: I) -> Self
  where
    I: IntoIterator<Item = (ObjectID, IotaAddress)>,
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

  async fn create<'i, C>(
    action: Self::Action,
    expiration: Option<u64>,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &C,
  ) -> Result<TransactionBuilder<CreateProposal<'i, Self::Action>>, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }
    let package = identity_package_id(client).await?;
    let identity_ref = client
      .get_object_ref_by_id(identity.id())
      .await?
      .expect("identity exists on-chain");
    let controller_cap_ref = controller_token.controller_ref(client).await?;
    let can_execute = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("controller_cap is for this identity")
      >= identity.threshold();
    let tx = if can_execute {
      // Construct a list of `(ObjectRef, TypeTag)` from the list of objects to send.
      let object_type_list = {
        let ids = action.0.iter().map(|(obj_id, _rcp)| obj_id);
        let mut object_and_type_list = vec![];
        for obj_id in ids {
          let ref_and_type = super::obj_ref_and_type_for_id(client, *obj_id)
            .await
            .map_err(|e| Error::ObjectLookup(e.to_string()))?;
          object_and_type_list.push(ref_and_type);
        }
        object_and_type_list
      };
      move_calls::identity::create_and_execute_send(
        identity_ref,
        controller_cap_ref,
        action.0,
        expiration,
        object_type_list,
        package,
      )
    } else {
      move_calls::identity::propose_send(identity_ref, controller_cap_ref, action.0, expiration, package)
    }
    .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;
    Ok(TransactionBuilder::new(CreateProposal {
      identity,
      ptb: bcs::from_bytes(&tx)?,
      chained_execution: can_execute,
      _action: PhantomData,
    }))
  }

  async fn into_tx<'i, C>(
    self,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &C,
  ) -> Result<TransactionBuilder<ExecuteProposal<'i, Self::Action>>, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }
    let proposal_id = self.id();
    let identity_ref = client
      .get_object_ref_by_id(identity.id())
      .await?
      .expect("identity exists on-chain");
    let controller_cap_ref = controller_token.controller_ref(client).await?;

    // Construct a list of `(ObjectRef, TypeTag)` from the list of objects to send.
    let object_type_list = {
      let ids = self.into_action().0.into_iter().map(|(obj_id, _rcp)| obj_id);
      let mut object_and_type_list = vec![];
      for obj_id in ids {
        let ref_and_type = super::obj_ref_and_type_for_id(client, obj_id)
          .await
          .map_err(|e| Error::ObjectLookup(e.to_string()))?;
        object_and_type_list.push(ref_and_type);
      }
      object_and_type_list
    };
    let package = identity_package_id(client).await?;

    let tx =
      move_calls::identity::execute_send(identity_ref, controller_cap_ref, proposal_id, object_type_list, package)
        .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;

    Ok(TransactionBuilder::new(ExecuteProposal {
      identity,
      ptb: bcs::from_bytes(&tx)?,
      _action: PhantomData,
    }))
  }

  fn parse_tx_effects(_effects: &IotaTransactionBlockEffects) -> Result<Self::Output, Error> {
    Ok(())
  }
}

#[derive(Debug, Deserialize, Serialize)]
struct IotaSendAction {
  objects: Vec<ObjectID>,
  recipients: Vec<IotaAddress>,
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
