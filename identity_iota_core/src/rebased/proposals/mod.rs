// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod access_sub_identity;
mod borrow;
mod config_change;
mod controller;
mod send;
mod update_did_doc;
mod upgrade;

use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;

use crate::rebased::iota::move_calls::identity::ControllerTokenArg;
use crate::rebased::migration::get_identity;
pub use access_sub_identity::*;
use async_trait::async_trait;
pub use borrow::*;
pub use config_change::*;
pub use controller::*;
use futures::StreamExt;
use iota_sdk::graphql_client::query_types::ObjectFilter;
use iota_sdk::graphql_client::Client as IotaClient;
use iota_sdk::graphql_client::Direction;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_type::MoveType;
use product_core::operation::Operation;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
use serde::Deserialize;

pub use send::*;
use serde::de::DeserializeOwned;
pub use update_did_doc::*;
pub use upgrade::*;

use super::iota::package::identity_package_id;
use crate::rebased::migration::OnChainIdentity;
use crate::rebased::migration::Proposal;
use crate::rebased::Error;

use super::migration::ControllerToken;

pub trait ProtoOperation {
  type Input;
  type Operation: Operation;

  fn with(self, input: Self::Input) -> Self::Operation;
}

impl<O> ProtoOperation for OperationBuilder<O>
where
  O: Operation,
{
  type Input = ();
  type Operation = O;

  fn with(self, _input: Self::Input) -> Self::Operation {
    self.into()
  }
}

/// Interface that allows the creation and execution of an [`OnChainIdentity`]'s [`Proposal`]s.
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
pub trait ProposalT: Sized {
  /// The [`Proposal`] action's type.
  type Action;
  /// The output of the [`Proposal`]
  type Output;

  /// Creates a new [`Proposal`] with the provided action and expiration.
  async fn create<'i>(
    action: Self::Action,
    expiration: Option<u64>,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<CreateProposal<'i, Self::Action>>, Error>;

  /// Converts the [`Proposal`] into a transaction that can be executed.
  async fn into_tx<'i>(
    self,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &impl ProductClient,
  ) -> Result<impl ProtoOperation, Error>;

  /// Parses the transaction's effects and returns the output of the [`Proposal`].
  fn parse_tx_effects(effects: &TransactionEffects) -> Result<Self::Output, Error>;
}

impl<A: MoveType> Proposal<A> {
  /// Creates a new [ApproveProposal] for the provided [`Proposal`].
  pub fn approve<'i>(
    &mut self,
    identity: &'i OnChainIdentity,
    controller_token: &ControllerToken,
  ) -> Result<OperationBuilder<ApproveProposal<'_, 'i, A>>, Error> {
    ApproveProposal::new(self, identity, controller_token).map(OperationBuilder::new)
  }
}

/// A builder for creating a [`Proposal`].
#[derive(Debug)]
pub struct ProposalBuilder<'i, 'c, A> {
  identity: &'i mut OnChainIdentity,
  controller_token: &'c ControllerToken,
  expiration: Option<u64>,
  action: A,
}

impl<A> Deref for ProposalBuilder<'_, '_, A> {
  type Target = A;
  fn deref(&self) -> &Self::Target {
    &self.action
  }
}

impl<A> DerefMut for ProposalBuilder<'_, '_, A> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.action
  }
}

impl<'i, 'c, A> ProposalBuilder<'i, 'c, A> {
  pub(crate) fn new(identity: &'i mut OnChainIdentity, controller_token: &'c ControllerToken, action: A) -> Self {
    Self {
      identity,
      controller_token,
      expiration: None,
      action,
    }
  }

  /// Sets the expiration epoch for the [`Proposal`].
  pub fn expiration_epoch(mut self, exp: u64) -> Self {
    self.expiration = Some(exp);
    self
  }
}

impl<'i, 'c, A> ProposalBuilder<'i, 'c, A>
where
  Proposal<A>: ProposalT<Action = A>,
{
  /// Creates a [`Proposal`] with the provided arguments. If `forbid_chained_execution` is set to `true`,
  /// the [`Proposal`] won't be executed even if creator alone has enough voting power.
  pub async fn finish(self, client: &impl ProductClient) -> Result<OperationBuilder<CreateProposal<'i, A>>, Error> {
    let Self {
      action,
      expiration,
      controller_token,
      identity,
    } = self;

    Proposal::<A>::create(action, expiration, identity, controller_token, client).await
  }
}

/// The result of attempting to perform an action on an Identity.
/// This action can either be executed right away - when the executing controller
/// has enough voting power to do so - or it can be pending, waiting for other
/// controllers' approvals.
#[derive(Debug)]
pub enum ProposedTxResult<P, T> {
  /// A proposed operation that has yet to be executed.
  Pending(P),
  /// Execute proposal output.
  Executed(T),
}

/// The result of creating a [`Proposal`]. When a [`Proposal`] is executed
/// in the same transaction as its creation, a [`ProposalResult::Executed`] is
/// returned. [`ProposalResult::Pending`] otherwise.
#[allow(type_alias_bounds)]
pub type ProposalResult<P: ProposalT> = ProposedTxResult<P, P::Output>;

/// A transaction to create a [`Proposal`].
#[derive(Debug)]
pub struct CreateProposal<'i, A> {
  identity: &'i mut OnChainIdentity,
  chained_execution: bool,
  tx: TransactionBuilder<IotaClient>,
  _action: PhantomData<A>,
}

impl<A> Operation for CreateProposal<'_, A>
where
  Proposal<A>: ProposalT<Action = A> + DeserializeOwned,
  A: Send + Sync,
{
  type Output = ProposalResult<Proposal<A>>;
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    tx_builder: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    Ok(self.tx.clone())
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = effects.status().error() {
      return Err(tx_error.into());
    }

    // Identity has been changed regardless of whether the proposal has been executed
    // or simply created. Refetch it, to sync it with its on-chain state.
    *self.identity = get_identity(client, self.identity.id())
      .await?
      .ok_or_else(|| Error::Identity(format!("identity {} cannot be found", self.identity.id())))?;

    if self.chained_execution {
      // The proposal has been created and executed right-away. Parse its effects.
      Proposal::<A>::parse_tx_effects(effects).map(ProposalResult::Executed)
    } else {
      // 2 objects are created, one is the Bag's Field and the other is our Proposal. Proposal is not owned by the bag,
      // but the field is.
      let proposals_bag_id = self.identity.multicontroller().proposals_bag_id();
      let proposal_id = effects
        .as_v1()
        .changed_objects
        .iter()
        .find(|obj_ref| obj_ref.output_state.object_owner().as_object_opt() != Some(proposals_bag_id))
        .expect("tx was successful")
        .object_id;

      let proposal = client
        .move_object_contents(proposal_id, None)
        .await
        .map_err(|e| Error::RpcError(e.to_string()))?
        .and_then(|proposal_json| serde_json::from_value::<Proposal<A>>(proposal_json).ok())
        .map(ProposalResult::Pending)
        .expect("tx was successful");

      Ok(proposal)
    }
  }
}

/// A transaction to execute a [`Proposal`].
#[derive(Debug)]
pub struct ExecuteProposal<'i, A> {
  tx: TransactionBuilder<IotaClient>,
  identity: &'i mut OnChainIdentity,
  _action: PhantomData<A>,
}

impl<A> Operation for ExecuteProposal<'_, A>
where
  Proposal<A>: ProposalT<Action = A>,
  A: Send + Sync,
{
  type Output = <Proposal<A> as ProposalT>::Output;
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    tx_builder: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    Ok(self.tx.clone())
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    let Self { identity, .. } = self;

    if let Some(tx_error) = tx_effects.status().error() {
      return Err(tx_error.into());
    }

    *identity = get_identity(client, identity.id())
      .await?
      .ok_or_else(|| Error::Identity(format!("identity {} cannot be found", identity.id())))?;

    Proposal::<A>::parse_tx_effects(tx_effects)
  }
}

/// A transaction to approve a [`Proposal`].
#[derive(Debug)]
pub struct ApproveProposal<'p, 'i, A> {
  proposal: &'p mut Proposal<A>,
  identity: &'i OnChainIdentity,
  controller_token: ControllerToken,
}

impl<'p, 'i, A> ApproveProposal<'p, 'i, A> {
  /// Creates a new [Transaction] to approve `identity`'s `proposal`.
  pub fn new(
    proposal: &'p mut Proposal<A>,
    identity: &'i OnChainIdentity,
    controller_token: &ControllerToken,
  ) -> Result<Self, Error> {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }

    Ok(Self {
      proposal,
      identity,
      controller_token: controller_token.clone(),
    })
  }
}

impl<A> Operation for ApproveProposal<'_, '_, A>
where
  A: MoveType + Send + Sync,
{
  type Output = ();
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    mut ptb: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    let package = identity_package_id(client.network()).await?;
    let identity = ptb.apply_argument(self.identity.id());
    let cap = ControllerTokenArg::from_token(&self.controller_token, &mut ptb, package);
    let proposal_id = ptb.apply_argument(self.proposal.id());
    let proposal_type = A::move_type(client.network())?;

    ptb
      .move_call(package, "identity", "approve_proposal")
      .type_tags(proposal_type)
      .arguments([identity, cap.arg(), proposal_id]);

    cap.put_back(&mut ptb, package);

    ptb
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = tx_effects.status().error() {
      return Err(tx_error.into());
    }

    let vp = self
      .identity
      .controller_voting_power(self.controller_token.controller_id())
      .expect("is identity's controller");
    *self.proposal.votes_mut() = self.proposal.votes() + vp;

    Ok(())
  }
}

/// A transaction that requires user input in order to be executed.
pub struct UserDrivenTx<'i, A> {
  identity: &'i mut OnChainIdentity,
  controller_token: ObjectId,
  action: A,
  proposal_id: ObjectId,
}

impl<'i, A> UserDrivenTx<'i, A> {
  fn new(identity: &'i mut OnChainIdentity, controller_token: ObjectId, action: A, proposal_id: ObjectId) -> Self {
    Self {
      identity,
      controller_token,
      action,
      proposal_id,
    }
  }
}

#[derive(Debug, Deserialize)]
struct ProposalEvent {
  identity: ObjectId,
  controller: ObjectId,
  proposal: ObjectId,
  #[allow(dead_code)]
  executed: bool,
}

pub(self) async fn object_type_for_ids(
  client: &impl ProductClient,
  ids: impl IntoIterator<Item = ObjectId>,
) -> Result<Vec<(ObjectId, TypeTag)>, Error> {
  let filter = ObjectFilter {
    object_ids: Some(ids.collect()),
    ..Default::default()
  };
  client
    .objects_stream(filter, Direction::Forward)
    .filter_map(|res| {
      res
        .ok()
        .map(|obj| (obj.object_id(), obj.object_type().into_struct().into()))
    })
    .collect()
    .await
}
