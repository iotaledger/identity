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

use crate::rebased::iota::move_calls;
use crate::rebased::migration::get_identity;
pub use access_sub_identity::*;
use async_trait::async_trait;
pub use borrow::*;
pub use config_change::*;
pub use controller::*;
use iota_interaction::rpc_types::IotaExecutionStatus;
use iota_interaction::rpc_types::IotaObjectData;
use iota_interaction::rpc_types::IotaObjectDataOptions;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI as _;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::base_types::ObjectRef;
use iota_interaction::types::base_types::ObjectType;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::types::TypeTag;
use iota_interaction::IotaClientTrait;
use iota_interaction::OptionalSend;
use iota_interaction::OptionalSync;
use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use product_common::transaction::ProtoTransaction;
use serde::Deserialize;
use tokio::sync::OnceCell;

pub use send::*;
use serde::de::DeserializeOwned;
pub use update_did_doc::*;
pub use upgrade::*;

use super::iota::package::identity_package_id;
use crate::rebased::migration::OnChainIdentity;
use crate::rebased::migration::Proposal;
use crate::rebased::Error;
use iota_interaction::MoveType;

use super::migration::ControllerToken;

/// Interface that allows the creation and execution of an [`OnChainIdentity`]'s [`Proposal`]s.
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
pub trait ProposalT: Sized {
  /// The [`Proposal`] action's type.
  type Action;
  /// The output of the [`Proposal`]
  type Output;

  /// Creates a new [`Proposal`] with the provided action and expiration.
  async fn create<'i, C>(
    action: Self::Action,
    expiration: Option<u64>,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &C,
  ) -> Result<TransactionBuilder<CreateProposal<'i, Self::Action>>, Error>
  where
    C: CoreClientReadOnly + OptionalSync;

  /// Converts the [`Proposal`] into a transaction that can be executed.
  async fn into_tx<'i, C>(
    self,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &C,
  ) -> Result<impl ProtoTransaction, Error>
  where
    C: CoreClientReadOnly + OptionalSync;

  /// Parses the transaction's effects and returns the output of the [`Proposal`].
  fn parse_tx_effects(effects: &IotaTransactionBlockEffects) -> Result<Self::Output, Error>;
}

impl<A> Proposal<A>
where
  Proposal<A>: ProposalT<Action = A>,
  A: MoveType + OptionalSend + OptionalSync,
{
  /// Creates a new [ApproveProposal] for the provided [`Proposal`].
  pub fn approve<'i>(
    &mut self,
    identity: &'i OnChainIdentity,
    controller_token: &ControllerToken,
  ) -> Result<TransactionBuilder<ApproveProposal<'_, 'i, A>>, Error> {
    ApproveProposal::new(self, identity, controller_token).map(TransactionBuilder::new)
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
  pub async fn finish<C>(self, client: &C) -> Result<TransactionBuilder<CreateProposal<'i, A>>, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
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
  ptb: ProgrammableTransaction,
  _action: PhantomData<A>,
}

impl<A> CreateProposal<'_, A> {
  /// Returns this [Transaction]'s [ProgrammableTransaction].
  pub fn ptb(&self) -> &ProgrammableTransaction {
    &self.ptb
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<A> Transaction for CreateProposal<'_, A>
where
  Proposal<A>: ProposalT<Action = A> + DeserializeOwned,
  A: OptionalSend + OptionalSync,
{
  type Output = ProposalResult<Proposal<A>>;
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, _client: &C) -> Result<ProgrammableTransaction, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    Ok(self.ptb.clone())
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, client: &C) -> Result<Self::Output, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let Self {
      identity,
      chained_execution,
      ..
    } = self;

    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    // Identity has been changed regardless of whether the proposal has been executed
    // or simply created. Refetch it, to sync it with its on-chain state.
    *identity = get_identity(client, identity.id())
      .await?
      .ok_or_else(|| Error::Identity(format!("identity {} cannot be found", identity.id())))?;

    if chained_execution {
      // The proposal has been created and executed right-away. Parse its effects.
      Proposal::<A>::parse_tx_effects(effects).map(ProposalResult::Executed)
    } else {
      // 2 objects are created, one is the Bag's Field and the other is our Proposal. Proposal is not owned by the bag,
      // but the field is.
      let proposals_bag_id = identity.multicontroller().proposals_bag_id();
      let proposal_id = effects
        .created()
        .iter()
        .find(|obj_ref| obj_ref.owner != proposals_bag_id)
        .expect("tx was successful")
        .object_id();

      client
        .get_object_by_id(proposal_id)
        .await
        .map_err(Error::from)
        .map(ProposalResult::Pending)
    }
  }
}

/// A transaction to execute a [`Proposal`].
#[derive(Debug)]
pub struct ExecuteProposal<'i, A> {
  ptb: ProgrammableTransaction,
  identity: &'i mut OnChainIdentity,
  _action: PhantomData<A>,
}

impl<A> ExecuteProposal<'_, A> {
  /// Returns this [Transaction]'s [ProgrammableTransaction].
  pub fn ptb(&self) -> &ProgrammableTransaction {
    &self.ptb
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<A> Transaction for ExecuteProposal<'_, A>
where
  Proposal<A>: ProposalT<Action = A>,
  A: OptionalSend + OptionalSync,
{
  type Output = <Proposal<A> as ProposalT>::Output;
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, _client: &C) -> Result<ProgrammableTransaction, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    Ok(self.ptb.clone())
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, client: &C) -> Result<Self::Output, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let Self { identity, .. } = self;

    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    *identity = get_identity(client, identity.id())
      .await?
      .ok_or_else(|| Error::Identity(format!("identity {} cannot be found", identity.id())))?;

    Proposal::<A>::parse_tx_effects(effects)
  }
}

/// A transaction to approve a [`Proposal`].
#[derive(Debug)]
pub struct ApproveProposal<'p, 'i, A> {
  proposal: &'p mut Proposal<A>,
  identity: &'i OnChainIdentity,
  controller_token: ControllerToken,
  cached_ptb: OnceCell<ProgrammableTransaction>,
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
      cached_ptb: OnceCell::new(),
    })
  }
}
impl<A: MoveType> ApproveProposal<'_, '_, A> {
  async fn make_ptb<C>(&self, client: &C) -> Result<ProgrammableTransaction, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let Self {
      proposal,
      identity,
      controller_token,
      ..
    } = self;
    let identity_ref = client
      .get_object_ref_by_id(identity.id())
      .await?
      .ok_or_else(|| Error::Identity(format!("identity {} doesn't exist", identity.id())))?;
    let controller_cap = controller_token.controller_ref(client).await?;
    let package = identity_package_id(client).await?;

    let tx = move_calls::identity::approve_proposal::<A>(identity_ref.clone(), controller_cap, proposal.id(), package)?;

    Ok(bcs::from_bytes(&tx)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<A> Transaction for ApproveProposal<'_, '_, A>
where
  Proposal<A>: ProposalT<Action = A>,
  A: MoveType + OptionalSend + OptionalSync,
{
  type Output = ();
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }
  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    let proposal_was_updated = effects
      .mutated()
      .iter()
      .any(|obj| obj.object_id() == self.proposal.id());
    if proposal_was_updated {
      let vp = self
        .identity
        .controller_voting_power(self.controller_token.controller_id())
        .expect("is identity's controller");
      *self.proposal.votes_mut() = self.proposal.votes() + vp;
      Ok(())
    } else {
      Err(Error::TransactionUnexpectedResponse(format!(
        "proposal {} wasn't updated in this transaction",
        self.proposal.id()
      )))
    }
  }
}

async fn obj_data_for_id(client: &impl CoreClientReadOnly, obj_id: ObjectID) -> anyhow::Result<IotaObjectData> {
  use anyhow::Context;

  client
    .client_adapter()
    .read_api()
    .get_object_with_options(obj_id, IotaObjectDataOptions::default().with_type().with_owner())
    .await?
    .into_object()
    .context("no iota object in response")
}

async fn obj_ref_and_type_for_id(
  client: &impl CoreClientReadOnly,
  obj_id: ObjectID,
) -> anyhow::Result<(ObjectRef, TypeTag)> {
  let res = obj_data_for_id(client, obj_id).await?;
  let obj_ref = res.object_ref();
  let obj_type = match res.object_type().expect("object type is requested") {
    ObjectType::Package => anyhow::bail!("a move package cannot be sent"),
    ObjectType::Struct(type_) => type_.into(),
  };

  Ok((obj_ref, obj_type))
}

/// A transaction that requires user input in order to be executed.
pub struct UserDrivenTx<'i, A> {
  identity: &'i mut OnChainIdentity,
  controller_token: ObjectID,
  action: A,
  proposal_id: ObjectID,
  cached_ptb: OnceCell<ProgrammableTransaction>,
}

impl<'i, A> UserDrivenTx<'i, A> {
  fn new(identity: &'i mut OnChainIdentity, controller_token: ObjectID, action: A, proposal_id: ObjectID) -> Self {
    Self {
      identity,
      controller_token,
      action,
      proposal_id,
      cached_ptb: OnceCell::new(),
    }
  }
}

#[derive(Debug, Deserialize)]
struct ProposalEvent {
  identity: ObjectID,
  controller: ObjectID,
  proposal: ObjectID,
  #[allow(dead_code)]
  executed: bool,
}
