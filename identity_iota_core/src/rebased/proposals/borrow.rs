// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::marker::PhantomData;

use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;

use crate::rebased::migration::ControllerToken;

use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use product_common::transaction::ProtoTransaction;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::rebased::migration::Proposal;
use crate::rebased::Error;
use async_trait::async_trait;
use iota_interaction::rpc_types::IotaExecutionStatus;
use iota_interaction::rpc_types::IotaObjectData;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI as _;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::types::TypeTag;
use iota_interaction::MoveType;
use iota_interaction::OptionalSync;
use serde::Serialize;

use super::CreateProposal;
use super::OnChainIdentity;
use super::ProposalBuilder;
use super::ProposalT;
use super::UserDrivenTx;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
      use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
      /// Instances of BorrowIntentFnT can be used as user-provided function to describe how
      /// a borrowed assets shall be used.
      pub trait BorrowIntentFnT: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>) {}
      impl<T> BorrowIntentFnT for T where T: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>) {}
      /// Boxed dynamic trait object of {@link BorrowIntentFnT}
      #[allow(unreachable_pub)]
      pub type BorrowIntentFn = Box<dyn BorrowIntentFnT + Send>;
    } else {
      use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
      /// Instances of BorrowIntentFnT can be used as user-provided function to describe how
      /// a borrowed assets shall be used.
      pub trait BorrowIntentFnT: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>) {}
      impl<T> BorrowIntentFnT for T where T: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>) {}
      /// Boxed dynamic trait object of {@link BorrowIntentFnT}
      #[allow(unreachable_pub)]
      pub type BorrowIntentFn = Box<dyn BorrowIntentFnT + Send>;
    }
}

/// Action used to borrow in transaction [OnChainIdentity]'s assets.
#[derive(Deserialize, Serialize)]
pub struct BorrowAction<F = BorrowIntentFn> {
  objects: Vec<ObjectID>,
  #[serde(skip, default = "Mutex::default")]
  intent_fn: Mutex<Option<F>>,
}

impl<F> Default for BorrowAction<F> {
  fn default() -> Self {
    BorrowAction {
      objects: vec![],
      intent_fn: Mutex::new(None),
    }
  }
}

/// A [`BorrowAction`] coupled with a user-provided function to describe how
/// the borrowed assets shall be used.
pub struct BorrowActionWithIntent<F>(BorrowAction<F>)
where
  F: BorrowIntentFnT;

impl MoveType for BorrowAction {
  fn move_type(package: ObjectID) -> TypeTag {
    use std::str::FromStr;

    TypeTag::from_str(&format!("{package}::borrow_proposal::Borrow")).expect("valid move type")
  }
}

impl<F> BorrowAction<F> {
  /// Adds an object to the lists of objects that will be borrowed when executing
  /// this action in a proposal.
  pub fn borrow_object(&mut self, object_id: ObjectID) {
    self.objects.push(object_id);
  }

  /// Adds many objects. See [`BorrowAction::borrow_object`] for more details.
  pub fn borrow_objects<I>(&mut self, objects: I)
  where
    I: IntoIterator<Item = ObjectID>,
  {
    objects.into_iter().for_each(|obj_id| self.borrow_object(obj_id));
  }

  async fn take_intent(&self) -> Option<F> {
    self.intent_fn.lock().await.take()
  }

  fn plug_intent<I>(self, intent_fn: I) -> BorrowActionWithIntent<I>
  where
    I: BorrowIntentFnT,
  {
    let action = BorrowAction {
      objects: self.objects,
      intent_fn: Mutex::new(Some(intent_fn)),
    };
    BorrowActionWithIntent(action)
  }
}

impl<'i, 'c, F> ProposalBuilder<'i, 'c, BorrowAction<F>> {
  /// Adds an object to the list of objects that will be borrowed when executing this action.
  pub fn borrow(mut self, object_id: ObjectID) -> Self {
    self.action.borrow_object(object_id);
    self
  }
  /// Adds many objects. See [`BorrowAction::borrow_object`] for more details.
  pub fn borrow_objects<I>(self, objects: I) -> Self
  where
    I: IntoIterator<Item = ObjectID>,
  {
    objects.into_iter().fold(self, |builder, obj| builder.borrow(obj))
  }

  /// Specifies how to use the borrowed assets. This is only useful if the sender of this
  /// transaction has enough voting power to execute this proposal right-away.
  pub fn with_intent<F1>(self, intent_fn: F1) -> ProposalBuilder<'i, 'c, BorrowAction<F1>>
  where
    F1: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>),
  {
    let ProposalBuilder {
      identity,
      expiration,
      controller_token,
      action: BorrowAction { objects, .. },
    } = self;
    let intent_fn = Mutex::new(Some(intent_fn));
    ProposalBuilder {
      identity,
      expiration,
      controller_token,
      action: BorrowAction { objects, intent_fn },
    }
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<F> ProposalT for Proposal<BorrowAction<F>>
where
  F: BorrowIntentFnT + Send + Sync,
{
  type Action = BorrowAction<F>;
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
      .expect("is a controller of identity")
      >= identity.threshold();
    let maybe_intent_fn = action.intent_fn.into_inner();
    let chained_execution = can_execute && maybe_intent_fn.is_some();
    let tx = if chained_execution {
      // Construct a list of `(ObjectRef, TypeTag)` from the list of objects to send.
      let object_data_list = {
        let mut object_data_list = vec![];
        for obj_id in action.objects {
          let object_data = super::obj_data_for_id(client, obj_id)
            .await
            .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;
          object_data_list.push(object_data);
        }
        object_data_list
      };
      move_calls::identity::create_and_execute_borrow(
        identity_ref,
        controller_cap_ref,
        object_data_list,
        maybe_intent_fn.unwrap(),
        expiration,
        package,
      )
    } else {
      move_calls::identity::propose_borrow(identity_ref, controller_cap_ref, action.objects, expiration, package)
    }
    .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;

    Ok(TransactionBuilder::new(CreateProposal {
      identity,
      ptb: bcs::from_bytes(&tx)?,
      chained_execution,
      _action: PhantomData,
    }))
  }

  async fn into_tx<'i, C>(
    self,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    _client: &C,
  ) -> Result<UserDrivenTx<'i, Self::Action>, Error> {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }

    let proposal_id = self.id();
    let borrow_action = self.into_action();

    Ok(UserDrivenTx::new(
      identity,
      controller_token.id(),
      borrow_action,
      proposal_id,
    ))
  }

  fn parse_tx_effects(effects: &IotaTransactionBlockEffects) -> Result<Self::Output, Error> {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    Ok(())
  }
}

impl<'i, F> UserDrivenTx<'i, BorrowAction<F>> {
  /// Defines how the borrowed assets should be used.
  pub fn with_intent<F1>(self, intent_fn: F1) -> UserDrivenTx<'i, BorrowActionWithIntent<F1>>
  where
    F1: BorrowIntentFnT,
  {
    UserDrivenTx::new(
      self.identity,
      self.controller_token,
      self.action.plug_intent(intent_fn),
      self.proposal_id,
    )
  }
}

impl<'i, F> ProtoTransaction for UserDrivenTx<'i, BorrowAction<F>> {
  type Input = BorrowIntentFn;
  type Tx = TransactionBuilder<UserDrivenTx<'i, BorrowActionWithIntent<BorrowIntentFn>>>;

  fn with(self, input: Self::Input) -> Self::Tx {
    TransactionBuilder::new(self.with_intent(input))
  }
}

impl<F> UserDrivenTx<'_, BorrowActionWithIntent<F>>
where
  F: BorrowIntentFnT,
{
  async fn make_ptb(
    &self,
    client: &(impl CoreClientReadOnly + OptionalSync),
  ) -> Result<ProgrammableTransaction, Error> {
    let Self {
      identity,
      action: borrow_action,
      proposal_id,
      controller_token,
      ..
    } = self;
    let identity_ref = client
      .get_object_ref_by_id(identity.id())
      .await?
      .expect("identity exists on-chain");
    let controller_token = client.get_object_by_id::<ControllerToken>(*controller_token).await?;
    let controller_token_ref = controller_token.controller_ref(client).await?;

    // Construct a list of `(ObjectRef, TypeTag)` from the list of objects to send.
    let object_data_list = {
      let mut object_data_list = vec![];
      for obj_id in borrow_action.0.objects.iter() {
        let object_data = super::obj_data_for_id(client, *obj_id)
          .await
          .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;
        object_data_list.push(object_data);
      }
      object_data_list
    };
    let package = identity_package_id(client).await?;
    let tx = move_calls::identity::execute_borrow(
      identity_ref,
      controller_token_ref,
      *proposal_id,
      object_data_list,
      borrow_action
        .0
        .take_intent()
        .await
        .expect("BorrowActionWithIntent makes sure intent_fn is there"),
      package,
    )
    .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;

    Ok(bcs::from_bytes(&tx)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<F> Transaction for UserDrivenTx<'_, BorrowActionWithIntent<F>>
where
  F: BorrowIntentFnT + Send,
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

    Ok(())
  }
}
