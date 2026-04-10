// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::marker::PhantomData;

use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::iota::package::identity_package_id_blocking;
use crate::rebased::migration::ControllerToken;
use crate::rebased::proposals::ProtoOperation;

use async_trait::async_trait;
use iota_sdk::graphql_client::query_types::ObjectFilter;
use iota_sdk::graphql_client::Client;
use iota_sdk::graphql_client::Direction;
use iota_sdk::transaction_builder::unresolved::Argument;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::Object;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_type::MoveType;
use product_core::move_type::UnknownTypeForNetwork;
use product_core::network::Network;
use product_core::operation::Operation;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::rebased::migration::Proposal;
use crate::rebased::Error;

use super::CreateProposal;
use super::OnChainIdentity;
use super::ProposalBuilder;
use super::ProposalT;
use super::UserDrivenTx;

/// Instances of BorrowIntentFnT can be used as user-provided function to describe how
/// a borrowed assets shall be used.
pub trait BorrowIntentFnT: FnOnce(&mut TransactionBuilder<Client>, &HashMap<ObjectId, (Argument, Object)>) {}
impl<T> BorrowIntentFnT for T where T: FnOnce(&mut TransactionBuilder<Client>, &HashMap<ObjectId, (Argument, Object)>) {}
pub type BorrowIntentFn = Box<dyn BorrowIntentFnT + Send>;

/// Action used to borrow in transaction [OnChainIdentity]'s assets.
#[derive(Deserialize, Serialize)]
pub struct BorrowAction<F = BorrowIntentFn> {
  objects: Vec<ObjectId>,
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
  fn move_type(network: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    let package = match network {
      Network::Mainnet => "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08",
      Network::Testnet => "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
      Network::Devnet => "0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103",
      _ => identity_package_id_blocking(network)
        .map_err(|_| UnknownTypeForNetwork::new("Borrow", network))?
        .to_string()
        .as_str(),
    };

    format!("{package}::borrow_proposal::Borrow")
      .parse()
      .expect("valid TypeTag")
  }
}

impl<F> BorrowAction<F> {
  /// Returns a new [BorrowAction].
  pub fn new<I>(objects: I) -> Self
  where
    I: IntoIterator<Item = ObjectId>,
  {
    Self {
      objects: objects.into_iter().collect(),
      intent_fn: Mutex::new(None),
    }
  }

  /// Returns a new [BorrowAction], attempting to directly execute the borrow.
  pub fn new_with_intent<I>(objects: I, intent: F) -> Self
  where
    I: IntoIterator<Item = ObjectId>,
  {
    Self {
      objects: objects.into_iter().collect(),
      intent_fn: Mutex::new(Some(intent)),
    }
  }

  /// Returns a reference to the list of objects that will be borrowed.
  pub fn objects(&self) -> &[ObjectId] {
    &self.objects
  }

  /// Adds an object to the lists of objects that will be borrowed when executing
  /// this action in a proposal.
  pub fn borrow_object(&mut self, object_id: ObjectId) {
    self.objects.push(object_id);
  }

  /// Adds many objects. See [`BorrowAction::borrow_object`] for more details.
  pub fn borrow_objects<I>(&mut self, objects: I)
  where
    I: IntoIterator<Item = ObjectId>,
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
  pub fn borrow(mut self, object_id: ObjectId) -> Self {
    self.action.borrow_object(object_id);
    self
  }
  /// Adds many objects. See [`BorrowAction::borrow_object`] for more details.
  pub fn borrow_objects<I>(self, objects: I) -> Self
  where
    I: IntoIterator<Item = ObjectId>,
  {
    objects.into_iter().fold(self, |builder, obj| builder.borrow(obj))
  }

  /// Specifies how to use the borrowed assets. This is only useful if the sender of this
  /// transaction has enough voting power to execute this proposal right-away.
  pub fn with_intent<F1>(self, intent_fn: F1) -> ProposalBuilder<'i, 'c, BorrowAction<F1>>
  where
    F1: FnOnce(&mut TransactionBuilder<Client>, &HashMap<ObjectId, (Argument, Object)>),
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
  F: BorrowIntentFnT,
{
  type Action = BorrowAction<F>;
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

    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());
    let package = identity_package_id(client.network()).await?;
    let can_execute = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("is a controller of identity")
      >= identity.threshold();
    let maybe_intent_fn = action.intent_fn.into_inner();
    let chained_execution = can_execute && maybe_intent_fn.is_some();
    if chained_execution {
      // Construct a list of `(ObjectId, TypeTag)` from the list of objects to send.
      let object_data_list = client
        .objects_stream(
          ObjectFilter {
            object_ids: Some(action.objects.clone()),
            ..Default::default()
          },
          Direction::Forward,
        )
        .collect()
        .await;

      let objects = action.objects.clone().into_iter().zip(object_data_list).collect();

      move_calls::identity::create_and_execute_borrow(
        &mut ptb,
        identity.id(),
        controller_token,
        objects,
        maybe_intent_fn.unwrap(),
        expiration,
        package,
        client.network(),
      )
    } else {
      move_calls::identity::propose_borrow(
        &mut ptb,
        identity.id(),
        controller_token,
        action.objects,
        expiration,
        package,
      )
    }

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
    _client: &impl ProductClient,
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

  fn parse_tx_effects(effects: &TransactionEffects) -> Result<Self::Output, Error> {
    if let Some(tx_error) = effects.status().error() {
      return Err(Error::TransactionExecutionFailed(tx_error.clone()));
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

impl<'i, F> ProtoOperation for UserDrivenTx<'i, BorrowAction<F>> {
  type Input = BorrowIntentFn;
  type Operation = OperationBuilder<UserDrivenTx<'i, BorrowActionWithIntent<BorrowIntentFn>>>;

  fn with(self, input: Self::Input) -> Self::Operation {
    OperationBuilder::new(self.with_intent(input))
  }
}

impl<F> UserDrivenTx<'_, BorrowActionWithIntent<F>>
where
  F: BorrowIntentFnT,
{
  async fn make_ptb(
    &self,
    client: &impl ProductClient,
    mut ptb: TransactionBuilder<Client>,
  ) -> Result<TransactionBuilder<Client>, Error> {
    let Self {
      identity,
      action: borrow_action,
      proposal_id,
      controller_token,
      ..
    } = self;
    let controller_token = client
      .move_object_contents(*controller_token, None)
      .await?
      .and_then(|obj| serde_json::from_value(obj).ok())
      .expect("controller token exists and is valid");

    let objects = client
      .objects_stream(
        ObjectFilter {
          object_ids: Some(borrow_action.0.objects().to_vec()),
          ..Default::default()
        },
        Direction::Forward,
      )
      .collect()
      .await?;
    let package = identity_package_id(client.network()).await?;
    move_calls::identity::execute_borrow(
      &mut ptb,
      identity.id(),
      &controller_token,
      *proposal_id,
      objects,
      borrow_action
        .0
        .take_intent()
        .await
        .expect("BorrowActionWithIntent makes sure intent_fn is there"),
      package,
      client.network(),
    );

    Ok(ptb)
  }
}

impl Operation for UserDrivenTx<'_, BorrowActionWithIntent<BorrowIntentFn>> {
  type Output = ();
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    ptb: TransactionBuilder<Client>,
  ) -> Result<TransactionBuilder<Client>, Self::Error> {
    self.make_ptb(client, ptb).await
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = effects.status().error() {
      return Err(Error::TransactionExecutionFailed(tx_error.clone()));
    }

    Ok(())
  }
}
