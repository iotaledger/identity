// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;

use futures::StreamExt;
use iota_sdk::graphql_client::query_types::EventFilter;
use iota_sdk::graphql_client::Client;
use iota_sdk::graphql_client::Direction;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::Event;
use iota_sdk::types::ObjectId;
use iota_sdk::types::ProgrammableTransaction;
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

use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::iota::package::identity_package_id_blocking;
use crate::rebased::migration::ControllerToken;
use crate::rebased::migration::InvalidControllerTokenForIdentity;
use crate::rebased::migration::OnChainIdentity;
use crate::rebased::migration::Proposal;

use super::ProposalEvent;
use super::ProposedTxResult;

type BoxedStdError = Box<dyn std::error::Error + Send + Sync>;

pub trait IntoOperation {
  type Op: Operation;

  fn into_operation(self) -> Self::Op;
}

/// Trait describing the function used to define what operation to perform on a sub-identity.
pub trait SubAccessFnT<'a>: FnOnce(&'a mut OnChainIdentity, ControllerToken) -> Self::Future {
  /// The [Future] type returned by the closure.
  type Future: Future<Output = Result<Self::IntoOperation, Self::Error>> + 'a;
  /// An [IntoOperation] type.
  type IntoOperation: IntoOperation<Op = Self::Op>;
  /// The [Operation] that encodes the operation to be performed on the sub-identity.
  type Op: Operation + 'a;
  /// The error returned by this function
  type Error: Into<BoxedStdError>;
}

impl<'a, F, Fut, IntoOp, Op, E> SubAccessFnT<'a> for F
where
  F: FnOnce(&'a mut OnChainIdentity, ControllerToken) -> Fut,
  Fut: Future<Output = Result<IntoOp, E>> + 'a,
  IntoOp: IntoOperation<Op = Op>,
  Op: Operation + 'a,
  E: Into<BoxedStdError>,
{
  type Future = Fut;
  type IntoOperation = IntoOp;
  type Op = Op;
  type Error = E;
}

/// A type implenting [Operation] that doesn't return anything meaningful.
///
/// Used to encode `sub_op` in [AccessSubIdentityTx] when no sub_op is present (create proposal).
#[derive(Debug)]
pub struct EmptyOp;

impl Operation for EmptyOp {
  type Output = ();
  type Error = Infallible;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    tx_builder: TransactionBuilder<Client>,
  ) -> Result<TransactionBuilder<Client>, Self::Error> {
    Ok(tx_builder)
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut iota_sdk::types::TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    Ok(())
  }
}

/// An action for accessing an [OnChainIdentity] that is owned by another
/// [OnChainIdentity].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccessSubIdentity {
  /// ID of the Identity whose token will be used to access the sub-Identity.
  #[serde(rename = "entity")]
  pub identity: ObjectId,
  #[serde(rename = "sub_entity")]
  /// ID of the sub-Identity that will be accessed through this action.
  pub sub_identity: ObjectId,
}

/// A builder structure that eases the creation of an [AccessSubIdentityTx].
#[derive(Debug)]
pub struct AccessSubIdentityBuilder<'i, 'sub, F = ()> {
  identity: &'i mut OnChainIdentity,
  identity_token: ControllerToken,
  sub_identity: &'sub mut OnChainIdentity,
  expiration: Option<u64>,
  sub_action: Option<F>,
}

impl<'i, 'sub, F> AccessSubIdentityBuilder<'i, 'sub, F> {
  /// Returns a new [AccessSubIdentityBuilder] that when built will return a [AccessSubIdentityTx]
  /// to access `sub_identity` through `identity`'s token.
  pub fn new(
    identity: &'i mut OnChainIdentity,
    sub_identity: &'sub mut OnChainIdentity,
    identity_token: &ControllerToken,
  ) -> Self {
    Self {
      identity,
      sub_identity,
      identity_token: identity_token.clone(),
      expiration: None,
      sub_action: None,
    }
  }

  /// Sets an epoch before which this proposal must be executed by any member of the controllers committee.
  ///
  /// If this action can be carried out in the same transaction as its proposal, this option is ignored.
  pub fn with_expiration(mut self, epoch_id: u64) -> Self {
    self.expiration = Some(epoch_id);
    self
  }

  /// Sets the operation to be performed on the sub-Identity.
  ///
  /// # Example
  /// ```ignore
  /// identity
  ///   .access_sub_identity(&mut sub_identity, &identity_token)
  ///   .to_perform(|sub_identity, sub_identity_token| async move {
  ///     sub_identity.deactivate_did(&sub_identity_token).finish().await
  ///   })
  /// ```
  pub fn to_perform<F1>(self, f: F1) -> AccessSubIdentityBuilder<'i, 'sub, F1>
  where
    F1: SubAccessFnT<'sub>,
  {
    AccessSubIdentityBuilder {
      identity: self.identity,
      identity_token: self.identity_token,
      sub_identity: self.sub_identity,
      expiration: self.expiration,
      sub_action: Some(f),
    }
  }

  async fn get_identity_token<C>(
    &self,
    client: &impl ProductClient,
  ) -> Result<ControllerToken, AccessSubIdentityBuilderErrorKind> {
    // Make sure `identity_token` grants access to `identity`.
    if self.identity.id() != self.identity_token.controller_of() {
      return Err(AccessSubIdentityBuilderErrorKind::Unauthorized(
        InvalidControllerTokenForIdentity {
          identity: self.identity.id(),
          controller_token: self.identity_token.clone(),
        },
      ));
    }

    // Retrieve from `identity` owned asset any token granting access to `sub_identity`.
    self
      .sub_identity
      .get_controller_token_for_address(self.identity.id().into(), client)
      .await
      .map_err(|e| AccessSubIdentityBuilderErrorKind::RpcError(e.into()))?
      // If no token was found, the two identities are unrelated, AKA `identity` is not a controller of `sub_identity`.
      .ok_or(AccessSubIdentityBuilderErrorKind::UnrelatedIdentities(
        UnrelatedIdentities {
          identity: self.identity.id(),
          sub_identity: self.sub_identity.id(),
        },
      ))
  }
}

impl<'i, 'sub> AccessSubIdentityBuilder<'i, 'sub, ()> {
  /// Consumes this builder returning a [TransactionBuilder] wrapping a [AccessSubIdentityTx] created
  /// with the supplied data.
  pub async fn finish(
    self,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<AccessSubIdentityTx<'i, 'sub, EmptyOp>>, AccessSubIdentityBuilderError> {
    let _ = self.get_identity_token(client).await?;
    let tx_kind = TxKind::Create {
      expiration: self.expiration,
    };

    Ok(OperationBuilder::new(AccessSubIdentityTx {
      identity: self.identity,
      identity_token: self.identity_token,
      sub_identity: self.sub_identity.id(),
      tx_kind,
      _sub: PhantomData,
    }))
  }
}

impl<'i, 'sub, F> AccessSubIdentityBuilder<'i, 'sub, F>
where
  F: SubAccessFnT<'sub>,
  F::Op: Operation,
{
  /// Consumes this builder returning an [OperationBuilder] wrapping a [AccessSubIdentityTx] created
  /// with the supplied data.
  pub async fn finish(
    self,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<AccessSubIdentityTx<'i, 'sub, F::Op>>, AccessSubIdentityBuilderError> {
    let sub_identity_token = self.get_identity_token(client).await?;

    // `true` if this operation can also be executed in the same transaction.
    let can_execute = self
      .identity
      .controller_voting_power(self.identity_token.controller_id())
      .expect("valid controller token")
      >= self.identity.threshold();

    // Invoke the user-passed function, if any, to compute the transaction to perform on `sub_identity`.
    // If `can_execute` is `false`, don't bother checking the user sub-action.
    let sub_identity_id = self.sub_identity.id();
    let maybe_sub_tx = if let Some(fetch_sub_tx) = self.sub_action.filter(|_| can_execute) {
      fetch_sub_tx(self.sub_identity, sub_identity_token.clone())
        .await
        .map(|into_tx| Some(into_tx.into_transaction()))
        .map_err(|e| AccessSubIdentityBuilderErrorKind::SubIdentityOperation {
          sub_identity: sub_identity_id,
          source: e.into(),
        })?
    } else {
      None
    };

    let tx_kind = maybe_sub_tx
      .map(move |sub_tx| TxKind::CreateAndExecute {
        sub_tx,
        sub_identity_token,
      })
      .unwrap_or(TxKind::Create {
        expiration: self.expiration,
      });
    let op = AccessSubIdentityTx {
      identity: self.identity,
      identity_token: self.identity_token,
      sub_identity: sub_identity_id,
      tx_kind,
      _sub: PhantomData,
    };

    Ok(OperationBuilder::new(op))
  }
}

impl Proposal<AccessSubIdentity> {
  /// Executes this proposal by returning the corresponding operation to be executed.
  pub async fn into_op<'i, 'sub, F>(
    self,
    identity: &'i mut OnChainIdentity,
    sub_identity: &'sub mut OnChainIdentity,
    identity_token: &ControllerToken,
    sub_action: F,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<AccessSubIdentityTx<'i, 'sub, F::Op>>, AccessSubIdentityBuilderError>
  where
    F: SubAccessFnT<'sub>,
    F::Op: Operation,
  {
    // Re-use builder's error-handling.
    let mut op = identity
      .access_sub_identity(sub_identity, identity_token)
      .to_perform(sub_action)
      .finish(client)
      .await?
      .into_inner();
    // Change tx_kind to `Execute`.
    let TxKind::CreateAndExecute {
      sub_tx,
      sub_identity_token,
    } = op.tx_kind
    else {
      unreachable!("a sub_action was passed");
    };
    op.tx_kind = TxKind::Execute {
      proposal_id: self.id(),
      sub_tx,
      sub_identity_token,
    };

    Ok(OperationBuilder::new(op))
  }
}

/// Error type that is returned when attempting to access an Identity `sub_identity`
/// that is **not** controlled by `identity`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("Identity `{identity}` has no control over Identity `{sub_identity}`")]
pub struct UnrelatedIdentities {
  /// ID of the base-Identity.
  pub identity: ObjectId,
  /// ID of the sub-Identity to be accessed.
  pub sub_identity: ObjectId,
}

/// Kind of failure that might happen when consuming an [AccessSubIdentityBuilder].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccessSubIdentityBuilderErrorKind {
  /// An RPC request to an IOTA Node failed.
  #[error(transparent)]
  RpcError(BoxedStdError),
  /// See [UnrelatedIdentities].
  #[error(transparent)]
  UnrelatedIdentities(#[from] UnrelatedIdentities),
  /// See [InvalidControllerTokenForIdentity].
  #[error(transparent)]
  Unauthorized(#[from] InvalidControllerTokenForIdentity),
  /// The user-defined operation passed to the builder through [AccessSubIdentityBuilder::to_perform] failed.
  #[non_exhaustive]
  #[error("user-defined operation on sub-Identity `{sub_identity}` failed")]
  SubIdentityOperation {
    /// ID of the sub-Identity.
    sub_identity: ObjectId,
    /// Error returned by the user closure.
    source: BoxedStdError,
  },
}

/// Error type returned by [AccessSubIdentityBuilder::finish].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("failed to build a valid sub-Identity access operation")]
pub struct AccessSubIdentityBuilderError {
  /// Type of failure.
  #[from]
  #[source]
  pub kind: AccessSubIdentityBuilderErrorKind,
}

#[derive(Debug)]
enum TxKind<Tx> {
  Create {
    expiration: Option<u64>,
  },
  Execute {
    proposal_id: ObjectId,
    sub_tx: Tx,
    sub_identity_token: ControllerToken,
  },
  CreateAndExecute {
    sub_tx: Tx,
    sub_identity_token: ControllerToken,
  },
}

/// [Transaction] that allows a controller of `identity` to access `sub_identity`
/// by borrowing one of `identity`'s token over it.
#[derive(Debug)]
pub struct AccessSubIdentityTx<'i, 'sub, Op = EmptyOp> {
  identity: &'i mut OnChainIdentity,
  identity_token: ControllerToken,
  sub_identity: ObjectId,
  tx_kind: TxKind<Op>,
  // The lifetime of sub-identity, borrowed within type parameter Tx.
  _sub: PhantomData<&'sub ()>,
}

impl<'i, 'sub, Op> AccessSubIdentityTx<'i, 'sub, Op>
where
  Op: Operation,
{
  async fn build_tx_impl(
    &self,
    client: &impl ProductClient,
  ) -> Result<TransactionBuilder<Client>, AccessSubIdentityErrorKind> {
    let package_id = identity_package_id(client.network())
      .await
      .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into()))?;

    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());

    match &self.tx_kind {
      TxKind::Create { expiration } => move_calls::identity::sub_identity::propose_identity_sub_access(
        &mut ptb,
        self.identity.id(),
        self.sub_identity,
        &self.identity_token,
        *expiration,
        package_id,
      ),
      TxKind::CreateAndExecute {
        sub_tx,
        sub_identity_token,
      } => {
        let sub_pt = sub_op_to_pt(sub_tx, client).await?;

        move_calls::identity::sub_identity::propose_and_execute_sub_identity_access(
          &mut ptb,
          self.identity.id(),
          self.sub_identity,
          &self.identity_token,
          sub_identity_token,
          sub_pt,
          None, // We are gonna execute it right away no need for expiration.
          package_id,
          client.network(),
        )
      }
      TxKind::Execute {
        proposal_id,
        sub_tx,
        sub_identity_token,
      } => {
        let sub_pt = sub_op_to_pt(sub_tx, client).await?;

        move_calls::identity::sub_identity::execute_sub_identity_access(
          &mut ptb,
          self.identity.id(),
          &self.identity_token,
          *proposal_id,
          sub_identity_token,
          sub_pt,
          package_id,
          client.network(),
        )
      }
    }

    Ok(ptb)
  }
}

async fn sub_op_to_pt<Op: Operation>(
  sub_op: &Op,
  client: &impl ProductClient,
) -> Result<ProgrammableTransaction, AccessSubIdentityErrorKind> {
  sub_op
    .to_transaction(
      client,
      TransactionBuilder::new(Address::ZERO).with_client((*client).clone()),
    )
    .await
    .map_err(|e| AccessSubIdentityErrorKind::InnerTransactionBuilding(e.into()))?
    .finish()
    .await
    .map_err(|e| AccessSubIdentityErrorKind::InnerTransactionBuilding(e.into()))?
    .into_v1()
    .kind
    .into_programmable_transaction()
}

impl<'i, 'sub, Op> Operation for AccessSubIdentityTx<'i, 'sub, Op>
where
  Op: Operation,
{
  type Error = AccessSubIdentityError;
  type Output = ProposedTxResult<Proposal<AccessSubIdentity>, Op::Output>;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    _tx_builder: TransactionBuilder<Client>,
  ) -> Result<TransactionBuilder<Client>, Self::Error> {
    self.build_tx_impl(client).await.map_err(|kind| AccessSubIdentityError {
      identity: self.identity.id(),
      sub_identity: self.sub_identity,
      kind,
    })
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    let events = client
      .events_stream(
        EventFilter {
          transaction_digest: Some(effects.digest().to_string()),
          ..Default::default()
        },
        Direction::Forward,
      )
      .collect()
      .await;

    // Extract the event for the proposal we are expecting.
    let extract_proposal_id = |event: &Event| -> Option<ProposalEvent> {
      if event.type_.module().as_str() == "identity" && event.type_.name().as_str() == "ProposalEvent" {
        serde_json::from_value::<ProposalEvent>(event.parsed_json.clone())
          .ok()
          .filter(|event| event.identity == self.identity.id() && event.controller == self.identity_token.id())
      } else {
        None
      }
    };

    if let Some(tx_error) = effects.status().error() {
      return Err(AccessSubIdentityError {
        identity: self.identity.id(),
        sub_identity: self.sub_identity,
        kind: AccessSubIdentityErrorKind::TransactionExecution(tx_error.into()),
      });
    }

    let maybe_proposal_id = {
      let maybe_proposal_event = events
        .data
        .iter()
        .enumerate()
        .find_map(|(i, event)| extract_proposal_id(event).map(|event| (i, event)));

      if let Some((i, event)) = maybe_proposal_event {
        // We handled this event, therefore we remove it so that other TXs can avoid going through it.
        events.data.swap_remove(i);
        Some(event.proposal)
      } else {
        None
      }
    };

    match self.tx_kind {
      TxKind::Create { .. } => client
        .get_object_by_id(maybe_proposal_id.expect("tx was successful"))
        .await
        .map(ProposedTxResult::Pending)
        .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into())),
      TxKind::CreateAndExecute { sub_tx, .. } | TxKind::Execute { sub_tx, .. } => sub_tx
        .apply_with_events(effects, events, client)
        .await
        .map(ProposedTxResult::Executed)
        .map_err(|e| AccessSubIdentityErrorKind::EffectsApplication(e.into())),
    }
    .map_err(|kind| AccessSubIdentityError {
      kind,
      sub_identity: self.sub_identity,
      identity: self.identity.id(),
    })
  }
}

impl MoveType for AccessSubIdentity {
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

    format!("{package}::access_sub_entity_proposal::AccessSubEntity")
      .parse()
      .expect("valid TypeTag")
  }
}

/// Type of failures that can be encountered when executing a [AccessSubIdentityTx].
// TODO: Expose this type after transation building/execution has been reworked throughout the library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
enum AccessSubIdentityErrorKind {
  /// An RPC request to an IOTA Node failed.
  #[error("RPC request failed")]
  RpcError(#[source] Box<dyn std::error::Error + Send + Sync>),
  /// Building the user-provided transaction failed.
  #[error("failed to build user-provided Transaction")]
  InnerTransactionBuilding(#[source] Box<dyn std::error::Error + Send + Sync>),
  /// Building the whole transaction failed.
  #[error("failed to build transaction")]
  TransactionBuilding(#[source] Box<dyn std::error::Error + Send + Sync>),
  /// Executing the transaction failed.
  #[error("transaction execution failed")]
  TransactionExecution(#[source] Box<dyn std::error::Error + Send + Sync>),
  /// Failed to apply the transaction's effects off-chain.
  #[error("transaction was successful but its effect couldn't be applied off-chain")]
  EffectsApplication(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Error type returned by executing an [AccessSubIdentityTx].
#[derive(Debug, thiserror::Error)]
#[error("transaction to access Identity `{sub_identity}` through Identity `{identity}` failed")]
#[non_exhaustive]
pub struct AccessSubIdentityError {
  /// ID of the base-Identity.
  pub identity: ObjectId,
  /// Id of the sub-Identity.
  pub sub_identity: ObjectId,
  /// Type of failure.
  #[source]
  kind: AccessSubIdentityErrorKind,
}
