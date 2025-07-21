// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;

use async_trait::async_trait;
use iota_interaction::rpc_types::IotaEvent;
use iota_interaction::rpc_types::IotaExecutionStatus;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI as _;
use iota_interaction::rpc_types::IotaTransactionBlockEvents;
use iota_interaction::rpc_types::IotaTransactionBlockResponseOptions;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::types::TypeTag;
use iota_interaction::MoveType;
use iota_interaction::OptionalSend;
use iota_interaction::OptionalSync;
use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use product_common::transaction::IntoTransaction;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::migration::ControllerToken;
use crate::rebased::migration::InvalidControllerTokenForIdentity;
use crate::rebased::migration::OnChainIdentity;
use crate::rebased::migration::Proposal;

use super::ProposalEvent;
use super::ProposedTxResult;

type BoxedStdError = Box<dyn std::error::Error + Send + Sync>;

/// Trait describing the function used to define what operation to perform on a sub-identity.
pub trait SubAccessFnT<'a>: FnOnce(&'a mut OnChainIdentity, ControllerToken) -> Self::Future {
  /// The [Future] type returned by the closure.
  type Future: Future<Output = Result<Self::IntoTx, Self::Error>> + OptionalSend + 'a;
  /// An [IntoTransaction] type.
  type IntoTx: IntoTransaction<Tx = Self::Tx>;
  /// The [Transaction] that encodes the operation to be performed on the sub-identity.
  type Tx: Transaction + 'a;
  /// The error returned by this function
  type Error: Into<BoxedStdError>;
}

impl<'a, F, Fut, IntoTx, Tx, E> SubAccessFnT<'a> for F
where
  F: FnOnce(&'a mut OnChainIdentity, ControllerToken) -> Fut,
  Fut: Future<Output = Result<IntoTx, E>> + OptionalSend + 'a,
  IntoTx: IntoTransaction<Tx = Tx>,
  Tx: Transaction + 'a,
  E: Into<BoxedStdError>,
{
  type Future = Fut;
  type IntoTx = IntoTx;
  type Tx = Tx;
  type Error = E;
}

/// A type implenting [Transansaction] that doesn't return anything meaningful.
///
/// Used to encode `sub_tx` in [AccessSubIdentityTx] when no sub_tx is present (create proposal).
#[derive(Debug)]
pub struct NeverTx;

#[cfg_attr(feature = "send-sync", async_trait)]
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
impl Transaction for NeverTx {
  type Output = ();
  type Error = Infallible;

  async fn build_programmable_transaction<C>(&self, _client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    Ok(ProgrammableTransaction {
      inputs: vec![],
      commands: vec![],
    })
  }

  async fn apply<C>(self, _effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
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
  pub identity: ObjectID,
  #[serde(rename = "sub_entity")]
  /// ID of the sub-Identity that will be accessed through this action.
  pub sub_identity: ObjectID,
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

  async fn validate<C>(&self, client: &C) -> Result<ControllerToken, AccessSubIdentityBuilderErrorKind>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    // Make sure `identity_token` grants access to `identity`.
    if self.identity.id() != self.identity_token.controller_of() {
      return Err(
        AccessSubIdentityBuilderErrorKind::Unauthorized(InvalidControllerTokenForIdentity {
          identity: self.identity.id(),
          controller_token: self.identity_token.clone(),
        })
        .into(),
      );
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
  pub async fn finish<C>(
    self,
    client: &C,
  ) -> Result<TransactionBuilder<AccessSubIdentityTx<'i, 'sub, NeverTx>>, AccessSubIdentityBuilderError>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let _ = self.validate(client).await?;
    let tx_kind = TxKind::Create {
      expiration: self.expiration,
    };

    Ok(TransactionBuilder::new(AccessSubIdentityTx {
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
  F::Tx: Transaction + OptionalSend + OptionalSync,
{
  /// Consumes this builder returning a [TransactionBuilder] wrapping a [AccessSubIdentityTx] created
  /// with the supplied data.
  pub async fn finish<C>(
    self,
    client: &C,
  ) -> Result<TransactionBuilder<AccessSubIdentityTx<'i, 'sub, F::Tx>>, AccessSubIdentityBuilderError>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let sub_identity_token = self.validate(client).await?;

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
    let tx = AccessSubIdentityTx {
      identity: self.identity,
      identity_token: self.identity_token,
      sub_identity: sub_identity_id,
      tx_kind,
      _sub: PhantomData,
    };

    Ok(TransactionBuilder::new(tx))
  }
}

impl Proposal<AccessSubIdentity> {
  /// Executes this proposal by returning the corresponding transaction to be executed.
  pub async fn into_tx<'i, 'sub, F, C>(
    self,
    identity: &'i mut OnChainIdentity,
    sub_identity: &'sub mut OnChainIdentity,
    identity_token: &ControllerToken,
    sub_action: F,
    client: &C,
  ) -> Result<TransactionBuilder<AccessSubIdentityTx<'i, 'sub, F::Tx>>, AccessSubIdentityBuilderError>
  where
    F: SubAccessFnT<'sub>,
    F::Tx: Transaction + OptionalSync + OptionalSend,
    C: CoreClientReadOnly + OptionalSync,
  {
    // Re-use builder's error-handling.
    let mut tx = identity
      .access_sub_identity(sub_identity, identity_token)
      .to_perform(sub_action)
      .finish(client)
      .await?
      .into_inner();
    // Change tx_kind to `Execute`.
    let TxKind::CreateAndExecute {
      sub_tx,
      sub_identity_token,
    } = tx.tx_kind
    else {
      unreachable!("a sub_action was passed");
    };
    tx.tx_kind = TxKind::Execute {
      proposal_id: self.id(),
      sub_tx,
      sub_identity_token,
    };

    Ok(TransactionBuilder::new(tx))
  }
}

/// Error type that is returned when attempting to access an Identity `sub_identity`
/// that is **not** controlled by `identity`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("Identity `{identity}` has no control over Identity `{sub_identity}`")]
pub struct UnrelatedIdentities {
  /// ID of the base-Identity.
  pub identity: ObjectID,
  /// ID of the sub-Identity to be accessed.
  pub sub_identity: ObjectID,
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
    sub_identity: ObjectID,
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
    proposal_id: ObjectID,
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
pub struct AccessSubIdentityTx<'i, 'sub, Tx> {
  identity: &'i mut OnChainIdentity,
  identity_token: ControllerToken,
  sub_identity: ObjectID,
  tx_kind: TxKind<Tx>,
  // The lifetime of sub-identity, borrowed within type parameter Tx.
  _sub: PhantomData<&'sub ()>,
}

impl<'i, 'sub, Tx> AccessSubIdentityTx<'i, 'sub, Tx>
where
  Tx: Transaction,
{
  async fn build_pt_impl<C>(&self, client: &C) -> Result<ProgrammableTransaction, AccessSubIdentityErrorKind>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    // Query the indexer for inputs' refs.
    let identity = client
      .get_object_ref_by_id(self.identity.id())
      .await
      .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into()))?
      .expect("exists on-chain");
    let sub_identity = client
      .get_object_ref_by_id(self.sub_identity)
      .await
      .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into()))?
      .expect("exists on-chain");
    let identity_token = self
      .identity_token
      .controller_ref(client)
      .await
      .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into()))?;
    let package_id = identity_package_id(client)
      .await
      .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into()))?;

    match &self.tx_kind {
      TxKind::Create { expiration } => move_calls::identity::sub_identity::propose_identity_sub_access(
        identity,
        sub_identity,
        identity_token,
        *expiration,
        package_id,
      ),
      TxKind::CreateAndExecute {
        sub_tx,
        sub_identity_token,
      } => {
        let sub_identity_token = sub_identity_token
          .controller_ref(client)
          .await
          .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into()))?;
        let sub_pt = sub_tx
          .build_programmable_transaction(client)
          .await
          .map_err(|e| AccessSubIdentityErrorKind::InnerTransactionBuilding(e.into()))?;

        move_calls::identity::sub_identity::propose_and_execute_sub_identity_access(
          identity,
          sub_identity,
          identity_token,
          sub_identity_token,
          sub_pt,
          None, // We are gonna execute it right away no need for expiration.
          package_id,
        )
      }
      TxKind::Execute {
        proposal_id,
        sub_tx,
        sub_identity_token,
      } => {
        let sub_identity_token = sub_identity_token
          .controller_ref(client)
          .await
          .map_err(|e| AccessSubIdentityErrorKind::RpcError(e.into()))?;
        let sub_pt = sub_tx
          .build_programmable_transaction(client)
          .await
          .map_err(|e| AccessSubIdentityErrorKind::InnerTransactionBuilding(e.into()))?;

        move_calls::identity::sub_identity::execute_sub_identity_access(
          identity,
          identity_token,
          *proposal_id,
          sub_identity_token,
          sub_pt,
          package_id,
        )
      }
    }
    .map_err(|e| AccessSubIdentityErrorKind::TransactionBuilding(e.into()))
  }
}

#[cfg_attr(feature = "send-sync", async_trait)]
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
impl<'i, 'sub, Tx> Transaction for AccessSubIdentityTx<'i, 'sub, Tx>
where
  Tx: Transaction + OptionalSync + OptionalSend,
{
  type Error = AccessSubIdentityError;
  type Output = ProposedTxResult<Proposal<AccessSubIdentity>, Tx::Output>;
  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.build_pt_impl(client).await.map_err(|kind| AccessSubIdentityError {
      identity: self.identity.id(),
      sub_identity: self.sub_identity,
      kind,
    })
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    use iota_interaction::IotaClientTrait as _;

    let tx_digest = effects.transaction_digest();
    let tx_block = client
      .client_adapter()
      .read_api()
      .get_transaction_with_options(*tx_digest, IotaTransactionBlockResponseOptions::default().with_events())
      .await
      .map_err(|e| AccessSubIdentityError {
        identity: self.identity.id(),
        sub_identity: self.sub_identity,
        kind: AccessSubIdentityErrorKind::RpcError(e.into()),
      })?;
    let mut tx_events = tx_block.events().cloned().unwrap_or_default();

    self.apply_with_events(effects, &mut tx_events, client).await
  }

  async fn apply_with_events<C>(
    self,
    effects: &mut IotaTransactionBlockEffects,
    events: &mut IotaTransactionBlockEvents,
    client: &C,
  ) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    // Extract the event for the proposal we are expecting.
    let extract_proposal_id = |event: &IotaEvent| -> Option<ProposalEvent> {
      if event.type_.module.as_str() == "identity" && event.type_.name.as_str() == "ProposalEvent" {
        serde_json::from_value::<ProposalEvent>(event.parsed_json.clone())
          .ok()
          .filter(|event| event.identity == self.identity.id() && event.controller == self.identity_token.id())
      } else {
        None
      }
    };

    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(AccessSubIdentityError {
        identity: self.identity.id(),
        sub_identity: self.sub_identity,
        kind: AccessSubIdentityErrorKind::TransactionExecution(error.as_str().into()),
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
  fn move_type(package: ObjectID) -> TypeTag {
    use std::str::FromStr;

    TypeTag::from_str(&format!("{package}::access_sub_entity_proposal::AccessSubEntity")).expect("valid move type")
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
  pub identity: ObjectID,
  /// Id of the sub-Identity.
  pub sub_identity: ObjectID,
  /// Type of failure.
  #[source]
  kind: AccessSubIdentityErrorKind,
}
