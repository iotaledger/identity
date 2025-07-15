// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::TransactionBuilder;

use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::migration::ControllerToken;
use async_trait::async_trait;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::TypeTag;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::migration::OnChainIdentity;
use crate::rebased::migration::Proposal;
use crate::rebased::Error;
use iota_interaction::MoveType;
use iota_interaction::OptionalSync;

use super::CreateProposal;
use super::ExecuteProposal;
use super::ProposalT;

/// Action for upgrading the version of an on-chain identity to the package's version.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Upgrade;

impl Upgrade {
  /// Creates a new [`Upgrade`] action.
  pub const fn new() -> Self {
    Self
  }
}

impl MoveType for Upgrade {
  fn move_type(package: ObjectID) -> TypeTag {
    format!("{package}::upgrade_proposal::Upgrade")
      .parse()
      .expect("valid utf8")
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl ProposalT for Proposal<Upgrade> {
  type Action = Upgrade;
  type Output = ();

  async fn create<'i, C>(
    _action: Self::Action,
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

    let identity_ref = client
      .get_object_ref_by_id(identity.id())
      .await?
      .expect("identity exists on-chain");
    let controller_cap_ref = controller_token.controller_ref(client).await?;
    let sender_vp = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("controller exists");
    let chained_execution = sender_vp >= identity.threshold();
    let package = identity_package_id(client).await?;

    let tx = move_calls::identity::propose_upgrade(identity_ref, controller_cap_ref, expiration, package)
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
    let package = identity_package_id(client).await?;

    let tx = move_calls::identity::execute_upgrade(identity_ref, controller_cap_ref, proposal_id, package)
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
