// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::rebased::client::IdentityClient;
use crate::rebased::iota::move_calls;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::migration::ControllerToken;
use async_trait::async_trait;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_type::MoveType;
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
  fn move_type(client: &impl ProductClient) -> TypeTag {
    let package = client.package_id();
    let mut tag = format!("{package}::upgrade_proposal::Upgrade")
      .parse()
      .expect("valid TypeTag");

    client.type_origin_table().canonicalize_type(&mut tag);
    tag
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl ProposalT for Proposal<Upgrade> {
  type Action = Upgrade;
  type Output = ();

  async fn create<'i>(
    _action: Self::Action,
    expiration: Option<u64>,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &IdentityClient,
  ) -> Result<OperationBuilder<CreateProposal<'i, Self::Action>>, Error> {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }

    let sender_vp = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("controller exists");
    let chained_execution = sender_vp >= identity.threshold();
    let package = identity_package_id(client.network()).await?;
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client(client.as_ref().clone());

    move_calls::identity::propose_upgrade(&mut ptb, identity.id(), controller_token, expiration, package);

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
    client: &IdentityClient,
  ) -> Result<OperationBuilder<ExecuteProposal<'i, Self::Action>>, Error> {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }

    let proposal_id = self.id();
    let package = identity_package_id(client.network()).await?;
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client(client.as_ref().clone());

    move_calls::identity::execute_upgrade(&mut ptb, identity.id(), controller_token, proposal_id, package);

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
