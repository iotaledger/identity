// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod borrow;
mod config_change;
mod create;
mod exec;
mod send;
pub(crate) mod sub_identity;
mod update;
mod upgrade;

pub(crate) use borrow::*;
pub(crate) use config_change::*;
pub(crate) use create::*;
pub(crate) use exec::*;
use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::unresolved::Argument;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::ObjectId;
use product_core::move_type::MoveType;
use product_core::network::Network;
pub(crate) use send::*;
pub(crate) use update::*;
pub(crate) use upgrade::*;

use crate::rebased::migration::ControllerToken;

pub(crate) enum ControllerTokenArg {
  Controller {
    cap: Argument,
    token: Argument,
    borrow: Argument,
  },
  Delegate(Argument),
}

impl ControllerTokenArg {
  pub(crate) fn from_token(token: &ControllerToken, ptb: &mut TransactionBuilder<Client>, package: ObjectId) -> Self {
    let token_arg = ptb.apply_argument(token.id());
    match token {
      ControllerToken::Delegate(_) => ControllerTokenArg::Delegate(token_arg),
      ControllerToken::Controller(_) => {
        let cap = token_arg;
        let (token, borrow) = get_controller_delegation(ptb, cap, package);

        Self::Controller { cap, token, borrow }
      }
    }
  }

  pub(crate) fn arg(&self) -> Argument {
    match self {
      Self::Controller { token, .. } => *token,
      Self::Delegate(token) => *token,
    }
  }

  pub(crate) fn put_back(self, ptb: &mut TransactionBuilder<Client>, package_id: ObjectId) {
    if let Self::Controller { cap, token, borrow } = self {
      put_back_delegation_token(ptb, cap, token, borrow, package_id);
    }
  }
}

pub(crate) fn get_controller_delegation(
  ptb: &mut TransactionBuilder<Client>,
  controller_cap: Argument,
  package: ObjectId,
) -> (Argument, Argument) {
  let Argument::Result(idx) = ptb
    .move_call(package, "controller", "borrow")
    .arguments([controller_cap])
    .arg()
  else {
    unreachable!()
  };

  (Argument::NestedResult(idx, 0), Argument::NestedResult(idx, 1))
}

pub(crate) fn put_back_delegation_token(
  ptb: &mut TransactionBuilder<Client>,
  controller_cap: Argument,
  delegation_token: Argument,
  borrow: Argument,
  package: ObjectId,
) {
  ptb
    .move_call(package, "controller", "put_back")
    .arguments([controller_cap, delegation_token, borrow]);
}

struct ProposalContext<'a> {
  ptb: &'a mut TransactionBuilder<Client>,
  capability: ControllerTokenArg,
  identity: Argument,
  proposal_id: Argument,
}

pub(crate) fn approve_proposal<T: MoveType>(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  controller_cap: &ControllerToken,
  proposal_id: ObjectId,
  package: ObjectId,
  network: Network,
) {
  let identity = ptb.apply_argument(SharedMut(identity));
  let capability = ControllerTokenArg::from_token(controller_cap, ptb, package);
  let proposal_id = ptb.pure(proposal_id);

  ptb
    .move_call(package, "identity", "approve_proposal")
    .arguments([identity, capability.arg(), proposal_id])
    .type_tags(T::move_type(network));

  capability.put_back(ptb, package);
}
