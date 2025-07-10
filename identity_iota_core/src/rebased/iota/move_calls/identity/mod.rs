// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod auth;
mod borrow;
mod config_change;
mod create;
mod exec;
mod send;
pub(crate) mod sub_identity;
mod update;
mod upgrade;

pub(crate) use auth::*;
pub(crate) use borrow::*;
pub(crate) use config_change::*;
pub(crate) use create::*;
pub(crate) use exec::*;
pub(crate) use send::*;
pub(crate) use update::*;
pub(crate) use upgrade::*;

use iota_interaction::ident_str;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::ObjectArg;
use iota_interaction::MoveType;
use iota_interaction::ProgrammableTransactionBcs;

use crate::rebased::rebased_err;
use crate::rebased::Error;

use super::utils;
use super::ControllerTokenRef;

enum ControllerTokenArg {
  Controller {
    cap: Argument,
    token: Argument,
    borrow: Argument,
  },
  Delegate(Argument),
}

impl ControllerTokenArg {
  fn from_ref(controller_ref: ControllerTokenRef, ptb: &mut Ptb, package: ObjectID) -> Result<Self, Error> {
    let token_arg = ptb
      .obj(ObjectArg::ImmOrOwnedObject(controller_ref.object_ref()))
      .map_err(rebased_err)?;
    match controller_ref {
      ControllerTokenRef::Delegate(_) => Ok(ControllerTokenArg::Delegate(token_arg)),
      ControllerTokenRef::Controller(_) => {
        let cap = token_arg;
        let (token, borrow) = utils::get_controller_delegation(ptb, cap, package);

        Ok(Self::Controller { cap, token, borrow })
      }
    }
  }

  fn arg(&self) -> Argument {
    match self {
      Self::Controller { token, .. } => *token,
      Self::Delegate(token) => *token,
    }
  }

  fn put_back(self, ptb: &mut Ptb, package_id: ObjectID) {
    if let Self::Controller { cap, token, borrow } = self {
      utils::put_back_delegation_token(ptb, cap, token, borrow, package_id);
    }
  }
}

struct ProposalContext {
  ptb: Ptb,
  capability: ControllerTokenArg,
  identity: Argument,
  proposal_id: Argument,
}

pub(crate) fn approve_proposal<T: MoveType>(
  identity: OwnedObjectRef,
  controller_cap: ControllerTokenRef,
  proposal_id: ObjectID,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)
    .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))?;
  let capability = ControllerTokenArg::from_ref(controller_cap, &mut ptb, package)?;
  let proposal_id = ptb
    .pure(proposal_id)
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;

  ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("approve_proposal").into(),
    vec![T::move_type(package)],
    vec![identity, capability.arg(), proposal_id],
  );

  capability.put_back(&mut ptb, package);

  Ok(bcs::to_bytes(&ptb.finish())?)
}
