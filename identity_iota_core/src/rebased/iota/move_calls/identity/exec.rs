// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::base_types::ObjectRef;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::ObjectArg;
use iota_interaction::MoveType as _;
use iota_interaction::ProgrammableTransactionBcs;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::iota::move_calls::ControllerTokenRef;
use crate::rebased::proposals::ControllerExecution;
use crate::rebased::Error;

use super::ControllerTokenArg;
use super::ProposalContext;

pub(crate) fn propose_controller_execution(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  controller_cap_id: ObjectID,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let ProposalContext {
    mut ptb, capability, ..
  } = controller_execution_impl(identity, capability, controller_cap_id, expiration, package_id)?;
  capability.put_back(&mut ptb, package_id);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn execute_controller_execution<F>(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  proposal_id: ObjectID,
  borrowing_controller_cap_ref: ObjectRef,
  intent_fn: F,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error>
where
  F: FnOnce(&mut Ptb, &Argument),
{
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package)?;
  let proposal_id = ptb.pure(proposal_id)?;

  execute_controller_execution_impl(
    &mut ptb,
    identity,
    proposal_id,
    capability.arg(),
    borrowing_controller_cap_ref,
    intent_fn,
    package,
  )?;

  capability.put_back(&mut ptb, package);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn create_and_execute_controller_execution<F>(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  expiration: Option<u64>,
  borrowing_controller_cap_ref: ObjectRef,
  intent_fn: F,
  package_id: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error>
where
  F: FnOnce(&mut Ptb, &Argument),
{
  let ProposalContext {
    mut ptb,
    capability,
    proposal_id,
    identity,
  } = controller_execution_impl(
    identity,
    capability,
    borrowing_controller_cap_ref.0,
    expiration,
    package_id,
  )?;

  execute_controller_execution_impl(
    &mut ptb,
    identity,
    proposal_id,
    capability.arg(),
    borrowing_controller_cap_ref,
    intent_fn,
    package_id,
  )?;

  capability.put_back(&mut ptb, package_id);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

fn controller_execution_impl(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  controller_cap_id: ObjectID,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> anyhow::Result<ProposalContext> {
  let mut ptb = Ptb::new();
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package_id)?;
  let identity_arg = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let controller_cap_id = ptb.pure(controller_cap_id)?;
  let exp_arg = utils::option_to_move(expiration, &mut ptb, package_id)?;

  let proposal_id = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").into(),
    ident_str!("propose_controller_execution").into(),
    vec![],
    vec![identity_arg, capability.arg(), controller_cap_id, exp_arg],
  );

  Ok(ProposalContext {
    ptb,
    capability,
    identity: identity_arg,
    proposal_id,
  })
}

pub(crate) fn execute_controller_execution_impl<F>(
  ptb: &mut Ptb,
  identity: Argument,
  proposal_id: Argument,
  delegation_token: Argument,
  borrowing_controller_cap_ref: ObjectRef,
  intent_fn: F,
  package: ObjectID,
) -> anyhow::Result<()>
where
  F: FnOnce(&mut Ptb, &Argument),
{
  // Get the proposal's action as argument.
  let controller_execution_action = ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("execute_proposal").into(),
    vec![ControllerExecution::move_type(package)],
    vec![identity, delegation_token, proposal_id],
  );

  // Borrow the controller cap into this transaction.
  let receiving = ptb.obj(ObjectArg::Receiving(borrowing_controller_cap_ref))?;
  let borrowed_controller_cap = ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("borrow_controller_cap").into(),
    vec![],
    vec![identity, controller_execution_action, receiving],
  );

  // Apply the user-defined operation.
  intent_fn(ptb, &borrowed_controller_cap);

  // Put back the borrowed controller cap.
  ptb.programmable_move_call(
    package,
    ident_str!("controller_proposal").into(),
    ident_str!("put_back").into(),
    vec![],
    vec![controller_execution_action, borrowed_controller_cap],
  );

  Ok(())
}
