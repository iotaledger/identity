// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::IotaAddress;
use iota_sdk_types::{ObjectId, Argument, TypeTag};
use iota_interaction::types::base_types::ObjectRef;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::CallArg;
use iota_interaction::MoveType as _;
use iota_interaction::ProgrammableTransactionBcs;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::iota::move_calls::ControllerTokenRef;
use crate::rebased::proposals::SendAction;
use crate::rebased::Error;

use super::ControllerTokenArg;
use super::ProposalContext;

pub(crate) fn propose_send(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  transfer_map: Vec<(ObjectId, IotaAddress)>,
  expiration: Option<u64>,
  package_id: ObjectId,
) -> Result<ProgrammableTransactionBcs, Error> {
  let ProposalContext {
    mut ptb, capability, ..
  } = send_proposal_impl(identity, capability, transfer_map, expiration, package_id)?;

  capability.put_back(&mut ptb, package_id);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn execute_send(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  proposal_id: ObjectId,
  objects: Vec<(ObjectRef, TypeTag)>,
  package: ObjectId,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package)?;
  let proposal_id = ptb.pure(proposal_id)?;

  execute_send_impl(&mut ptb, identity, capability.arg(), proposal_id, objects, package)?;

  capability.put_back(&mut ptb, package);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn create_and_execute_send(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  transfer_map: Vec<(ObjectId, IotaAddress)>,
  expiration: Option<u64>,
  objects: Vec<(ObjectRef, TypeTag)>,
  package: ObjectId,
) -> anyhow::Result<ProgrammableTransactionBcs, Error> {
  let ProposalContext {
    mut ptb,
    identity,
    capability,
    proposal_id,
  } = send_proposal_impl(identity, capability, transfer_map, expiration, package)?;

  execute_send_impl(&mut ptb, identity, capability.arg(), proposal_id, objects, package)?;

  capability.put_back(&mut ptb, package);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

fn send_proposal_impl(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  transfer_map: Vec<(ObjectId, IotaAddress)>,
  expiration: Option<u64>,
  package_id: ObjectId,
) -> anyhow::Result<ProposalContext> {
  let mut ptb = Ptb::new();
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package_id)?;
  let identity_arg = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let exp_arg = utils::option_to_move(expiration, &mut ptb, package_id)?;
  let (objects, recipients) = {
    let (objects, recipients): (Vec<_>, Vec<_>) = transfer_map.into_iter().unzip();
    let objects = ptb.pure(objects)?;
    let recipients = ptb.pure(recipients)?;

    (objects, recipients)
  };

  let proposal_id = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").as_str().into(),
    ident_str!("propose_send").as_str().into(),
    vec![],
    vec![identity_arg, capability.arg(), exp_arg, objects, recipients],
  );

  Ok(ProposalContext {
    ptb,
    identity: identity_arg,
    capability,
    proposal_id,
  })
}

pub(crate) fn execute_send_impl(
  ptb: &mut Ptb,
  identity: Argument,
  delegation_token: Argument,
  proposal_id: Argument,
  objects: Vec<(ObjectRef, TypeTag)>,
  package: ObjectId,
) -> anyhow::Result<()> {
  // Get the proposal's action as argument.
  let send_action = ptb.programmable_move_call(
    package,
    ident_str!("identity").as_str().into(),
    ident_str!("execute_proposal").as_str().into(),
    vec![SendAction::move_type(package)],
    vec![identity, delegation_token, proposal_id],
  );

  // Send each object in this send action.
  // Traversing the map in reverse reduces the number of operations on the move side.
  for (obj, obj_type) in objects.into_iter().rev() {
    let recv_obj = ptb.obj(CallArg::Receiving(obj))?;

    ptb.programmable_move_call(
      package,
      ident_str!("identity").as_str().into(),
      ident_str!("execute_send").as_str().into(),
      vec![obj_type],
      vec![identity, send_action, recv_obj],
    );
  }

  // Consume the now empty send_action
  ptb.programmable_move_call(
    package,
    ident_str!("transfer_proposal").as_str().into(),
    ident_str!("complete_send").as_str().into(),
    vec![],
    vec![send_action],
  );

  Ok(())
}
