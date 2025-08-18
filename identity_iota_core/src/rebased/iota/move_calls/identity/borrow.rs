// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use iota_interaction::ident_str;
use iota_interaction::rpc_types::IotaObjectData;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::base_types::ObjectType;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::ObjectArg;
use iota_interaction::MoveType as _;
use iota_interaction::ProgrammableTransactionBcs;
use itertools::Itertools as _;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::iota::move_calls::ControllerTokenRef;
use crate::rebased::proposals::BorrowAction;
use crate::rebased::Error;

use super::ControllerTokenArg;
use super::ProposalContext;

fn borrow_proposal_impl(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  objects: Vec<ObjectID>,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> anyhow::Result<ProposalContext> {
  let mut ptb = Ptb::new();
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package_id)?;
  let identity_arg = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let exp_arg = utils::option_to_move(expiration, &mut ptb, package_id)?;
  let objects_arg = ptb.pure(objects)?;

  let proposal_id = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").into(),
    ident_str!("propose_borrow").into(),
    vec![],
    vec![identity_arg, capability.arg(), exp_arg, objects_arg],
  );

  Ok(ProposalContext {
    ptb,
    identity: identity_arg,
    capability,
    proposal_id,
  })
}

pub(crate) fn execute_borrow_impl<F>(
  ptb: &mut Ptb,
  identity: Argument,
  delegation_token: Argument,
  proposal_id: Argument,
  objects: Vec<IotaObjectData>,
  intent_fn: F,
  package: ObjectID,
) -> anyhow::Result<()>
where
  F: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>),
{
  // Get the proposal's action as argument.
  let borrow_action = ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("execute_proposal").into(),
    vec![BorrowAction::move_type(package)],
    vec![identity, delegation_token, proposal_id],
  );

  // Borrow all the objects specified in the action.
  let obj_arg_map = objects
    .into_iter()
    .map(|obj_data| {
      let obj_ref = obj_data.object_ref();
      let ObjectType::Struct(obj_type) = obj_data.object_type()? else {
        unreachable!("move packages cannot be borrowed to begin with");
      };
      let recv_obj = ptb.obj(ObjectArg::Receiving(obj_ref))?;

      let obj_arg = ptb.programmable_move_call(
        package,
        ident_str!("identity").into(),
        ident_str!("execute_borrow").into(),
        vec![obj_type.into()],
        vec![identity, borrow_action, recv_obj],
      );

      Ok((obj_ref.0, (obj_arg, obj_data)))
    })
    .collect::<anyhow::Result<_>>()?;

  // Apply the user-defined operation.
  intent_fn(ptb, &obj_arg_map);

  // Put back all the objects.
  obj_arg_map.into_values().for_each(|(obj_arg, obj_data)| {
    let ObjectType::Struct(obj_type) = obj_data.object_type().expect("checked above") else {
      unreachable!("move packages cannot be borrowed to begin with");
    };
    ptb.programmable_move_call(
      package,
      ident_str!("borrow_proposal").into(),
      ident_str!("put_back").into(),
      vec![obj_type.into()],
      vec![borrow_action, obj_arg],
    );
  });

  // Consume the now empty borrow_action
  ptb.programmable_move_call(
    package,
    ident_str!("borrow_proposal").into(),
    ident_str!("conclude_borrow").into(),
    vec![],
    vec![borrow_action],
  );

  Ok(())
}

pub(crate) fn propose_borrow(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  objects: Vec<ObjectID>,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let ProposalContext {
    mut ptb, capability, ..
  } = borrow_proposal_impl(identity, capability, objects, expiration, package_id)?;

  capability.put_back(&mut ptb, package_id);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn execute_borrow<F>(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  proposal_id: ObjectID,
  objects: Vec<IotaObjectData>,
  intent_fn: F,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error>
where
  F: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>),
{
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package)?;
  let proposal_id = ptb.pure(proposal_id)?;

  execute_borrow_impl(
    &mut ptb,
    identity,
    capability.arg(),
    proposal_id,
    objects,
    intent_fn,
    package,
  )?;

  capability.put_back(&mut ptb, package);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn create_and_execute_borrow<F>(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  objects: Vec<IotaObjectData>,
  intent_fn: F,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> anyhow::Result<ProgrammableTransactionBcs, Error>
where
  F: FnOnce(&mut Ptb, &HashMap<ObjectID, (Argument, IotaObjectData)>),
{
  let ProposalContext {
    mut ptb,
    capability,
    identity,
    proposal_id,
  } = borrow_proposal_impl(
    identity,
    capability,
    objects.iter().map(|obj_data| obj_data.object_id).collect_vec(),
    expiration,
    package_id,
  )?;

  execute_borrow_impl(
    &mut ptb,
    identity,
    capability.arg(),
    proposal_id,
    objects,
    intent_fn,
    package_id,
  )?;

  capability.put_back(&mut ptb, package_id);

  Ok(bcs::to_bytes(&ptb.finish())?)
}
