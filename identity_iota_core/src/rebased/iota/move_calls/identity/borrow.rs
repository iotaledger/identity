// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::unresolved::Argument;
use iota_sdk::transaction_builder::Receiving;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Object;
use iota_sdk::types::ObjectId;
use itertools::Itertools as _;
use product_core::move_type::MoveType;
use product_core::network::Network;

use crate::rebased::migration::ControllerToken;
use crate::rebased::proposals::BorrowAction;

use super::ControllerTokenArg;
use super::ProposalContext;

fn borrow_proposal_impl<'a>(
  ptb: &'a mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  objects: Vec<ObjectId>,
  expiration: Option<u64>,
  package_id: ObjectId,
) -> ProposalContext<'a> {
  let capability = ControllerTokenArg::from_token(capability, ptb, package_id);
  let identity_arg = ptb.apply_argument(SharedMut(identity));
  let exp_arg = ptb.pure(expiration);
  let objects_arg = ptb.pure(objects);

  let proposal_id = ptb
    .move_call(package_id, "identity", "propose_borrow")
    .arguments([identity_arg, capability.arg(), exp_arg, objects_arg])
    .arg();

  ProposalContext {
    ptb,
    identity: identity_arg,
    capability,
    proposal_id,
  }
}

pub(crate) fn execute_borrow_impl<F>(
  ptb: &mut TransactionBuilder<Client>,
  identity: Argument,
  delegation_token: Argument,
  proposal_id: Argument,
  objects: Vec<Object>,
  intent_fn: F,
  package: ObjectId,
  network: Network,
) where
  F: FnOnce(&mut TransactionBuilder<Client>, &HashMap<ObjectId, (Argument, Object)>),
{
  // Get the proposal's action as argument.
  let borrow_action = ptb
    .move_call(package, "identity", "execute_proposal")
    .type_tags(BorrowAction::move_type(network))
    .arguments([identity, delegation_token, proposal_id])
    .arg();

  // Borrow all the objects specified in the action.
  let mut obj_arg_map = HashMap::new();
  for obj in objects {
    let type_ = obj.object_type().into_struct();
    let recv_obj = ptb.apply_argument(Receiving(obj.object_id()));
    let obj_arg = ptb
      .move_call(package, "identity", "execute_borrow")
      .type_tags(type_.into())
      .arguments([identity, borrow_action, recv_obj])
      .arg();

    obj_arg_map.insert(obj.object_id(), (obj_arg, obj));
  }

  // Apply the user-defined operation.
  intent_fn(ptb, &obj_arg_map);

  // Put back all the objects.
  for (obj_arg, obj_data) in obj_arg_map.into_values() {
    let obj_type = obj_data.object_type().into_struct();
    ptb
      .move_call(package, "identity", "put_back")
      .type_tags(obj_type.into())
      .arguments([borrow_action, obj_arg]);
  }

  // Consume the now empty borrow_action
  ptb
    .move_call(package, "borrow_proposal", "conclude_borrow")
    .arguments([borrow_action]);
}

pub(crate) fn propose_borrow(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  objects: Vec<ObjectId>,
  expiration: Option<u64>,
  package_id: ObjectId,
) {
  let ProposalContext { ptb, capability, .. } =
    borrow_proposal_impl(ptb, identity, capability, objects, expiration, package_id)?;

  capability.put_back(ptb, package_id);
}

pub(crate) fn execute_borrow<F>(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  proposal_id: ObjectId,
  objects: Vec<Object>,
  intent_fn: F,
  package: ObjectId,
  network: Network,
) where
  F: FnOnce(&mut TransactionBuilder<Client>, &HashMap<ObjectId, (Argument, Object)>),
{
  let identity = ptb.apply_argument(SharedMut(identity));
  let capability = ControllerTokenArg::from_token(capability, ptb, package)?;
  let proposal_id = ptb.pure(proposal_id)?;

  execute_borrow_impl(
    &mut ptb,
    identity,
    capability.arg(),
    proposal_id,
    objects,
    intent_fn,
    package,
    network,
  );

  capability.put_back(ptb, package);
}

pub(crate) fn create_and_execute_borrow<F>(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  objects: Vec<Object>,
  intent_fn: F,
  expiration: Option<u64>,
  package_id: ObjectId,
  network: Network,
) where
  F: FnOnce(&mut TransactionBuilder<Client>, &HashMap<ObjectId, (Argument, Object)>),
{
  let ProposalContext {
    mut ptb,
    capability,
    identity,
    proposal_id,
  } = borrow_proposal_impl(
    ptb,
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
    network,
  );

  capability.put_back(&mut ptb, package_id);
}
