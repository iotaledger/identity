// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::unresolved::Argument;
use iota_sdk::transaction_builder::Receiving;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TypeTag;
use product_core::network::Network;

use crate::rebased::migration::ControllerToken;
use crate::rebased::proposals::SendAction;

use super::ControllerTokenArg;
use super::ProposalContext;

pub(crate) fn propose_send(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  transfer_map: Vec<(ObjectId, Address)>,
  expiration: Option<u64>,
  package_id: ObjectId,
  network: Network,
) {
  let ProposalContext {
    mut ptb, capability, ..
  } = send_proposal_impl(ptb, identity, capability, transfer_map, expiration, package_id)?;

  capability.put_back(&mut ptb, package_id);
}

pub(crate) fn execute_send(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  proposal_id: ObjectId,
  objects: Vec<(ObjectId, TypeTag)>,
  package: ObjectId,
  network: Network,
) {
  let identity = ptb.apply_argument(SharedMut(identity));
  let capability = ControllerTokenArg::from_token(capability, &mut ptb, package)?;
  let proposal_id = ptb.pure(proposal_id)?;

  execute_send_impl(
    &mut ptb,
    identity,
    capability.arg(),
    proposal_id,
    objects,
    package,
    network,
  )?;

  capability.put_back(&mut ptb, package);
}

pub(crate) fn create_and_execute_send(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  transfer_map: Vec<(ObjectId, Address)>,
  expiration: Option<u64>,
  objects: Vec<(ObjectId, TypeTag)>,
  package: ObjectId,
  network: Network,
) {
  let ProposalContext {
    mut ptb,
    identity,
    capability,
    proposal_id,
  } = send_proposal_impl(ptb, identity, capability, transfer_map, expiration, package)?;

  execute_send_impl(
    &mut ptb,
    identity,
    capability.arg(),
    proposal_id,
    objects,
    package,
    network,
  )?;

  capability.put_back(&mut ptb, package);
}

fn send_proposal_impl<'a>(
  ptb: &'a mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  transfer_map: Vec<(ObjectId, Address)>,
  expiration: Option<u64>,
  package_id: ObjectId,
) -> ProposalContext<'a> {
  let capability = ControllerTokenArg::from_token(capability, &mut ptb, package_id)?;
  let identity_arg = ptb.apply_argument(SharedMut(identity));
  let exp_arg = ptb.pure(expiration);
  let (objects, recipients) = {
    let (objects, recipients): (Vec<_>, Vec<_>) = transfer_map.into_iter().unzip();
    let objects = ptb.pure(objects)?;
    let recipients = ptb.pure(recipients)?;

    (objects, recipients)
  };

  let proposal_id = ptb
    .move_call(package_id, "identity", "propose_send")
    .arguments([identity_arg, capability.arg(), exp_arg, objects, recipients])
    .arg();

  ProposalContext {
    ptb,
    identity: identity_arg,
    capability,
    proposal_id,
  }
}

pub(crate) fn execute_send_impl(
  ptb: &mut TransactionBuilder<Client>,
  identity: Argument,
  delegation_token: Argument,
  proposal_id: Argument,
  objects: Vec<(ObjectId, TypeTag)>,
  package: ObjectId,
  network: Network,
) {
  // Get the proposal's action as argument.
  let send_action = ptb
    .move_call(package, "identity", "execute_proposal")
    .type_tags(SendAction::move_type(network).expect("Failed to get SendAction type tag")?)
    .arguments([identity, delegation_token, proposal_id])
    .arg();

  // Send each object in this send action.
  // Traversing the map in reverse reduces the number of operations on the move side.
  for (obj, obj_type) in objects.into_iter().rev() {
    let recv_obj = ptb.apply_argument(Receiving(obj));

    ptb
      .move_call(package, "identity", "execute_send")
      .type_tags(obj_type)
      .arguments([identity, send_action, recv_obj]);
  }

  // Consume the now empty send_action
  ptb
    .move_call(package, "transfer_proposal", "complete_send")
    .arguments(send_action);
}
