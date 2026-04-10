// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::unresolved::Argument;
use iota_sdk::transaction_builder::unresolved::Input;
use iota_sdk::transaction_builder::unresolved::InputKind;
use iota_sdk::transaction_builder::Receiving;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::ObjectId;
use iota_sdk::types::ProgrammableTransaction;
use product_core::network::Network;

use crate::rebased::iota::ptb_merge_tx_with_inputs_replacement;
use crate::rebased::migration::ControllerToken;
use crate::rebased::proposals::AccessSubIdentity;

use super::ControllerTokenArg;
use super::ProposalContext;

pub(crate) fn propose_identity_sub_access(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  sub_identity: ObjectId,
  identity_token: &ControllerToken,
  expiration: Option<u64>,
  package_id: ObjectId,
) {
  let ProposalContext {
    mut ptb, capability, ..
  } = identity_sub_access_impl(ptb, identity, sub_identity, identity_token, expiration, package_id);
  capability.put_back(&mut ptb, package_id);
}

pub(crate) fn execute_sub_identity_access(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  identity_token: &ControllerToken,
  proposal_id: ObjectId,
  sub_identity_token: &ControllerToken,
  inner_pt: ProgrammableTransaction,
  package: ObjectId,
  network: Network,
) {
  let identity = ptb.apply_argument(SharedMut(identity));
  let identity_token = ControllerTokenArg::from_token(identity_token, ptb, package);
  let proposal_id = ptb.pure(proposal_id);

  execute_sub_identity_access_impl(
    ptb,
    identity,
    proposal_id,
    identity_token.arg(),
    sub_identity_token,
    inner_pt,
    package,
    network,
  );

  identity_token.put_back(ptb, package);
}

pub(crate) fn propose_and_execute_sub_identity_access(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  sub_identity: ObjectId,
  identity_token: &ControllerToken,
  sub_identity_token: &ControllerToken,
  inner_pt: ProgrammableTransaction,
  expiration: Option<u64>,
  package_id: ObjectId,
  network: Network,
) {
  let ProposalContext {
    ptb,
    capability,
    proposal_id,
    identity,
  } = identity_sub_access_impl(ptb, identity, sub_identity, identity_token, expiration, package_id)?;

  execute_sub_identity_access_impl(
    ptb,
    identity,
    proposal_id,
    capability.arg(),
    sub_identity_token,
    inner_pt,
    package_id,
    network,
  )?;

  capability.put_back(ptb, package_id);
}

fn identity_sub_access_impl<'a>(
  ptb: &'a mut TransactionBuilder<Client>,
  identity: ObjectId,
  sub_identity: ObjectId,
  identity_token: &ControllerToken,
  expiration: Option<u64>,
  package_id: ObjectId,
) -> ProposalContext<'a> {
  let cap = ControllerTokenArg::from_token(identity_token, &mut ptb, package_id)?;
  let identity_arg = ptb.apply_argument(SharedMut(identity));
  let sub_identity_arg = ptb.apply_argument(SharedMut(sub_identity));
  let exp_arg = ptb.pure(expiration);

  let proposal_id = ptb
    .move_call(package_id, "identity", "propose_access_to_sub_identity")
    .arguments([identity_arg, cap.arg(), sub_identity_arg, exp_arg])
    .arg();

  ProposalContext {
    ptb,
    capability: cap,
    identity: identity_arg,
    proposal_id,
  }
}

pub(crate) fn execute_sub_identity_access_impl(
  ptb: &mut TransactionBuilder<Client>,
  identity: Argument,
  proposal_id: Argument,
  identity_token: Argument,
  sub_identity_token: &ControllerToken,
  inner_pt: ProgrammableTransaction,
  package: ObjectId,
  network: Network,
) {
  // Get the proposal's action as argument.
  let action = ptb
    .move_call(package, "identity", "execute_proposal")
    .type_tags(AccessSubIdentity::move_type(network).expect("move type can be determined"))
    .arguments([identity, identity_token, proposal_id])
    .arg();

  // Borrow the sub_identity_token into this transaction.
  let receiving_sub_identity_token = ptb.apply_argument(Receiving(sub_identity_token.id()));
  let borrowed_token_to_sub_identity = {
    let fn_name = if sub_identity_token.is_controller_cap() {
      "borrow_controller_cap_to_sub_identity"
    } else {
      "borrow_delegation_token_to_sub_identity"
    };
    ptb
      .move_call(package, "identity", fn_name)
      .arguments([identity, action, receiving_sub_identity_token])
      .arg()
  };

  // Merge inner_pt into this PTB by making sure the controller token used to access the sub_identity in
  // `inner_pt` is replaced with the same controller token but as an argument of this PTB.
  ptb_merge_tx_with_inputs_replacement(
    ptb,
    inner_pt,
    vec![(
      Input {
        kind: InputKind::ImmutableOrOwned(sub_identity_token.id()),
        is_gas: false,
      },
      borrowed_token_to_sub_identity,
    )],
  );

  let put_back_fn_name = if sub_identity_token.is_controller_cap() {
    "put_back_controller_cap"
  } else {
    "put_back_delegation_token"
  };

  // Return the the borrowed controller token.
  ptb
    .move_call(package, "identity", put_back_fn_name)
    .arguments([action, borrowed_token_to_sub_identity]);
}
