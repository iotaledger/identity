// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::CallArg;
use iota_interaction::types::transaction::ObjectArg;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::MoveType as _;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::iota::move_calls::ControllerTokenRef;
use crate::rebased::iota::ptb_merge_tx_with_inputs_replacement;
use crate::rebased::proposals::AccessSubIdentity;
use crate::rebased::Error;

use super::ControllerTokenArg;
use super::ProposalContext;

pub(crate) fn propose_identity_sub_access(
  identity: OwnedObjectRef,
  sub_identity: OwnedObjectRef,
  identity_token: ControllerTokenRef,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> Result<ProgrammableTransaction, Error> {
  let ProposalContext {
    mut ptb, capability, ..
  } = identity_sub_access_impl(identity, sub_identity, identity_token, expiration, package_id)?;
  capability.put_back(&mut ptb, package_id);

  Ok(ptb.finish())
}

pub(crate) fn execute_sub_identity_access(
  identity: OwnedObjectRef,
  identity_token: ControllerTokenRef,
  proposal_id: ObjectID,
  sub_identity_token: ControllerTokenRef,
  inner_pt: ProgrammableTransaction,
  package: ObjectID,
) -> Result<ProgrammableTransaction, Error> {
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let identity_token = ControllerTokenArg::from_ref(identity_token, &mut ptb, package)?;
  let proposal_id = ptb.pure(proposal_id)?;

  execute_sub_identity_access_impl(
    &mut ptb,
    identity,
    proposal_id,
    identity_token.arg(),
    sub_identity_token,
    inner_pt,
    package,
  )?;

  identity_token.put_back(&mut ptb, package);

  Ok(ptb.finish())
}

pub(crate) fn propose_and_execute_sub_identity_access(
  identity: OwnedObjectRef,
  sub_identity: OwnedObjectRef,
  identity_token: ControllerTokenRef,
  sub_identity_token: ControllerTokenRef,
  inner_pt: ProgrammableTransaction,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> Result<ProgrammableTransaction, Error> {
  let ProposalContext {
    mut ptb,
    capability,
    proposal_id,
    identity,
  } = identity_sub_access_impl(identity, sub_identity, identity_token, expiration, package_id)?;

  execute_sub_identity_access_impl(
    &mut ptb,
    identity,
    proposal_id,
    capability.arg(),
    sub_identity_token,
    inner_pt,
    package_id,
  )?;

  capability.put_back(&mut ptb, package_id);

  Ok(ptb.finish())
}

fn identity_sub_access_impl(
  identity: OwnedObjectRef,
  sub_identity: OwnedObjectRef,
  identity_token: ControllerTokenRef,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> anyhow::Result<ProposalContext> {
  let mut ptb = Ptb::new();
  let cap = ControllerTokenArg::from_ref(identity_token, &mut ptb, package_id)?;
  let identity_arg = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let sub_identity_arg = utils::owned_ref_to_shared_object_arg(sub_identity, &mut ptb, false)?;
  let exp_arg = ptb.pure(expiration)?;

  let proposal_id = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").into(),
    ident_str!("propose_access_to_sub_identity").into(),
    vec![],
    vec![identity_arg, cap.arg(), sub_identity_arg, exp_arg],
  );

  Ok(ProposalContext {
    ptb,
    capability: cap,
    identity: identity_arg,
    proposal_id,
  })
}

pub(crate) fn execute_sub_identity_access_impl(
  ptb: &mut Ptb,
  identity: Argument,
  proposal_id: Argument,
  identity_token: Argument,
  sub_identity_token: ControllerTokenRef,
  inner_pt: ProgrammableTransaction,
  package: ObjectID,
) -> anyhow::Result<()> {
  // Get the proposal's action as argument.
  let action = ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("execute_proposal").into(),
    vec![AccessSubIdentity::move_type(package)],
    vec![identity, identity_token, proposal_id],
  );

  // Borrow the sub_identity_token into this transaction.
  let receiving_sub_identity_token = ptb.obj(ObjectArg::Receiving(sub_identity_token.object_ref()))?;
  let borrowed_token_to_sub_identity = if sub_identity_token.is_controller_cap() {
    ptb.programmable_move_call(
      package,
      ident_str!("identity").into(),
      ident_str!("borrow_controller_cap_to_sub_identity").into(),
      vec![],
      vec![identity, action, receiving_sub_identity_token],
    )
  } else {
    ptb.programmable_move_call(
      package,
      ident_str!("identity").into(),
      ident_str!("borrow_delegation_token_to_sub_identity").into(),
      vec![],
      vec![identity, action, receiving_sub_identity_token],
    )
  };

  // Merge inner_pt into this PTB by making sure the controller token used to access the sub_identity in
  // `inner_pt` is replaced with the same controller token but as an argument of this PTB.
  ptb_merge_tx_with_inputs_replacement(
    ptb,
    inner_pt,
    vec![(
      CallArg::Object(ObjectArg::ImmOrOwnedObject(sub_identity_token.object_ref())),
      borrowed_token_to_sub_identity,
    )],
  );

  // Return the the borrowed controller token.
  if sub_identity_token.is_controller_cap() {
    ptb.programmable_move_call(
      package,
      ident_str!("access_sub_entity_proposal").into(),
      ident_str!("put_back_controller_cap").into(),
      vec![],
      vec![action, borrowed_token_to_sub_identity],
    );
  } else {
    ptb.programmable_move_call(
      package,
      ident_str!("access_sub_entity_proposal").into(),
      ident_str!("put_back_delegation_token").into(),
      vec![],
      vec![action, borrowed_token_to_sub_identity],
    );
  }

  Ok(())
}
