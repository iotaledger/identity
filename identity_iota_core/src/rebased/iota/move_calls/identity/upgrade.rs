// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::ProgrammableTransactionBcs;
use iota_interaction::rpc_types::OwnedObjectRef;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::iota::move_calls::ControllerTokenRef;
use crate::rebased::rebased_err;
use crate::rebased::Error;

use super::ControllerTokenArg;

pub(crate) fn propose_upgrade(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  expiration: Option<u64>,
  package_id: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package_id)?;
  let identity_arg = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let exp_arg = utils::option_to_move(expiration, &mut ptb, package_id).map_err(rebased_err)?;

  let _proposal_id = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").into(),
    ident_str!("propose_upgrade").into(),
    vec![],
    vec![identity_arg, capability.arg(), exp_arg],
  );

  capability.put_back(&mut ptb, package_id);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn execute_upgrade(
  identity: OwnedObjectRef,
  capability: ControllerTokenRef,
  proposal_id: ObjectID,
  package_id: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let capability = ControllerTokenArg::from_ref(capability, &mut ptb, package_id)?;
  let proposal_id = ptb.pure(proposal_id).map_err(rebased_err)?;
  let identity_arg = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true).map_err(rebased_err)?;

  let _ = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").into(),
    ident_str!("execute_upgrade").into(),
    vec![],
    vec![identity_arg, capability.arg(), proposal_id],
  );

  capability.put_back(&mut ptb, package_id);

  Ok(bcs::to_bytes(&ptb.finish())?)
}