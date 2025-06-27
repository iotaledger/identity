// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::ProgrammableTransactionBcs;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::transaction::ObjectArg;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectRef;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::rebased_err;
use crate::rebased::Error;

pub(crate) async fn delegate_controller_cap(
  controller_cap: ObjectRef,
  recipient: IotaAddress,
  permissions: u32,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let cap = ptb
    .obj(ObjectArg::ImmOrOwnedObject(controller_cap))
    .map_err(rebased_err)?;
  let permissions = ptb.pure(permissions).map_err(rebased_err)?;

  let delegation_token = ptb.programmable_move_call(
    package,
    ident_str!("controller").into(),
    ident_str!("delegate_with_permissions").into(),
    vec![],
    vec![cap, permissions],
  );

  ptb.transfer_arg(recipient, delegation_token);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn revoke_delegation_token(
  identity: OwnedObjectRef,
  controller_cap: ObjectRef,
  delegation_token_id: ObjectID,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let cap = ptb
    .obj(ObjectArg::ImmOrOwnedObject(controller_cap))
    .map_err(rebased_err)?;
  let delegation_token_id = ptb.pure(delegation_token_id).map_err(rebased_err)?;

  ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("revoke_token").into(),
    vec![],
    vec![identity, cap, delegation_token_id],
  );

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn unrevoke_delegation_token(
  identity: OwnedObjectRef,
  controller_cap: ObjectRef,
  delegation_token_id: ObjectID,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let cap = ptb
    .obj(ObjectArg::ImmOrOwnedObject(controller_cap))
    .map_err(rebased_err)?;
  let delegation_token_id = ptb.pure(delegation_token_id).map_err(rebased_err)?;

  ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("unrevoke_token").into(),
    vec![],
    vec![identity, cap, delegation_token_id],
  );

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) async fn destroy_delegation_token(
  identity: OwnedObjectRef,
  delegation_token: ObjectRef,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true)?;
  let delegation_token = ptb
    .obj(ObjectArg::ImmOrOwnedObject(delegation_token))
    .map_err(rebased_err)?;

  ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("destroy_delegation_token").into(),
    vec![],
    vec![identity, delegation_token],
  );

  Ok(bcs::to_bytes(&ptb.finish())?)
}