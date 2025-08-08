// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::str::FromStr as _;

use iota_interaction::ident_str;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::TypeTag;
use iota_interaction::ProgrammableTransactionBcs;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::iota::move_calls::ControllerTokenRef;
use crate::rebased::rebased_err;
use crate::rebased::Error;

use super::ControllerTokenArg;

#[allow(clippy::too_many_arguments)]
pub(crate) fn propose_config_change<I1, I2>(
  identity: OwnedObjectRef,
  controller_cap: ControllerTokenRef,
  expiration: Option<u64>,
  threshold: Option<u64>,
  controllers_to_add: I1,
  controllers_to_remove: HashSet<ObjectID>,
  controllers_to_update: I2,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error>
where
  I1: IntoIterator<Item = (IotaAddress, u64)>,
  I2: IntoIterator<Item = (ObjectID, u64)>,
{
  let mut ptb = Ptb::new();

  let controllers_to_add = {
    let (addresses, vps): (Vec<IotaAddress>, Vec<u64>) = controllers_to_add.into_iter().unzip();
    let addresses = ptb.pure(addresses).map_err(rebased_err)?;
    let vps = ptb.pure(vps).map_err(rebased_err)?;

    ptb.programmable_move_call(
      package,
      ident_str!("utils").into(),
      ident_str!("vec_map_from_keys_values").into(),
      vec![TypeTag::Address, TypeTag::U64],
      vec![addresses, vps],
    )
  };
  let controllers_to_update = {
    let (ids, vps): (Vec<ObjectID>, Vec<u64>) = controllers_to_update.into_iter().unzip();
    let ids = ptb.pure(ids).map_err(rebased_err)?;
    let vps = ptb.pure(vps).map_err(rebased_err)?;

    ptb.programmable_move_call(
      package,
      ident_str!("utils").into(),
      ident_str!("vec_map_from_keys_values").into(),
      vec![TypeTag::from_str("0x2::object::ID").expect("valid utf8"), TypeTag::U64],
      vec![ids, vps],
    )
  };
  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true).map_err(rebased_err)?;
  let capability = ControllerTokenArg::from_ref(controller_cap, &mut ptb, package)?;
  let expiration = utils::option_to_move(expiration, &mut ptb, package).map_err(rebased_err)?;
  let threshold = utils::option_to_move(threshold, &mut ptb, package).map_err(rebased_err)?;
  let controllers_to_remove = ptb.pure(controllers_to_remove).map_err(rebased_err)?;

  let _proposal_id = ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("propose_config_change").into(),
    vec![],
    vec![
      identity,
      capability.arg(),
      expiration,
      threshold,
      controllers_to_add,
      controllers_to_remove,
      controllers_to_update,
    ],
  );

  capability.put_back(&mut ptb, package);

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn execute_config_change(
  identity: OwnedObjectRef,
  controller_cap: ControllerTokenRef,
  proposal_id: ObjectID,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();

  let identity = utils::owned_ref_to_shared_object_arg(identity, &mut ptb, true).map_err(rebased_err)?;
  let capability = ControllerTokenArg::from_ref(controller_cap, &mut ptb, package)?;
  let proposal_id = ptb.pure(proposal_id).map_err(rebased_err)?;
  ptb.programmable_move_call(
    package,
    ident_str!("identity").into(),
    ident_str!("execute_config_change").into(),
    vec![],
    vec![identity, capability.arg(), proposal_id],
  );

  capability.put_back(&mut ptb, package);

  Ok(bcs::to_bytes(&ptb.finish())?)
}
