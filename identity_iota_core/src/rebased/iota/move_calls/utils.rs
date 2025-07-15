// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::base_types::STD_OPTION_MODULE_NAME;
use iota_interaction::types::object::Owner;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::ObjectArg;
use iota_interaction::types::IOTA_CLOCK_OBJECT_ID;
use iota_interaction::types::IOTA_CLOCK_OBJECT_SHARED_VERSION;
use iota_interaction::types::MOVE_STDLIB_PACKAGE_ID;
use iota_interaction::MoveType;
use serde::Serialize;

use crate::rebased::Error;

/// Adds a reference to the on-chain clock to `ptb`'s arguments.
pub(crate) fn get_clock_ref(ptb: &mut Ptb) -> Argument {
  ptb
    .obj(ObjectArg::SharedObject {
      id: IOTA_CLOCK_OBJECT_ID,
      initial_shared_version: IOTA_CLOCK_OBJECT_SHARED_VERSION,
      mutable: false,
    })
    .expect("network has a singleton clock instantiated")
}

pub(crate) fn get_controller_delegation(
  ptb: &mut Ptb,
  controller_cap: Argument,
  package: ObjectID,
) -> (Argument, Argument) {
  let Argument::Result(idx) = ptb.programmable_move_call(
    package,
    ident_str!("controller").into(),
    ident_str!("borrow").into(),
    vec![],
    vec![controller_cap],
  ) else {
    unreachable!("making move calls always return a result variant");
  };

  (Argument::NestedResult(idx, 0), Argument::NestedResult(idx, 1))
}

pub(crate) fn put_back_delegation_token(
  ptb: &mut Ptb,
  controller_cap: Argument,
  delegation_token: Argument,
  borrow: Argument,
  package: ObjectID,
) {
  ptb.programmable_move_call(
    package,
    ident_str!("controller").into(),
    ident_str!("put_back").into(),
    vec![],
    vec![controller_cap, delegation_token, borrow],
  );
}

pub(crate) fn owned_ref_to_shared_object_arg(
  owned_ref: OwnedObjectRef,
  ptb: &mut Ptb,
  mutable: bool,
) -> anyhow::Result<Argument> {
  let Owner::Shared { initial_shared_version } = owned_ref.owner else {
    anyhow::bail!("Object \"{}\" is not a shared object", owned_ref.object_id());
  };
  ptb.obj(ObjectArg::SharedObject {
    id: owned_ref.object_id(),
    initial_shared_version,
    mutable,
  })
}

pub(crate) fn option_to_move<T: MoveType + Serialize>(
  option: Option<T>,
  ptb: &mut Ptb,
  package: ObjectID,
) -> Result<Argument, anyhow::Error> {
  let arg = if let Some(t) = option {
    let t = ptb.pure(t)?;
    ptb.programmable_move_call(
      MOVE_STDLIB_PACKAGE_ID,
      STD_OPTION_MODULE_NAME.into(),
      ident_str!("some").into(),
      vec![T::move_type(package)],
      vec![t],
    )
  } else {
    ptb.programmable_move_call(
      MOVE_STDLIB_PACKAGE_ID,
      STD_OPTION_MODULE_NAME.into(),
      ident_str!("none").into(),
      vec![T::move_type(package)],
      vec![],
    )
  };

  Ok(arg)
}

pub(crate) fn ptb_pure<T>(ptb: &mut Ptb, name: &str, value: T) -> Result<Argument, Error>
where
  T: Serialize + core::fmt::Debug,
{
  ptb.pure(&value).map_err(|err| {
    Error::InvalidArgument(format!(
      r"could not serialize pure value {name} with value {value:?}; {err}"
    ))
  })
}

#[allow(dead_code)]
pub(crate) fn ptb_obj(ptb: &mut Ptb, name: &str, value: ObjectArg) -> Result<Argument, Error> {
  ptb
    .obj(value)
    .map_err(|err| Error::InvalidArgument(format!("could not serialize object {name} {value:?}; {err}")))
}
