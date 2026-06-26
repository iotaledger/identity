// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::rpc_types::OwnedObjectRef;
use iota_interaction::types::base_types::ObjectRef;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::CallArg;
use iota_interaction::types::IOTA_FRAMEWORK_PACKAGE_ID;
use iota_interaction::ProgrammableTransactionBcs;
use iota_sdk_types::ObjectId;

use crate::rebased::Error;

use super::utils;

pub(crate) fn migrate_did_output(
  did_output: ObjectRef,
  creation_timestamp: Option<u64>,
  migration_registry: OwnedObjectRef,
  package: ObjectId,
) -> anyhow::Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let did_output = ptb.obj(CallArg::ImmutableOrOwned(did_output))?;
  let migration_registry = utils::owned_ref_to_shared_object_arg(migration_registry, &mut ptb, true)?;
  let clock = utils::get_clock_ref(&mut ptb);

  let creation_timestamp = match creation_timestamp {
    Some(timestamp) => ptb.pure(timestamp)?,
    _ => ptb.programmable_move_call(
      IOTA_FRAMEWORK_PACKAGE_ID,
      ident_str!("clock").as_str().into(),
      ident_str!("timestamp_ms").as_str().into(),
      vec![],
      vec![clock],
    ),
  };

  ptb.programmable_move_call(
    package,
    ident_str!("migration").as_str().into(),
    ident_str!("migrate_alias_output").as_str().into(),
    vec![],
    vec![did_output, migration_registry, creation_timestamp, clock],
  );

  Ok(bcs::to_bytes(&ptb.finish())?)
}
