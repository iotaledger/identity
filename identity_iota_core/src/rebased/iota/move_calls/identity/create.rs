// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::ident_str;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::TypeTag;
use iota_interaction::OptionalSend;
use iota_interaction::ProgrammableTransactionBcs;

use crate::rebased::iota::move_calls::utils;
use crate::rebased::Error;

pub(crate) async fn new_identity(
  did_doc: Option<&[u8]>,
  package_id: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = Ptb::new();
  let doc_arg = utils::ptb_pure(&mut ptb, "did_doc", did_doc)?;
  let clock = utils::get_clock_ref(&mut ptb);

  // Create a new identity, sending its capability to the tx's sender.
  let _identity_id = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").into(),
    ident_str!("new").into(),
    vec![],
    vec![doc_arg, clock],
  );

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) async fn new_with_controllers<C>(
  did_doc: Option<&[u8]>,
  controllers: C,
  threshold: u64,
  package_id: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error>
where
  C: IntoIterator<Item = (IotaAddress, u64, bool)> + OptionalSend,
{
  use itertools::Either;
  use itertools::Itertools as _;

  let mut ptb = Ptb::new();

  let (controllers_that_can_delegate, controllers): (Vec<_>, Vec<_>) =
    controllers.into_iter().partition_map(|(address, vp, can_delegate)| {
      if can_delegate {
        Either::Left((address, vp))
      } else {
        Either::Right((address, vp))
      }
    });

  let mut make_vec_map = |controllers: Vec<(IotaAddress, u64)>| -> Result<Argument, Error> {
    let (ids, vps): (Vec<_>, Vec<_>) = controllers.into_iter().unzip();
    let ids = ptb.pure(ids).map_err(|e| Error::InvalidArgument(e.to_string()))?;
    let vps = ptb.pure(vps).map_err(|e| Error::InvalidArgument(e.to_string()))?;
    Ok(ptb.programmable_move_call(
      package_id,
      ident_str!("utils").into(),
      ident_str!("vec_map_from_keys_values").into(),
      vec![TypeTag::Address, TypeTag::U64],
      vec![ids, vps],
    ))
  };

  let controllers = make_vec_map(controllers)?;
  let controllers_that_can_delegate = make_vec_map(controllers_that_can_delegate)?;
  let doc_arg = ptb.pure(did_doc).map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let threshold_arg = ptb.pure(threshold).map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let clock = utils::get_clock_ref(&mut ptb);

  // Create a new identity, sending its capabilities to the specified controllers.
  let _identity_id = ptb.programmable_move_call(
    package_id,
    ident_str!("identity").into(),
    ident_str!("new_with_controllers").into(),
    vec![],
    vec![
      doc_arg,
      controllers,
      controllers_that_can_delegate,
      threshold_arg,
      clock,
    ],
  );

  Ok(bcs::to_bytes(&ptb.finish())?)
}
