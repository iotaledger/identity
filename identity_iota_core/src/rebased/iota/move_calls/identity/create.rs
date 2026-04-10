// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::unresolved::Argument;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TypeTag;

pub(crate) fn new_identity(ptb: &mut TransactionBuilder<Client>, did_doc: Option<&[u8]>, package_id: ObjectId) {
  let doc_arg = ptb.pure(did_doc);
  let clock = ptb.apply_argument(ObjectId::CLOCK);

  // Create a new identity, sending its capability to the tx's sender.
  ptb.move_call(package_id, "identity", "new").arguments([doc_arg, clock]);
}

pub(crate) fn new_with_controllers(
  ptb: &mut TransactionBuilder<Client>,
  did_doc: Option<&[u8]>,
  controllers: impl IntoIterator<Item = (Address, u64, bool)>,
  threshold: u64,
  package_id: ObjectId,
) {
  use itertools::Either;
  use itertools::Itertools as _;

  let (controllers_that_can_delegate, controllers): (Vec<_>, Vec<_>) =
    controllers.into_iter().partition_map(|(address, vp, can_delegate)| {
      if can_delegate {
        Either::Left((address, vp))
      } else {
        Either::Right((address, vp))
      }
    });

  let mut make_vec_map = |controllers: Vec<(Address, u64)>| -> Argument {
    let (ids, vps): (Vec<_>, Vec<_>) = controllers.into_iter().unzip();
    let ids = ptb.pure(ids);
    let vps = ptb.pure(vps);

    ptb
      .move_call(package_id, "utils", "vec_map_from_keys_values")
      .type_tags([TypeTag::Address, TypeTag::U64])
      .arguments([ids, vps])
      .arg()
  };

  let controllers = make_vec_map(controllers);
  let controllers_that_can_delegate = make_vec_map(controllers_that_can_delegate);
  let doc_arg = ptb.pure(did_doc);
  let threshold_arg = ptb.pure(threshold);
  let clock = ptb.apply_argument(ObjectId::CLOCK);

  // Create a new identity, sending its capabilities to the specified controllers.
  ptb
    .move_call(package_id, "identity", "new_with_controllers")
    .arguments([
      doc_arg,
      controllers,
      controllers_that_can_delegate,
      threshold_arg,
      clock,
    ]);
}
