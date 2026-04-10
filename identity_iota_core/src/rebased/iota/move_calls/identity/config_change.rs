// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TypeTag;

use crate::rebased::migration::ControllerToken;

use super::ControllerTokenArg;

#[allow(clippy::too_many_arguments)]
pub(crate) fn propose_config_change<I1, I2>(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  controller_cap: &ControllerToken,
  expiration: Option<u64>,
  threshold: Option<u64>,
  controllers_to_add: I1,
  controllers_to_remove: HashSet<ObjectId>,
  controllers_to_update: I2,
  package: ObjectId,
) {
  let controllers_to_add = {
    let (addresses, vps): (Vec<Address>, Vec<u64>) = controllers_to_add.into_iter().unzip();
    let addresses = ptb.pure(addresses);
    let vps = ptb.pure(vps);

    ptb
      .move_call(package, "utils", "vec_map_from_keys_values")
      .arguments([addresses, vps])
      .type_tags([TypeTag::Address, TypeTag::U64])
      .arg()
  };
  let controllers_to_update = {
    let (ids, vps): (Vec<ObjectId>, Vec<u64>) = controllers_to_update.into_iter().unzip();
    let ids = ptb.pure(ids);
    let vps = ptb.pure(vps);

    ptb
      .move_call(package, "utils", "vec_map_from_keys_values")
      .arguments([ids, vps])
      .type_tags([TypeTag::from_str("0x2::object::ID").expect("valid utf8"), TypeTag::U64])
      .arg()
  };
  let identity = ptb.apply_argument(SharedMut(identity));
  let capability = ControllerTokenArg::from_token(controller_cap, ptb, package);
  let expiration = ptb.pure(expiration);
  let threshold = ptb.pure(threshold);
  let controllers_to_remove = ptb.pure(controllers_to_remove);

  ptb.move_call(package, "identity", "propose_config_change").arguments([
    identity,
    capability.arg(),
    expiration,
    threshold,
    controllers_to_add,
    controllers_to_remove,
    controllers_to_update,
  ]);

  capability.put_back(ptb, package);
}

pub(crate) fn execute_config_change(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  controller_cap: &ControllerToken,
  proposal_id: ObjectId,
  package: ObjectId,
) {
  let identity = ptb.apply_argument(SharedMut(identity));
  let capability = ControllerTokenArg::from_token(controller_cap, ptb, package);
  let proposal_id = ptb.pure(proposal_id);

  ptb
    .move_call(package, "identity", "execute_config_change")
    .arguments([identity, capability.arg(), proposal_id]);

  capability.put_back(ptb, package);
}
