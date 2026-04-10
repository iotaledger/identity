// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::ObjectId;

use crate::rebased::migration::ControllerToken;

use super::ControllerTokenArg;

pub(crate) fn propose_upgrade(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  expiration: Option<u64>,
  package_id: ObjectId,
) {
  let capability = ControllerTokenArg::from_token(capability, ptb, package_id);
  let identity_arg = ptb.apply_argument(SharedMut(identity));
  let exp_arg = ptb.pure(expiration);

  ptb
    .move_call(package_id, "identity", "propose_upgrade")
    .arguments([identity_arg, capability.arg(), exp_arg]);

  capability.put_back(ptb, package_id);
}

pub(crate) fn execute_upgrade(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  proposal_id: ObjectId,
  package_id: ObjectId,
) {
  let capability = ControllerTokenArg::from_token(capability, ptb, package_id)?;
  let proposal_id = ptb.pure(proposal_id);
  let identity_arg = ptb.apply_argument(SharedMut(identity));

  ptb
    .move_call(package_id, "identity", "execute_upgrade")
    .arguments([identity_arg, capability.arg(), proposal_id]);

  capability.put_back(&mut ptb, package_id);
}
