// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::ObjectId;

use crate::rebased::migration::ControllerToken;

use super::ControllerTokenArg;

pub(crate) fn propose_update(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  did_doc: Option<&[u8]>,
  expiration: Option<u64>,
  package_id: ObjectId,
) {
  let capability = ControllerTokenArg::from_token(capability, ptb, package_id)?;
  let identity_arg = ptb.apply_argument(SharedMut(identity));
  let exp_arg = ptb.pure(expiration);
  let doc_arg = ptb.pure(did_doc);
  let clock = ptb.apply_argument(ObjectId::CLOCK);

  ptb.move_call(package_id, "identity", "propose_update").arguments([
    identity_arg,
    capability.arg(),
    doc_arg,
    exp_arg,
    clock,
  ]);

  capability.put_back(&mut ptb, package_id);
}

pub(crate) fn execute_update(
  ptb: &mut TransactionBuilder<Client>,
  identity: ObjectId,
  capability: &ControllerToken,
  proposal_id: ObjectId,
  package_id: ObjectId,
) {
  let capability = ControllerTokenArg::from_token(capability, ptb, package_id)?;
  let proposal_id = ptb.pure(proposal_id);
  let identity_arg = ptb.apply_argument(SharedMut(identity));
  let clock = ptb.apply_argument(ObjectId::CLOCK);

  ptb.move_call(package_id, "identity", "execute_update").arguments([
    identity_arg,
    capability.arg(),
    proposal_id,
    clock,
  ]);

  capability.put_back(&mut ptb, package_id);
}
