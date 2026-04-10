// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::Shared;
use iota_sdk::transaction_builder::SharedMut;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use product_core::CLOCK_ADDRESS;

pub(crate) fn migrate_did_output(
  ptb: &mut TransactionBuilder<Client>,
  did_output: ObjectId,
  creation_timestamp: Option<u64>,
  migration_registry: ObjectId,
  package: ObjectId,
) {
  let did_output = ptb.apply_argument(did_output);
  let migration_registry = ptb.apply_argument(SharedMut(migration_registry));
  let clock = ptb.apply_argument(Shared(CLOCK_ADDRESS));

  let creation_timestamp = if let Some(timestamp) = creation_timestamp {
    ptb.pure(timestamp)
  } else {
    ptb
      .move_call(Address::FRAMEWORK, "clock", "timestamp_ms")
      .arguments(clock)
      .arg()
  };

  ptb.move_call(package, "migration", "migrate_alias_output").arguments([
    did_output,
    migration_registry,
    creation_timestamp,
    clock,
  ]);
}
