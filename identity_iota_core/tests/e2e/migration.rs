// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::get_funded_test_client;
use identity_iota_core::rebased::migration;
use iota_sdk::types::base_types::ObjectID;

#[tokio::test]
async fn migration_registry_is_found() -> anyhow::Result<()> {
  let client = get_funded_test_client().await?;
  let random_alias_id = ObjectID::random();

  let doc = migration::lookup(&client, random_alias_id).await?;
  assert!(doc.is_none());

  Ok(())
}
