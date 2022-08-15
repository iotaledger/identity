// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_stardust::Error;
use identity_stardust::StardustClientExt;
use identity_stardust::StardustDocument;
use iota_client::block::address::Address;
use iota_client::secret::SecretManager;
use iota_client::Client;

mod ex0_create_did;

/// Demonstrate how to delete an existing DID in an Alias Output, reclaiming the stored deposit.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // Create a new DID in an Alias Output for us to modify.
  let (client, address, secret_manager, document): (Client, Address, SecretManager, StardustDocument) =
    ex0_create_did::run().await?;

  // Deletes the Alias Output and its contained DID Document, rendering the DID permanently destroyed.
  // This operation is *not* reversible.
  // Deletion can only be done by the governor of the Alias Output.
  client
    .delete_did_output(&secret_manager, address, document.id())
    .await?;

  // Attempting to resolve a deleted DID results in a `NotFound` error.
  let error: Error = client.resolve_did(document.id()).await.unwrap_err();

  assert!(matches!(
    error,
    identity_stardust::Error::DIDResolutionError(iota_client::Error::NotFound)
  ));

  Ok(())
}
