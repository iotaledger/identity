// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did;
use examples::random_stronghold_path;
use examples::API_ENDPOINT;
use identity_iota::crypto::KeyPair;
use identity_iota::iota::Error;
use identity_iota::iota::IotaClientExt;

use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use iota_client::block::address::Address;
use iota_client::secret::stronghold::StrongholdSecretManager;
use iota_client::secret::SecretManager;
use iota_client::Client;

/// Demonstrates how to delete a DID in an Alias Output, reclaiming the storage deposit.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // Create a new client to interact with the IOTA ledger.
  let client: Client = Client::builder().with_primary_node(API_ENDPOINT, None)?.finish()?;

  // Create a new secret manager backed by a Stronghold.
  let mut secret_manager: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password("secure_password")
      .build(random_stronghold_path())?,
  );

  // Create a new DID in an Alias Output for us to modify.
  let (address, document, _): (Address, IotaDocument, KeyPair) = create_did(&client, &mut secret_manager).await?;
  let did = document.id().clone();

  // Deletes the Alias Output and its contained DID Document, rendering the DID permanently destroyed.
  // This operation is *not* reversible.
  // Deletion can only be done by the governor of the Alias Output.
  client.delete_did_output(&secret_manager, address, &did).await?;

  // Attempting to resolve a deleted DID results in a `NotFound` error.
  let error: Error = client.resolve_did(&did).await.unwrap_err();
  assert!(matches!(
    error,
    identity_iota::iota::Error::DIDResolutionError(iota_client::Error::NotFound(..))
  ));

  Ok(())
}
