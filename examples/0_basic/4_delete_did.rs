// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::get_funded_client;
use examples::get_memstorage;
use identity_iota::iota::rebased::Error;
use identity_iota::iota::IotaDocument;

/// Demonstrates how to delete a DID in an identity.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let storage = get_memstorage()?;
  let client = get_funded_client(&storage).await?;
  let mut identity = client
    .create_identity(IotaDocument::new(client.network()))
    .finish()
    .build_and_execute(&client)
    .await?
    .output;
  let did = identity.did_document().id().clone();

  println!("Created a new Identity containing DID Document {did}");

  // Delete the DID we just created.
  let controller_token = identity.get_controller_token(&client).await?.expect("is a controller");
  identity
    .delete_did(&controller_token)
    .finish(&client)
    .await?
    .build_and_execute(&client)
    .await?;

  assert!(identity.has_deleted_did());
  assert_eq!(identity.did_document().metadata.deactivated, Some(true));

  println!("DID {did} was successfully deleted!");

  // Trying to update a deleted DID Document must fail.
  let err = identity
    .update_did_document(IotaDocument::new(client.network()), &controller_token)
    .finish(&client)
    .await;
  assert!(matches!(err, Err(Error::Identity(_))));

  // Resolution of the DID document through its DID must fail.
  let err = client.resolve_did(&did).await.unwrap_err();
  assert!(matches!(err, Error::DIDResolutionError(_)));

  Ok(())
}
