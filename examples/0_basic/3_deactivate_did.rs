// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use examples::TEST_GAS_BUDGET;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;

/// Demonstrates how to deactivate a DID in an identity.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // create new client to interact with chain and get funded account with keys
  let storage = get_memstorage()?;
  let identity_client = get_funded_client(&storage).await?;

  // create new DID document and publish it
  let (document, _) = create_did_document(&identity_client, &storage).await?;

  println!("Published DID document: {document:#}");

  let did: IotaDID = document.id().clone();

  // Deactivate the DID by publishing an empty document.
  // This process can be reversed since the identity is not destroyed.
  // Deactivation may only be performed by a controller of the identity.
  identity_client.deactivate_did_output(&did, TEST_GAS_BUDGET).await?;

  // Resolving a deactivated DID returns an empty DID document
  // with its `deactivated` metadata field set to `true`.
  let deactivated: IotaDocument = identity_client.resolve_did(&did).await?;
  println!("Deactivated DID document: {deactivated:#}");
  assert_eq!(deactivated.metadata.deactivated, Some(true));

  // Re-activate the DID by publishing a valid DID document.
  let reactivated: IotaDocument = identity_client
    .publish_did_document_update(document.clone(), TEST_GAS_BUDGET)
    .await?;
  println!("Reactivated DID document result: {reactivated:#}");

  let resolved: IotaDocument = identity_client.resolve_did(&did).await?;
  println!("Reactivated DID document resolved from chain: {resolved:#}");

  Ok(())
}
