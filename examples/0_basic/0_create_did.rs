// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did_document;
use examples::get_funded_client;

use examples::get_memstorage;

/// Demonstrates how to create a DID Document and publish it on chain.
///
/// In this example we connect to a locally running private network, but it can be adapted
/// to run on any IOTA node by setting the network and faucet endpoints.
///
/// See the following instructions on running your own private network
/// https://github.com/iotaledger/hornet/tree/develop/private_tangle
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // create new client to interact with chain and get funded account with keys
  let storage = get_memstorage()?;
  let identity_client = get_funded_client(&storage).await?;

  // create new DID document and publish it
  let (document, _) = create_did_document(&identity_client, &storage).await?;
  println!("Published DID document: {document:#}");

  // check if we can resolve it via client
  let resolved = identity_client.resolve_did(document.id()).await?;
  println!("Resolved DID document: {resolved:#}");

  Ok(())
}
