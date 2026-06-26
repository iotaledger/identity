// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_stronghold_storage;
use examples::random_stronghold_path;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::credential::Jws;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::verification::jws::DecodedJws;

/// Demonstrates how to use stronghold for secure storage.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // Create storage for key-ids and JWKs.
  //
  // In this example, the same stronghold file that is used to store
  // key-ids as well as the JWKs.
  let path = random_stronghold_path();
  let storage = get_stronghold_storage(Some(path.clone()))?;

  // use stronghold storage to create new client to interact with chain and get funded account with keys
  let identity_client = get_funded_client(&storage).await?;
  // create and publish document with stronghold storage
  let (document, vm_fragment) = create_did_document(&identity_client, &storage).await?;

  // Resolve the published DID Document.
  let mut resolver = Resolver::<IotaDocument>::new();
  resolver.attach_iota_handler((*identity_client).clone());
  let resolved_document: IotaDocument = resolver.resolve(document.id()).await.unwrap();

  drop(storage);

  // Create the storage again to demonstrate that data are read from the existing stronghold file.
  let storage = get_stronghold_storage(Some(path))?;

  // Sign data with the created verification method.
  let data = b"test_data";
  let jws: Jws = resolved_document
    .create_jws(&storage, &vm_fragment, data, &JwsSignatureOptions::default())
    .await?;

  // Verify Signature.
  let decoded_jws: DecodedJws = resolved_document.verify_jws(
    &jws,
    None,
    &EdDSAJwsVerifier::default(),
    &JwsVerificationOptions::default(),
  )?;

  assert_eq!(String::from_utf8_lossy(decoded_jws.claims.as_ref()), "test_data");

  println!("successfully verified signature");

  Ok(())
}
