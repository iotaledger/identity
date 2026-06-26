// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use examples::TEST_GAS_BUDGET;
use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::did::DIDUrl;
use identity_iota::did::DID;
use identity_iota::document::Service;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodRelationship;
use identity_iota::verification::MethodScope;

/// Demonstrates how to update a DID document in an existing identity.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // create new client to interact with chain and get funded account with keys
  let storage = get_memstorage()?;
  let identity_client = get_funded_client(&storage).await?;
  // create new DID document and publish it
  let (document, vm_fragment_1) = create_did_document(&identity_client, &storage).await?;
  let did: IotaDID = document.id().clone();

  // Resolve the latest state of the document.
  let mut document: IotaDocument = identity_client.resolve_did(&did).await?;

  // Insert a new Ed25519 verification method in the DID document.
  let vm_fragment_2: String = document
    .generate_method(
      &storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

  // Attach a new method relationship to the inserted method.
  document.attach_method_relationship(
    &document.id().to_url().join(format!("#{vm_fragment_2}"))?,
    MethodRelationship::Authentication,
  )?;

  // Add a new Service.
  let service: Service = Service::from_json_value(json!({
    "id": document.id().to_url().join("#linked-domain")?,
    "type": "LinkedDomains",
    "serviceEndpoint": "https://iota.org/"
  }))?;
  assert!(document.insert_service(service).is_ok());
  document.metadata.updated = Some(Timestamp::now_utc());

  // Remove a verification method.
  let original_method: DIDUrl = document.resolve_method(&vm_fragment_1, None).unwrap().id().clone();
  document.purge_method(&storage, &original_method).await.unwrap();

  let updated = identity_client
    .publish_did_document_update(document.clone(), TEST_GAS_BUDGET)
    .await?;
  println!("Updated DID document result: {updated:#}");

  let resolved: IotaDocument = identity_client.resolve_did(&did).await?;
  println!("Updated DID document resolved from chain: {resolved:#}");

  Ok(())
}
