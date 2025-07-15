// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use examples::TEST_GAS_BUDGET;
use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::did::DID;
use identity_iota::document::Service;
use identity_iota::iota::rebased::client::get_object_id_from_did;
use identity_iota::iota::rebased::migration::has_previous_version;
use identity_iota::iota::rebased::migration::Identity;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::verification::MethodRelationship;
use iota_sdk::rpc_types::IotaObjectData;

/// Demonstrates how to obtain the identity history.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // Create a new client to interact with the IOTA ledger.
  // NOTE: a permanode is required to fetch older output histories.
  let storage = get_memstorage()?;
  let identity_client = get_funded_client(&storage).await?;
  // create new DID document and publish it
  let (document, vm_fragment_1) = create_did_document(&identity_client, &storage).await?;
  let did: IotaDID = document.id().clone();

  // Resolve the latest state of the document.
  let mut document: IotaDocument = identity_client.resolve_did(&did).await?;

  // Attach a new method relationship to the existing method.
  document.attach_method_relationship(
    &document.id().to_url().join(format!("#{vm_fragment_1}"))?,
    MethodRelationship::Authentication,
  )?;

  // Adding multiple services.
  let services = [
    json!({"id": document.id().to_url().join("#my-service-0")?, "type": "MyService", "serviceEndpoint": "https://iota.org/"}),
  ];
  for service in services {
    let service: Service = Service::from_json_value(service)?;
    assert!(document.insert_service(service).is_ok());
    document.metadata.updated = Some(Timestamp::now_utc());

    identity_client
      .publish_did_document_update(document.clone(), TEST_GAS_BUDGET)
      .await?;
  }

  // ====================================
  // Retrieving the identity History
  // ====================================

  // Step 1 - Get the latest identity
  let identity = identity_client.get_identity(get_object_id_from_did(&did)?).await?;
  let onchain_identity = if let Identity::FullFledged(value) = identity {
    value
  } else {
    anyhow::bail!("history only available for onchain identities");
  };

  // Step 2 - Get history
  let history = onchain_identity.get_history(&identity_client, None, None).await?;
  println!("Identity History has {} entries", history.len());

  // Optional step - Parse to documents
  let documents: Vec<IotaDocument> = history
    .into_iter()
    .map(|data| IotaDocument::unpack_from_iota_object_data(&did, &data, true))
    .collect::<Result<_, _>>()?;
  println!("Current version: {}", documents[0]);
  println!("Previous version: {}", documents[1]);

  // Depending on your use case, you can also page through the results
  // Alternative Step 2 - Page by looping until no result is returned (here with page size 1)
  let mut current_item: Option<&IotaObjectData> = None;
  let mut history: Vec<IotaObjectData>;
  loop {
    history = onchain_identity
      .get_history(&identity_client, current_item, Some(1))
      .await?;
    if history.is_empty() {
      break;
    }
    current_item = history.first();
    let IotaObjectData { object_id, version, .. } = current_item.unwrap();
    println!("Identity History entry: object_id: {object_id}, version: {version}");
  }

  // Alternative Step 2 - Page by looping with pre-fetch next page check (again with page size 1)
  let mut current_item: Option<&IotaObjectData> = None;
  let mut history: Vec<IotaObjectData>;
  loop {
    history = onchain_identity
      .get_history(&identity_client, current_item, Some(1))
      .await?;

    current_item = history.first();
    let IotaObjectData { object_id, version, .. } = current_item.unwrap();
    println!("Identity History entry: object_id: {object_id}, version: {version}");

    if !has_previous_version(current_item.unwrap())? {
      break;
    }
  }

  Ok(())
}
