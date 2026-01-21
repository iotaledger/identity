// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::get_read_only_client;
use identity_iota::core::ToJson;
use identity_iota::iota::rebased::utils::request_funds;
use identity_iota::iota::IotaDocument;
use identity_iota::iota_interaction::KeytoolStorage as Keytool;
use identity_iota::storage::KeytoolStorage;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_storage::JwkDocumentExt as _;
use identity_storage::KeyType;
use iota_sdk::types::base_types::IotaAddress;
use iota_sdk::types::crypto::SignatureScheme;

/// This examples showcases how the Identity library can leverage IOTA Keytool
/// for all operations that require access to any key-material.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // For starter we access the local IOTA Keytool executable to create a new keypair.
  let keytool = Keytool::new();
  // We generate a new Ed25519 key handled by the keytool, that we will use to interact with the ledger
  // throughout this example.
  let (pk, _alias) = keytool.generate_key(SignatureScheme::ED25519)?;
  let address = IotaAddress::from(&pk);
  println!("Created new address {address}!");

  // Let's request some funds for our new address.
  request_funds(&address).await?;

  // Let's use the newly generated key to build the signer that will power our identity client.
  let identity_client = {
    let read_only_client = get_read_only_client().await?;
    // If we don't specify the address to use KeytoolSigner will use the current active-address.
    let signer = keytool.signer().with_address(address).build()?;
    read_only_client.set_signer(signer).await?
  };

  // Let's create a new DID Document, with a verification method
  // that has its secret key stored in the Keytool.

  // Firstly, we create a storage instance from our Keytool.
  let keytool_storage = KeytoolStorage::from(keytool);
  // Then we start building our DID Document.
  let mut did_document = IotaDocument::new(identity_client.network());
  // We build a new verification method.
  let _vm_fragment = did_document
    .generate_method(
      &keytool_storage,
      KeyType::new("secp256r1"),
      JwsAlgorithm::ES256,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

  // Let's publish our new DID Document.
  let did_document = identity_client
    .publish_did_document(did_document)
    .build_and_execute(&identity_client)
    .await?
    .output;
  println!(
    "Here is our published DID Document:\n{}",
    did_document.to_json_pretty()?
  );

  Ok(())
}
