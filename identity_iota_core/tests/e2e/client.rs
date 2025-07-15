// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::get_funded_test_client;
use crate::common::TestClient;
use identity_iota_core::rebased::migration;
use identity_iota_core::IotaDocument;

use iota_sdk::types::crypto::SignatureScheme;

#[tokio::test]
async fn can_create_an_identity() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;

  let did = identity.did_document().id();
  assert_eq!(did.network_str(), identity_client.network().as_ref());

  Ok(())
}

#[tokio::test]
async fn can_resolve_a_new_identity() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let new_identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;

  let identity = migration::get_identity(&identity_client, new_identity.id()).await?;

  assert!(identity.is_some());

  Ok(())
}

#[tokio::test]
async fn client_with_keytool_signer_active_address_works() -> anyhow::Result<()> {
  let test_client = TestClient::new().await?;
  let _identity = test_client
    .create_identity(IotaDocument::new(test_client.network()))
    .finish()
    .build_and_execute(&test_client)
    .await?
    .output;

  Ok(())
}

#[tokio::test]
async fn client_with_new_ed25519_keytool_signer_works() -> anyhow::Result<()> {
  let test_client = TestClient::new_with_key_type(SignatureScheme::ED25519).await?;
  let _identity = test_client
    .create_identity(IotaDocument::new(test_client.network()))
    .finish()
    .build_and_execute(&test_client)
    .await?
    .output;

  Ok(())
}

#[tokio::test]
async fn client_with_new_secp256r1_keytool_signer_works() -> anyhow::Result<()> {
  let test_client = TestClient::new_with_key_type(SignatureScheme::Secp256r1).await?;
  let _identity = test_client
    .create_identity(IotaDocument::new(test_client.network()))
    .finish()
    .build_and_execute(&test_client)
    .await?
    .output;

  Ok(())
}

#[tokio::test]
async fn client_with_new_secp256k1_keytool_signer_works() -> anyhow::Result<()> {
  let test_client = TestClient::new_with_key_type(SignatureScheme::Secp256k1).await?;
  let _identity = test_client
    .create_identity(IotaDocument::new(test_client.network()))
    .finish()
    .build_and_execute(&test_client)
    .await?
    .output;

  Ok(())
}
