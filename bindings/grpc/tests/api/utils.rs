// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _utils::signing_client::SigningClient;
use _utils::DataSigningRequest;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_storage::JwkStorage;
use identity_storage::KeyType;
use identity_stronghold::StrongholdKeyType;
use identity_stronghold::StrongholdStorage;

use crate::helpers::make_stronghold;
use crate::helpers::TestServer;

mod _utils {
  tonic::include_proto!("utils");
}

const SAMPLE_SIGNING_DATA: &'static [u8] = b"I'm just some random data to be signed :)";

#[tokio::test]
async fn raw_data_signing_works() -> anyhow::Result<()> {
  let stronghold = StrongholdStorage::new(make_stronghold());
  let server = TestServer::new_with_stronghold(stronghold.clone()).await;

  let key_id = stronghold
    .generate(KeyType::from_static_str("Ed25519"), JwsAlgorithm::EdDSA)
    .await?
    .key_id;

  let expected_signature = {
    let public_key_jwk = stronghold
      .get_public_key_with_type(&key_id, StrongholdKeyType::Ed25519)
      .await?;
    stronghold.sign(&key_id, SAMPLE_SIGNING_DATA, &public_key_jwk).await?
  };

  let mut grpc_client = SigningClient::connect(server.endpoint()).await?;
  let signature = grpc_client
    .sign(DataSigningRequest {
      data: SAMPLE_SIGNING_DATA.to_owned(),
      key_id: key_id.to_string(),
    })
    .await?
    .into_inner()
    .signature;

  assert_eq!(signature, expected_signature);

  Ok(())
}
