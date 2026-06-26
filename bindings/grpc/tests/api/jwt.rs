// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _credentials::jwt_client::JwtClient;
use _credentials::JwtCreationRequest;
use identity_iota::core::Object;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::credential::CredentialBuilder;
use identity_iota::did::DID;
use identity_stronghold::StrongholdStorage;
use iota_sdk_legacy::Url;
use serde_json::json;

use crate::helpers::make_stronghold;
use crate::helpers::Entity;
use crate::helpers::TestServer;

mod _credentials {
  tonic::include_proto!("credentials");
}

#[tokio::test]
async fn jwt_creation() -> anyhow::Result<()> {
  let stronghold = StrongholdStorage::new(make_stronghold());
  let server = TestServer::new_with_stronghold(stronghold.clone()).await;
  let api_client = server.client();

  let mut issuer = Entity::new_with_stronghold(stronghold);
  issuer.create_did(api_client).await?;

  let mut holder = Entity::new();
  holder.create_did(api_client).await?;

  let credential = CredentialBuilder::<Object>::default()
    .issuance_date(Timestamp::now_utc())
    .issuer(Url::parse(issuer.document().unwrap().id().as_str())?)
    .subject(serde_json::from_value(json!({
        "id": holder.document().unwrap().id().as_str(),
        "type": "UniversityDegree",
        "gpa": "4.0",
    }))?)
    .build()?;

  let mut grpc_client = JwtClient::connect(server.endpoint()).await?;
  let _ = grpc_client
    .create(JwtCreationRequest {
      credential_json: credential.to_json()?,
      issuer_fragment: issuer.fragment().unwrap().to_owned(),
    })
    .await?;

  Ok(())
}
