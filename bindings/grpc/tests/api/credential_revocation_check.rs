// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use credentials::credential_revocation_client::CredentialRevocationClient;
use credentials::RevocationStatus;
use identity_iota::credential::RevocationBitmap;
use identity_iota::credential::RevocationBitmapStatus;
use identity_iota::credential::{self};
use identity_iota::did::DID;
use identity_stronghold::StrongholdStorage;
use serde_json::json;

use crate::credential_revocation_check::credentials::RevocationCheckRequest;
use crate::helpers::make_stronghold;
use crate::helpers::Entity;
use crate::helpers::TestServer;

mod credentials {
  tonic::include_proto!("credentials");
}

#[tokio::test]
async fn checking_status_of_credential_works() -> anyhow::Result<()> {
  let server = TestServer::new().await;
  let client = server.client();

  let stronghold = StrongholdStorage::new(make_stronghold());

  let mut issuer = Entity::new_with_stronghold(stronghold);
  issuer.create_did(client).await?;

  let mut subject = Entity::new();
  subject.create_did(client).await?;

  let service_id = issuer
    .document()
    .unwrap() // Safety: `create_did` didn't fail
    .id()
    .to_url()
    .join("#my-revocation-service")?;

  // Add a revocation service to the issuer's DID document
  issuer
    .update_document(client, |mut doc| {
      let service = RevocationBitmap::new().to_service(service_id.clone()).unwrap();

      doc.insert_service(service).ok().map(|_| doc)
    })
    .await?;

  let credential_status: credential::Status = RevocationBitmapStatus::new(service_id, 3).into();

  let mut grpc_client = CredentialRevocationClient::connect(server.endpoint()).await?;
  let req = RevocationCheckRequest {
    r#type: credential_status.type_,
    url: credential_status.id.into_string(),
    properties: credential_status
      .properties
      .into_iter()
      .map(|(k, v)| (k, v.to_string().trim_matches('"').to_owned()))
      .collect(),
  };
  let res = grpc_client.check(tonic::Request::new(req.clone())).await?.into_inner();

  assert_eq!(res.status(), RevocationStatus::Valid);

  // Revoke credential
  issuer
    .update_document(client, |mut doc| {
      doc.revoke_credentials("my-revocation-service", &[3]).ok().map(|_| doc)
    })
    .await?;

  let res = grpc_client.check(tonic::Request::new(req)).await?.into_inner();
  assert_eq!(res.status(), RevocationStatus::Revoked);

  Ok(())
}

#[tokio::test]
async fn checking_status_of_valid_but_unresolvable_url_fails() -> anyhow::Result<()> {
  use identity_grpc::services::credential::revocation::RevocationCheckError;
  let server = TestServer::new().await;

  let mut grpc_client = CredentialRevocationClient::connect(server.endpoint()).await?;
  let properties = json!({
      "revocationBitmapIndex": "3"
  });
  let req = RevocationCheckRequest {
    r#type: RevocationBitmap::TYPE.to_owned(),
    url: "did:example:1234567890#my-revocation-service".to_owned(),
    properties: properties
      .as_object()
      .unwrap()
      .into_iter()
      .map(|(k, v)| (k.clone(), v.to_string().trim_matches('"').to_owned()))
      .collect(),
  };
  let res_error = grpc_client.check(tonic::Request::new(req.clone())).await;

  assert!(res_error.is_err_and(|e| matches!(e.try_into().unwrap(), RevocationCheckError::ResolutionError(_))));

  Ok(())
}
