// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::helpers::TestServer;
use _status_list_2021::status_list2021_svc_client::StatusList2021SvcClient;
use _status_list_2021::CreateRequest;
use _status_list_2021::Purpose;
use _status_list_2021::UpdateRequest;
use identity_iota::core::FromJson;
use identity_iota::core::ToJson;
use identity_iota::core::Url;
use identity_iota::credential::status_list_2021::StatusList2021;
use identity_iota::credential::status_list_2021::StatusList2021Credential;
use identity_iota::credential::status_list_2021::StatusList2021CredentialBuilder;
use identity_iota::credential::status_list_2021::StatusPurpose;
use identity_iota::credential::Issuer;
use tonic::Request;

mod _status_list_2021 {
  tonic::include_proto!("status_list_2021");
}

#[tokio::test]
async fn status_list_2021_credential_creation() -> anyhow::Result<()> {
  let server = TestServer::new().await;

  let id = Url::parse("http://example.com/credentials/status/1").unwrap();
  let issuer = Issuer::Url(Url::parse("http://example.com/issuers/1").unwrap());
  let status_list_credential = StatusList2021CredentialBuilder::new(StatusList2021::default())
    .purpose(StatusPurpose::Revocation)
    .subject_id(id.clone())
    .issuer(issuer.clone())
    .build()
    .unwrap();

  let mut grpc_client = StatusList2021SvcClient::connect(server.endpoint()).await?;
  let res = grpc_client
    .create(Request::new(CreateRequest {
      id: Some(id.into_string()),
      issuer: issuer.url().to_string(),
      purpose: Purpose::Revocation as i32,
      length: None,
      expiration_date: None,
      contexts: vec![],
      types: vec![],
    }))
    .await?
    .into_inner()
    .credential_json;
  let grpc_credential = StatusList2021Credential::from_json(&res)?;

  assert_eq!(status_list_credential, grpc_credential);
  Ok(())
}

#[tokio::test]
async fn status_list_2021_credential_update() -> anyhow::Result<()> {
  let server = TestServer::new().await;

  let id = Url::parse("http://example.com/credentials/status/1").unwrap();
  let issuer = Issuer::Url(Url::parse("http://example.com/issuers/1").unwrap());
  let mut status_list_credential = StatusList2021CredentialBuilder::new(StatusList2021::default())
    .purpose(StatusPurpose::Revocation)
    .subject_id(id)
    .issuer(issuer)
    .build()
    .unwrap();

  let entries_to_set = [0_u64, 42, 420, 4200];
  let entries = entries_to_set.iter().map(|i| (*i, true)).collect();

  let mut grpc_client = StatusList2021SvcClient::connect(server.endpoint()).await?;
  let grpc_credential = grpc_client
    .update(Request::new(UpdateRequest {
      credential_json: status_list_credential.to_json().unwrap(),
      entries,
    }))
    .await
    .map(|res| res.into_inner().credential_json)
    .map(|credential_json| StatusList2021Credential::from_json(&credential_json).unwrap())
    .unwrap();

  status_list_credential.update(|status_list| {
    for idx in entries_to_set {
      status_list.set_entry(idx as usize, true)?
    }
    Ok(())
  })?;

  assert_eq!(status_list_credential, grpc_credential);
  Ok(())
}
