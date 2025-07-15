// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_stronghold::StrongholdStorage;
use identity_iota::iota::rebased::utils::request_funds;

use tonic::Request;

use crate::helpers::get_address;
use crate::helpers::make_stronghold;
use crate::helpers::Entity;
use crate::helpers::TestServer;

use _document::document_service_client::DocumentServiceClient;
use _document::CreateDidRequest;

mod _document {
  tonic::include_proto!("document");
}

#[tokio::test]
async fn did_document_creation() -> anyhow::Result<()> {
  let stronghold = StrongholdStorage::new(make_stronghold());
  let server = TestServer::new_with_stronghold(stronghold.clone()).await;

  let user = Entity::new_with_stronghold(stronghold);
  let (user_address, key_id, _) = get_address(user.storage()).await?;

  request_funds(&user_address).await?;

  let mut grpc_client = DocumentServiceClient::connect(server.endpoint()).await?;
  grpc_client
    .create(Request::new(CreateDidRequest {
      key_id: key_id.as_str().to_string(),
    }))
    .await?;

  Ok(())
}
