// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _credentials::jwt_server::Jwt as JwtSvc;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::credential::Credential;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::Storage;
use identity_stronghold::StrongholdStorage;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use self::_credentials::jwt_server::JwtServer;
use self::_credentials::JwtCreationRequest;
use self::_credentials::JwtCreationResponse;

mod _credentials {
  tonic::include_proto!("credentials");
}

pub struct JwtService {
  resolver: Resolver<IotaDocument>,
  storage: Storage<StrongholdStorage, StrongholdStorage>,
}

impl JwtService {
  pub fn new(client: &IdentityClientReadOnly, stronghold: &StrongholdStorage) -> Self {
    let mut resolver = Resolver::new();
    resolver.attach_iota_handler(client.clone());
    Self {
      resolver,
      storage: Storage::new(stronghold.clone(), stronghold.clone()),
    }
  }
}

#[tonic::async_trait]
impl JwtSvc for JwtService {
  #[tracing::instrument(
    name = "create_jwt_credential",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
  )]
  async fn create(&self, req: Request<JwtCreationRequest>) -> Result<Response<JwtCreationResponse>, Status> {
    let JwtCreationRequest {
      credential_json,
      issuer_fragment,
    } = req.into_inner();
    let credential =
      Credential::<Object>::from_json(credential_json.as_str()).map_err(|e| Status::invalid_argument(e.to_string()))?;
    let issuer_did =
      IotaDID::parse(credential.issuer.url().as_str()).map_err(|e| Status::invalid_argument(e.to_string()))?;
    let issuer_document = self
      .resolver
      .resolve(&issuer_did)
      .await
      .map_err(|e| Status::not_found(e.to_string()))?;

    let jwt = issuer_document
      .create_credential_jwt(
        &credential,
        &self.storage,
        &issuer_fragment,
        &JwsSignatureOptions::default(),
        None,
      )
      .await
      .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(JwtCreationResponse { jwt: jwt.into() }))
  }
}

pub fn service(client: &IdentityClientReadOnly, stronghold: &StrongholdStorage) -> JwtServer<JwtService> {
  JwtServer::new(JwtService::new(client, stronghold))
}
