// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _utils::signing_server::Signing as SigningSvc;
use _utils::signing_server::SigningServer;
use _utils::DataSigningRequest;
use _utils::DataSigningResponse;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageError;
use identity_stronghold::StrongholdKeyType;
use identity_stronghold::StrongholdStorage;
use tonic::Request;
use tonic::Response;
use tonic::Status;

mod _utils {
  tonic::include_proto!("utils");
}

#[derive(Debug, thiserror::Error)]
#[error("Key storage error: {0}")]
pub struct Error(#[from] KeyStorageError);

impl From<Error> for Status {
  fn from(value: Error) -> Self {
    Status::internal(value.to_string())
  }
}

pub struct SigningService {
  storage: StrongholdStorage,
}

impl SigningService {
  pub fn new(stronghold: &StrongholdStorage) -> Self {
    Self {
      storage: stronghold.clone(),
    }
  }
}

#[tonic::async_trait]
impl SigningSvc for SigningService {
  #[tracing::instrument(
    name = "utils/sign",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
  )]
  async fn sign(&self, req: Request<DataSigningRequest>) -> Result<Response<DataSigningResponse>, Status> {
    let DataSigningRequest { data, key_id } = req.into_inner();
    let key_id = KeyId::new(key_id);
    let public_key_jwk = self
      .storage
      .get_public_key_with_type(&key_id, StrongholdKeyType::Ed25519)
      .await
      .map_err(Error)?;
    let signature = self
      .storage
      .sign(&key_id, &data, &public_key_jwk)
      .await
      .map_err(Error)?;

    Ok(Response::new(DataSigningResponse { signature }))
  }
}

pub fn service(stronghold: &StrongholdStorage) -> SigningServer<SigningService> {
  SigningServer::new(SigningService::new(stronghold))
}
