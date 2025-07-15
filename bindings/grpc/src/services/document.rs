// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _document::document_service_server::DocumentService;
use _document::document_service_server::DocumentServiceServer;
use _document::CreateDidRequest;
use _document::CreateDidResponse;
use identity_iota::core::ToJson;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::transaction::Transaction;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkStorageDocumentError;
use identity_iota::storage::Storage;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_storage::KeyId;
use identity_storage::KeyStorageErrorKind;
use identity_storage::StorageSigner;
use identity_stronghold::StrongholdKeyType;
use identity_stronghold::StrongholdStorage;
use identity_stronghold::ED25519_KEY_TYPE;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;

mod _document {
  tonic::include_proto!("document");
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error(transparent)]
  IotaClientError(identity_iota::iota::Error),
  #[error(transparent)]
  StorageError(JwkStorageDocumentError),
  #[error(transparent)]
  StrongholdError(identity_iota::core::SingleStructError<KeyStorageErrorKind>),
  #[error(transparent)]
  IdentityClientError(identity_iota::iota::rebased::Error),
  #[error("did error : {0}")]
  DIDError(String),
}

impl From<Error> for Status {
  fn from(value: Error) -> Self {
    Status::new(Code::Internal, value.to_string())
  }
}

pub struct DocumentSvc {
  storage: Storage<StrongholdStorage, StrongholdStorage>,
  client: IdentityClientReadOnly,
}

impl DocumentSvc {
  pub fn new(client: &IdentityClientReadOnly, stronghold: &StrongholdStorage) -> Self {
    Self {
      storage: Storage::new(stronghold.clone(), stronghold.clone()),
      client: client.clone(),
    }
  }
}

#[tonic::async_trait]
impl DocumentService for DocumentSvc {
  #[tracing::instrument(
    name = "create_did_document",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
  )]
  async fn create(&self, req: Request<CreateDidRequest>) -> Result<Response<CreateDidResponse>, Status> {
    let CreateDidRequest { key_id } = req.into_inner();

    let key_id = KeyId::new(key_id);
    let pub_key = self
      .storage
      .key_id_storage()
      .get_public_key_with_type(&key_id, StrongholdKeyType::Ed25519)
      .await
      .map_err(Error::StrongholdError)?;

    let network_name = self.client.network();

    let storage = StorageSigner::new(&self.storage, key_id, pub_key);

    let identity_client = IdentityClient::new(self.client.clone(), storage)
      .await
      .map_err(Error::IdentityClientError)?;

    let mut created_identity = identity_client
      .create_identity(IotaDocument::new(network_name))
      .finish()
      .execute(&identity_client)
      .await
      .map_err(Error::IdentityClientError)?
      .output;

    let did =
      IotaDID::parse(format!("did:iota:{}", created_identity.id())).map_err(|e| Error::DIDError(e.to_string()))?;

    let mut document = IotaDocument::new_with_id(did.clone());
    let fragment = document
      .generate_method(
        &self.storage,
        ED25519_KEY_TYPE.clone(),
        JwsAlgorithm::EdDSA,
        Some(identity_client.signer().key_id().as_str()),
        MethodScope::VerificationMethod,
      )
      .await
      .map_err(Error::StorageError)?;

    created_identity
      .update_did_document(document.clone())
      .finish(&identity_client)
      .await
      .map_err(Error::IdentityClientError)?
      .execute(&identity_client)
      .await
      .map_err(Error::IdentityClientError)?;

    Ok(Response::new(CreateDidResponse {
      document_json: document.to_json().unwrap(),
      fragment,
      did: did.to_string(),
    }))
  }
}

pub fn service(client: &IdentityClientReadOnly, stronghold: &StrongholdStorage) -> DocumentServiceServer<DocumentSvc> {
  DocumentServiceServer::new(DocumentSvc::new(client, stronghold))
}
