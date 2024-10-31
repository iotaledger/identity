// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _utils::did_jwk_server::DidJwk as DidJwkSvc;
use _utils::did_jwk_server::DidJwkServer;
use _utils::iota_utils_server::IotaUtils as IotaUtilsSvc;
use _utils::iota_utils_server::IotaUtilsServer;
use _utils::signing_server::Signing as SigningSvc;
use _utils::signing_server::SigningServer;
use _utils::DataSigningRequest;
use _utils::DataSigningResponse;
use _utils::DidJwkResolutionRequest;
use _utils::DidJwkResolutionResponse;
use _utils::IotaDidToAliasAddressRequest;
use _utils::IotaDidToAliasAddressResponse;
use anyhow::Context;
use identity_iota::core::ToJson;
use identity_iota::did::CoreDID;
use identity_iota::document::DocumentBuilder;
use identity_iota::iota::IotaDID;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageError;
use identity_iota::storage::KeyType;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jwu::decode_b64_json;
use identity_iota::verification::VerificationMethod;
use identity_stronghold::StrongholdKeyType;
use identity_stronghold::StrongholdStorage;
use iota_sdk::types::block::address::AliasAddress;
use iota_sdk::types::block::address::Hrp;
use iota_sdk::types::block::address::ToBech32Ext as _;
use iota_sdk::types::block::output::AliasId;
use tonic::async_trait;
use tonic::transport::server::RoutesBuilder;
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
    let DataSigningRequest { data, key_id, key_type } = req.into_inner();
    let key_id = KeyId::new(key_id);
    let key_type = {
      let key_type = KeyType::new(key_type);
      StrongholdKeyType::try_from(&key_type).map_err(|e| Status::invalid_argument(e.to_string()))?
    };
    let public_key_jwk = self
      .storage
      .get_public_key_with_type(&key_id, key_type)
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

pub fn init_services(routes: &mut RoutesBuilder, stronghold: &StrongholdStorage) {
  routes.add_service(SigningServer::new(SigningService::new(stronghold)));
  routes.add_service(DidJwkServer::new(DidJwkService {}));
  routes.add_service(IotaUtilsServer::new(IotaUtils {}));
}

#[derive(Debug)]
pub struct DidJwkService {}

#[tonic::async_trait]
impl DidJwkSvc for DidJwkService {
  #[tracing::instrument(
    name = "utils/resolve_did_jwk",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
  )]
  async fn resolve(&self, req: Request<DidJwkResolutionRequest>) -> Result<Response<DidJwkResolutionResponse>, Status> {
    let DidJwkResolutionRequest { did } = req.into_inner();
    let jwk = parse_did_jwk(&did).map_err(|e| Status::invalid_argument(e.to_string()))?;
    let did = CoreDID::parse(did).expect("valid did:jwk");
    let verification_method =
      VerificationMethod::new_from_jwk(did.clone(), jwk, Some("0")).map_err(|e| Status::internal(e.to_string()))?;
    let verification_method_id = verification_method.id().clone();
    let doc = DocumentBuilder::default()
      .id(did)
      .verification_method(verification_method)
      .assertion_method(verification_method_id.clone())
      .authentication(verification_method_id.clone())
      .capability_invocation(verification_method_id.clone())
      .capability_delegation(verification_method_id.clone())
      .key_agreement(verification_method_id)
      .build()
      .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(DidJwkResolutionResponse {
      doc: doc.to_json().map_err(|e| Status::internal(e.to_string()))?,
    }))
  }
}

fn parse_did_jwk(did: &str) -> anyhow::Result<Jwk> {
  let did_parts: [&str; 3] = did
    .split(':')
    .collect::<Vec<_>>()
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid did:jwk \"{did}\""))?;

  match did_parts {
    ["did", "jwk", data] => decode_b64_json(data).context("failed to deserialize JWK"),
    _ => anyhow::bail!("invalid did:jwk string \"{did}\""),
  }
}

#[derive(Debug)]
struct IotaUtils;

#[async_trait]
impl IotaUtilsSvc for IotaUtils {
  #[tracing::instrument(
    name = "utils/iota_did_to_alias_address",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
  )]
  async fn did_iota_to_alias_address(
    &self,
    req: Request<IotaDidToAliasAddressRequest>,
  ) -> Result<Response<IotaDidToAliasAddressResponse>, Status> {
    let IotaDidToAliasAddressRequest { did } = req.into_inner();
    let iota_did = IotaDID::try_from(did).map_err(|e| Status::invalid_argument(format!("invalid iota did: {e}")))?;
    let network = iota_did.network_str().to_string();
    let alias_address = AliasAddress::new(AliasId::from(&iota_did));
    let alias_bech32 = alias_address.to_bech32_unchecked(Hrp::from_str_unchecked(&network));

    Ok(Response::new(IotaDidToAliasAddressResponse {
      alias_address: alias_bech32.to_string(),
      network,
    }))
  }
}
