// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::ToJson;
use identity_iota::credential::status_list_2021::StatusList2021Credential;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtValidationError;
use identity_iota::credential::StatusCheck;
use identity_iota::iota::IotaDID;
use identity_iota::resolver;
use identity_iota::resolver::Resolver;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;

use _credentials::vc_validation_server::VcValidation;
use _credentials::vc_validation_server::VcValidationServer;
use _credentials::VcValidationRequest;
use _credentials::VcValidationResponse;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;

mod _credentials {
  tonic::include_proto!("credentials");
}

#[derive(Debug, thiserror::Error)]
pub enum VcValidationError {
  #[error(transparent)]
  JwtValidationError(#[from] JwtValidationError),
  #[error("DID resolution error")]
  DidResolutionError(#[source] resolver::Error),
  #[error("Provided an invalid StatusList2021Credential")]
  InvalidStatusList2021Credential(#[source] identity_iota::core::Error),
  #[error("The provided credential has been revoked")]
  RevokedCredential,
  #[error("The provided credential has expired")]
  ExpiredCredential,
  #[error("The provided credential has been suspended")]
  SuspendedCredential,
}

impl From<VcValidationError> for Status {
  fn from(error: VcValidationError) -> Self {
    let code = match &error {
      VcValidationError::InvalidStatusList2021Credential(_) => Code::InvalidArgument,
      _ => Code::Internal,
    };

    Status::new(code, error.to_string())
  }
}

pub struct VcValidator {
  resolver: Resolver,
}

impl VcValidator {
  pub fn new(client: &IdentityClientReadOnly) -> Self {
    let mut resolver = Resolver::new();
    resolver.attach_iota_handler(client.clone());
    Self { resolver }
  }
}

#[tonic::async_trait]
impl VcValidation for VcValidator {
  #[tracing::instrument(
    name = "validate_jwt_credential",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
)]
  async fn validate(&self, req: Request<VcValidationRequest>) -> Result<Response<VcValidationResponse>, Status> {
    let VcValidationRequest {
      credential_jwt,
      status_list_credential_json,
    } = req.into_inner();
    let jwt = Jwt::new(credential_jwt);
    let issuer_did = JwtCredentialValidatorUtils::extract_issuer_from_jwt::<IotaDID>(&jwt)
      .map_err(VcValidationError::JwtValidationError)?;
    let issuer_doc = self
      .resolver
      .resolve(&issuer_did)
      .await
      .map_err(VcValidationError::DidResolutionError)?;

    let mut validation_option = JwtCredentialValidationOptions::default();
    if status_list_credential_json.is_some() {
      validation_option = validation_option.status_check(StatusCheck::SkipAll);
    }

    let validator = JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
    let decoded_credential = validator
      .validate::<_, Object>(&jwt, &issuer_doc, &validation_option, FailFast::FirstError)
      .map_err(|mut e| match e.validation_errors.swap_remove(0) {
        JwtValidationError::Revoked => VcValidationError::RevokedCredential,
        JwtValidationError::ExpirationDate | JwtValidationError::IssuanceDate => VcValidationError::ExpiredCredential,
        e => VcValidationError::JwtValidationError(e),
      })?;

    if let Some(status_list_json) = status_list_credential_json {
      let status_list = StatusList2021Credential::from_json(&status_list_json)
        .map_err(VcValidationError::InvalidStatusList2021Credential)?;
      JwtCredentialValidatorUtils::check_status_with_status_list_2021(
        &decoded_credential.credential,
        &status_list,
        StatusCheck::Strict,
      )
      .map_err(|e| match e {
        JwtValidationError::Revoked => VcValidationError::RevokedCredential,
        JwtValidationError::Suspended => VcValidationError::SuspendedCredential,
        e => VcValidationError::JwtValidationError(e),
      })?;
    }

    let response = Response::new(VcValidationResponse {
      credential_json: decoded_credential.credential.to_json().unwrap(),
    });

    Ok(response)
  }
}

pub fn service(client: &IdentityClientReadOnly) -> VcValidationServer<VcValidator> {
  VcValidationServer::new(VcValidator::new(client))
}
