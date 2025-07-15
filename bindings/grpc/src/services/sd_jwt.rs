// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _sd_jwt::verification_server::Verification;
use _sd_jwt::verification_server::VerificationServer;
use _sd_jwt::VerificationRequest;
use _sd_jwt::VerificationResponse;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::KeyBindingJWTValidationOptions;
use identity_iota::credential::SdJwtCredentialValidator;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use identity_iota::sd_jwt_payload::SdJwt;
use identity_iota::sd_jwt_payload::SdObjectDecoder;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use self::_sd_jwt::KeyBindingOptions;

mod _sd_jwt {
  tonic::include_proto!("sd_jwt");
}

impl From<KeyBindingOptions> for KeyBindingJWTValidationOptions {
  fn from(value: KeyBindingOptions) -> Self {
    let mut kb_options = Self::default();
    kb_options.nonce = value.nonce;
    kb_options.aud = value.aud;
    kb_options.earliest_issuance_date = value
      .earliest_issuance_date
      .and_then(|t| Timestamp::parse(t.as_str()).ok());
    kb_options.latest_issuance_date = value
      .latest_issuance_date
      .and_then(|t| Timestamp::parse(t.as_str()).ok());

    kb_options
  }
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "error", content = "reason")]
enum SdJwtVerificationError {
  #[error("Failed to parse SD-JWT: {0}")]
  DeserializationError(String),
  #[error("Failed to parse JWT: {0}")]
  JwtError(String),
  #[error("Credential verification failed: {0}")]
  VerificationError(String),
  #[error("Failed to resolve DID Document: {0}")]
  DidResolutionError(String),
  #[error("Missing \"kb_options\".")]
  MissingKbOptions,
  #[error("{0}")]
  KeyBindingJwtError(String),
  #[error("Provided an invalid holder's id.")]
  InvalidHolderDid,
}

impl From<SdJwtVerificationError> for tonic::Status {
  fn from(value: SdJwtVerificationError) -> Self {
    let code = match &value {
      SdJwtVerificationError::DeserializationError(_) => tonic::Code::InvalidArgument,
      SdJwtVerificationError::JwtError(_) => tonic::Code::InvalidArgument,
      SdJwtVerificationError::VerificationError(_) => tonic::Code::InvalidArgument,
      SdJwtVerificationError::DidResolutionError(_) => tonic::Code::NotFound,
      SdJwtVerificationError::MissingKbOptions => tonic::Code::InvalidArgument,
      SdJwtVerificationError::KeyBindingJwtError(_) => tonic::Code::Internal,
      SdJwtVerificationError::InvalidHolderDid => tonic::Code::InvalidArgument,
    };
    let message = value.to_string();
    let error_json = serde_json::to_vec(&value).expect("plenty of memory!");

    tonic::Status::with_details(code, message, error_json.into())
  }
}

#[derive(Debug)]
pub struct SdJwtService {
  resolver: Resolver<IotaDocument>,
}

impl SdJwtService {
  pub fn new(client: &IdentityClientReadOnly) -> Self {
    let mut resolver = Resolver::new();
    resolver.attach_iota_handler(client.clone());
    Self { resolver }
  }
}

#[tonic::async_trait]
impl Verification for SdJwtService {
  #[tracing::instrument(
    name = "sd_jwt_verification",
    skip_all,
    fields(request = ?request.get_ref())
    ret,
    err,
  )]
  async fn verify(
    &self,
    request: tonic::Request<VerificationRequest>,
  ) -> Result<tonic::Response<VerificationResponse>, tonic::Status> {
    let VerificationRequest { jwt, kb_options } = request.into_inner();
    let mut sd_jwt = SdJwt::parse(&jwt).map_err(|e| SdJwtVerificationError::DeserializationError(e.to_string()))?;
    let jwt = Jwt::new(sd_jwt.jwt);

    let issuer_did = JwtCredentialValidatorUtils::extract_issuer_from_jwt::<IotaDID>(&jwt)
      .map_err(|e| SdJwtVerificationError::VerificationError(e.to_string()))?;
    let issuer_document = self
      .resolver
      .resolve(&issuer_did)
      .await
      .map_err(|e| SdJwtVerificationError::DidResolutionError(e.to_string()))?;
    sd_jwt.jwt = jwt.into();

    let decoder = SdObjectDecoder::new_with_sha256();
    let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
    let credential = validator
      .validate_credential::<_, Object>(
        &sd_jwt,
        &issuer_document,
        &JwtCredentialValidationOptions::default(),
        FailFast::FirstError,
      )
      .map_err(|e| SdJwtVerificationError::VerificationError(e.to_string()))?;

    if sd_jwt.key_binding_jwt.is_some() {
      let Some(kb_options) = kb_options else {
        return Err(SdJwtVerificationError::MissingKbOptions.into());
      };
      let holder = {
        let did =
          IotaDID::parse(kb_options.holder_did.as_str()).map_err(|_| SdJwtVerificationError::InvalidHolderDid)?;
        self
          .resolver
          .resolve(&did)
          .await
          .map_err(|e| SdJwtVerificationError::DidResolutionError(e.to_string()))?
      };
      let _ = validator
        .validate_key_binding_jwt(&sd_jwt, &holder, &kb_options.into())
        .map_err(|e| SdJwtVerificationError::KeyBindingJwtError(e.to_string()))?;
    }

    Ok(tonic::Response::new(VerificationResponse {
      credential: credential.credential.to_json().unwrap(),
    }))
  }
}

pub fn service(client: &IdentityClientReadOnly) -> VerificationServer<SdJwtService> {
  VerificationServer::new(SdJwtService::new(client))
}
