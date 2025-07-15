// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use credential_verification::credential_revocation_server::CredentialRevocation;
use credential_verification::credential_revocation_server::CredentialRevocationServer;
use credential_verification::RevocationCheckRequest;
use credential_verification::RevocationCheckResponse;
use credential_verification::RevocationStatus;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtValidationError;
use identity_iota::credential::RevocationBitmapStatus;
use identity_iota::credential::{self};
use identity_iota::prelude::IotaDocument;
use identity_iota::prelude::Resolver;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use prost::bytes::Bytes;
use serde::Deserialize;
use serde::Serialize;

use thiserror::Error;
use tonic::Request;
use tonic::Response;
use tonic::{self};

mod credential_verification {
  use super::RevocationCheckError;
  use identity_iota::credential::RevocationBitmapStatus;
  use identity_iota::credential::Status;

  tonic::include_proto!("credentials");

  impl TryFrom<RevocationCheckRequest> for Status {
    type Error = RevocationCheckError;
    fn try_from(req: RevocationCheckRequest) -> Result<Self, Self::Error> {
      use identity_iota::core::Object;
      use identity_iota::core::Url;

      if req.r#type.as_str() != RevocationBitmapStatus::TYPE {
        Err(Self::Error::UnknownRevocationType(req.r#type))
      } else {
        let parsed_url = req
          .url
          .parse::<Url>()
          .map_err(|_| Self::Error::InvalidRevocationUrl(req.url))?;
        let properties = req
          .properties
          .into_iter()
          .map(|(k, v)| serde_json::to_value(v).map(|v| (k, v)))
          .collect::<Result<Object, _>>()
          .map_err(|_| Self::Error::MalformedPropertiesObject)?;

        Ok(Status {
          id: parsed_url,
          type_: req.r#type,
          properties,
        })
      }
    }
  }
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[serde(tag = "error_type", content = "reason")]
#[serde(rename_all = "snake_case")]
pub enum RevocationCheckError {
  #[error("Unknown revocation type {0}")]
  UnknownRevocationType(String),
  #[error("Could not parse {0} into a valid URL")]
  InvalidRevocationUrl(String),
  #[error("Properties isn't a valid JSON object")]
  MalformedPropertiesObject,
  #[error("Invalid credential status: {0}")]
  InvalidCredentialStatus(String),
  #[error("Issuer's DID resolution error: {0}")]
  ResolutionError(String),
  #[error("Revocation map not found")]
  RevocationMapNotFound,
}

impl From<RevocationCheckError> for tonic::Status {
  fn from(e: RevocationCheckError) -> Self {
    let message = e.to_string();
    let code = match &e {
      RevocationCheckError::InvalidCredentialStatus(_)
      | RevocationCheckError::MalformedPropertiesObject
      | RevocationCheckError::UnknownRevocationType(_)
      | RevocationCheckError::InvalidRevocationUrl(_) => tonic::Code::InvalidArgument,
      RevocationCheckError::ResolutionError(_) => tonic::Code::Internal,
      RevocationCheckError::RevocationMapNotFound => tonic::Code::NotFound,
    };
    let error_json = serde_json::to_vec(&e).unwrap_or_default();

    tonic::Status::with_details(code, message, Bytes::from(error_json))
  }
}

impl TryFrom<tonic::Status> for RevocationCheckError {
  type Error = ();
  fn try_from(value: tonic::Status) -> Result<Self, Self::Error> {
    serde_json::from_slice(value.details()).map_err(|_| ())
  }
}

#[derive(Debug)]
pub struct CredentialVerifier {
  resolver: Resolver<IotaDocument>,
}

impl CredentialVerifier {
  pub fn new(client: &IdentityClientReadOnly) -> Self {
    let mut resolver = Resolver::new();
    resolver.attach_iota_handler(client.clone());
    Self { resolver }
  }
}

#[tonic::async_trait]
impl CredentialRevocation for CredentialVerifier {
  #[tracing::instrument(
    name = "credential_check",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
  )]
  async fn check(
    &self,
    req: Request<RevocationCheckRequest>,
  ) -> Result<Response<RevocationCheckResponse>, tonic::Status> {
    let credential_revocation_status = {
      let revocation_status = credential::Status::try_from(req.into_inner())?;
      RevocationBitmapStatus::try_from(revocation_status)
        .map_err(|e| RevocationCheckError::InvalidCredentialStatus(e.to_string()))?
    };
    let issuer_did = credential_revocation_status.id().unwrap(); // Safety: already parsed as a valid URL
    let issuer_doc = self
      .resolver
      .resolve(issuer_did.did())
      .await
      .map_err(|e| RevocationCheckError::ResolutionError(e.to_string()))?;

    if let Err(e) =
      JwtCredentialValidatorUtils::check_revocation_bitmap_status(&issuer_doc, credential_revocation_status)
    {
      match &e {
        JwtValidationError::Revoked => Ok(Response::new(RevocationCheckResponse {
          status: RevocationStatus::Revoked.into(),
        })),
        _ => Err(RevocationCheckError::RevocationMapNotFound.into()),
      }
    } else {
      Ok(Response::new(RevocationCheckResponse {
        status: RevocationStatus::Valid.into(),
      }))
    }
  }
}

pub fn service(client: &IdentityClientReadOnly) -> CredentialRevocationServer<CredentialVerifier> {
  CredentialRevocationServer::new(CredentialVerifier::new(client))
}
