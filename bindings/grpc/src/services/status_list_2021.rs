// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use identity_iota::core::Context;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::core::Url;
use identity_iota::credential::status_list_2021::StatusList2021;
use identity_iota::credential::status_list_2021::StatusList2021Credential;
use identity_iota::credential::status_list_2021::StatusList2021CredentialBuilder;
use identity_iota::credential::status_list_2021::StatusList2021CredentialError;
use identity_iota::credential::status_list_2021::StatusPurpose;
use identity_iota::credential::Issuer;
use identity_iota::credential::{self};

use _status_list_2021::status_list2021_svc_server::StatusList2021Svc;
use _status_list_2021::status_list2021_svc_server::StatusList2021SvcServer;
use _status_list_2021::CreateRequest;
use _status_list_2021::Purpose;
use _status_list_2021::StatusListCredential;
use _status_list_2021::UpdateRequest;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;

mod _status_list_2021 {
  use identity_iota::credential::status_list_2021::StatusPurpose;

  tonic::include_proto!("status_list_2021");

  impl From<Purpose> for StatusPurpose {
    fn from(value: Purpose) -> Self {
      match value {
        Purpose::Revocation => StatusPurpose::Revocation,
        Purpose::Suspension => StatusPurpose::Suspension,
      }
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("A valid status list must have at least 16KB entries")]
  InvalidStatusListLength,
  #[error("\"{0}\" is not a valid context")]
  InvalidContext(String),
  #[error("\"{0}\" is not a valid issuer")]
  InvalidIssuer(String),
  #[error("\"{0}\" is not a valid timestamp")]
  InvalidTimestamp(String),
  #[error("\"{0}\" is not a valid id")]
  InvalidId(String),
  #[error("Failed to deserialize into a valid StatusList2021Credential")]
  CredentialDeserializationError(#[source] identity_iota::core::Error),
  #[error(transparent)]
  CredentialError(#[from] credential::Error),
  #[error(transparent)]
  StatusListError(StatusList2021CredentialError),
}

impl From<Error> for Status {
  fn from(value: Error) -> Self {
    let code = match &value {
      Error::InvalidStatusListLength
      | Error::InvalidContext(_)
      | Error::InvalidIssuer(_)
      | Error::InvalidTimestamp(_) => Code::InvalidArgument,
      _ => Code::Internal,
    };

    Status::new(code, value.to_string())
  }
}

pub struct StatusList2021Service;

#[tonic::async_trait]
impl StatusList2021Svc for StatusList2021Service {
  #[tracing::instrument(
    name = "create_status_list_credential",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
)]
  async fn create(&self, req: Request<CreateRequest>) -> Result<Response<StatusListCredential>, Status> {
    let CreateRequest {
      purpose,
      length,
      id,
      expiration_date,
      contexts,
      types,
      issuer,
    } = req.into_inner();
    let status_list = length
      .map(|entries| StatusList2021::new(entries as usize))
      .unwrap_or(Ok(StatusList2021::default()))
      .map_err(|_| Error::InvalidStatusListLength)?;

    let mut builder = StatusList2021CredentialBuilder::new(status_list);
    let contexts = contexts.into_iter().collect::<HashSet<_>>();
    for ctx in contexts {
      let url = Url::parse(&ctx).map_err(move |_| Error::InvalidContext(ctx))?;
      builder = builder.context(Context::Url(url));
    }

    let types = types.into_iter().collect::<HashSet<_>>();
    for t in types {
      builder = builder.add_type(t);
    }
    let issuer = Url::parse(&issuer)
      .map_err(move |_| Error::InvalidIssuer(issuer))
      .map(Issuer::Url)?;
    builder = builder.issuer(issuer);
    builder = builder.purpose(StatusPurpose::from(Purpose::try_from(purpose).unwrap()));
    if let Some(exp) = expiration_date {
      let exp = Timestamp::parse(&exp).map_err(move |_| Error::InvalidTimestamp(exp))?;
      builder = builder.expiration_date(exp);
    }
    if let Some(id) = id {
      let id = Url::parse(&id).map_err(move |_| Error::InvalidId(id))?;
      builder = builder.subject_id(id);
    }
    let status_list_credential = builder.build().map_err(Error::CredentialError)?;
    let res = StatusListCredential {
      credential_json: status_list_credential.to_json().unwrap(),
    };

    Ok(Response::new(res))
  }

  #[tracing::instrument(
    name = "update_status_list_credential",
    skip_all,
    fields(request = ?req.get_ref())
    ret,
    err,
  )]
  async fn update(&self, req: Request<UpdateRequest>) -> Result<Response<StatusListCredential>, Status> {
    let UpdateRequest {
      credential_json,
      entries,
    } = req.into_inner();
    let mut status_list_credential =
      StatusList2021Credential::from_json(&credential_json).map_err(Error::CredentialDeserializationError)?;

    status_list_credential
      .update(move |status_list| {
        for (idx, value) in entries {
          status_list.set_entry(idx as usize, value)?
        }

        Ok(())
      })
      .map_err(Error::StatusListError)?;

    Ok(Response::new(StatusListCredential {
      credential_json: status_list_credential.to_json().unwrap(),
    }))
  }
}

pub fn service() -> StatusList2021SvcServer<StatusList2021Service> {
  StatusList2021SvcServer::new(StatusList2021Service)
}
