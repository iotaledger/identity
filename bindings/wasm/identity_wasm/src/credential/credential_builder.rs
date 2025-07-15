// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Context;
use identity_iota::core::Object;
use identity_iota::core::OneOrMany;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::Evidence;
use identity_iota::credential::Issuer;
use identity_iota::credential::Policy;
use identity_iota::credential::Proof;
use identity_iota::credential::RefreshService;
use identity_iota::credential::Schema;
use identity_iota::credential::Status;
use identity_iota::credential::Subject;
use wasm_bindgen::prelude::*;

use proc_typescript::typescript;

use crate::error::WasmResult;

impl TryFrom<ICredential> for CredentialBuilder {
  type Error = JsValue;

  fn try_from(values: ICredential) -> std::result::Result<Self, Self::Error> {
    let ICredentialHelper {
      context,
      id,
      r#type,
      credential_subject,
      issuer,
      issuance_date,
      expiration_date,
      credential_status,
      credential_schema,
      refresh_service,
      terms_of_use,
      evidence,
      non_transferable,
      proof,
      properties,
    } = values.into_serde::<ICredentialHelper>().wasm_result()?;

    let mut builder: CredentialBuilder = CredentialBuilder::new(properties);

    if let Some(context) = context {
      for value in context.into_vec() {
        builder = builder.context(value);
      }
    }
    if let Some(id) = id {
      builder = builder.id(Url::parse(id).wasm_result()?);
    }
    if let Some(types) = r#type {
      for value in types.iter() {
        builder = builder.type_(value);
      }
    }
    if let Some(credential_subject) = credential_subject {
      for subject in credential_subject.into_vec() {
        builder = builder.subject(subject);
      }
    }
    if let Some(issuer) = issuer {
      builder = builder.issuer(issuer);
    }
    if let Some(issuance_date) = issuance_date {
      builder = builder.issuance_date(issuance_date);
    }
    if let Some(expiration_date) = expiration_date {
      builder = builder.expiration_date(expiration_date);
    }
    if let Some(credential_status) = credential_status {
      builder = builder.status(credential_status);
    }
    if let Some(credential_schema) = credential_schema {
      for schema in credential_schema.into_vec() {
        builder = builder.schema(schema);
      }
    }
    if let Some(refresh_service) = refresh_service {
      for service in refresh_service.into_vec() {
        builder = builder.refresh_service(service);
      }
    }
    if let Some(terms_of_use) = terms_of_use {
      for policy in terms_of_use.into_vec() {
        builder = builder.terms_of_use(policy);
      }
    }
    if let Some(evidence) = evidence {
      for value in evidence.into_vec() {
        builder = builder.evidence(value);
      }
    }
    if let Some(non_transferable) = non_transferable {
      builder = builder.non_transferable(non_transferable);
    }
    if let Some(proof) = proof {
      builder = builder.proof(proof);
    }

    Ok(builder)
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "ICredential")]
  pub type ICredential;
}

/// Fields for constructing a new {@link Credential}.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[typescript(name = "ICredential", readonly, optional)]
struct ICredentialHelper {
  /// The JSON-LD context(s) applicable to the {@link Credential}.
  #[typescript(type = "string | Record<string, any> | Array<string | Record<string, any>>")]
  context: Option<OneOrMany<Context>>,
  /// A unique URI that may be used to identify the {@link Credential}.
  #[typescript(type = "string")]
  id: Option<String>,
  /// One or more URIs defining the type of the {@link Credential}. Contains the base context by default.
  #[typescript(name = "type", type = "string | Array<string>")]
  r#type: Option<OneOrMany<String>>,
  /// One or more objects representing the {@link Credential} subject(s).
  #[typescript(optional = false, name = "credentialSubject", type = "Subject | Array<Subject>")]
  credential_subject: Option<OneOrMany<Subject>>,
  /// A reference to the issuer of the {@link Credential}.
  #[typescript(optional = false, type = "string | CoreDID | IotaDID | Issuer")]
  issuer: Option<Issuer>,
  /// A timestamp of when the {@link Credential} becomes valid. Defaults to the current datetime.
  #[typescript(name = "issuanceDate", type = "Timestamp")]
  issuance_date: Option<Timestamp>,
  /// A timestamp of when the {@link Credential} should no longer be considered valid.
  #[typescript(name = "expirationDate", type = "Timestamp")]
  expiration_date: Option<Timestamp>,
  /// Information used to determine the current status of the {@link Credential}.
  #[typescript(name = "credentialStatus", type = "Status")]
  credential_status: Option<Status>,
  /// Information used to assist in the enforcement of a specific {@link Credential} structure.
  #[typescript(name = "credentialSchema", type = "Schema | Array<Schema>")]
  credential_schema: Option<OneOrMany<Schema>>,
  /// Service(s) used to refresh an expired {@link Credential}.
  #[typescript(name = "refreshService", type = "RefreshService | Array<RefreshService>")]
  refresh_service: Option<OneOrMany<RefreshService>>,
  /// Terms-of-use specified by the {@link Credential} issuer.
  #[typescript(name = "termsOfUse", type = "Policy | Array<Policy>")]
  terms_of_use: Option<OneOrMany<Policy>>,
  /// Human-readable evidence used to support the claims within the {@link Credential}.
  #[typescript(type = "Evidence | Array<Evidence>")]
  evidence: Option<OneOrMany<Evidence>>,
  /// Indicates that the {@link Credential} must only be contained within a {@link Presentation} with a proof issued
  /// from the {@link Credential} subject.
  #[typescript(name = "nonTransferable", type = "boolean")]
  non_transferable: Option<bool>,
  // The `proof` property of the {@link Credential}.
  #[typescript(type = "Proof")]
  proof: Option<Proof>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  #[typescript(optional = false, name = "[properties: string]", type = "unknown")]
  properties: Object,
}
