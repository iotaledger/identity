// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;

use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FmtJson as _;
use identity_core::convert::ToJson as _;
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde::de::Error as _;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;

use crate::credential::CredentialBuilder;
use crate::credential::CredentialJwtClaims;
use crate::credential::CredentialSealed;
use crate::credential::CredentialT;
use crate::credential::Evidence;
use crate::credential::Issuer;
use crate::credential::Policy;
use crate::credential::Proof;
use crate::credential::RefreshService;
use crate::credential::Schema;
use crate::credential::Status;
use crate::credential::Subject;
use crate::error::Error;
use crate::error::Result;

pub(crate) static BASE_CONTEXT: Lazy<Context> =
  Lazy::new(|| Context::Url(Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()));

fn deserialize_vc2_0_context<'de, D>(deserializer: D) -> Result<OneOrMany<Context>, D::Error>
where
  D: Deserializer<'de>,
{
  let ctx = OneOrMany::<Context>::deserialize(deserializer)?;
  if ctx.contains(&BASE_CONTEXT) {
    Ok(ctx)
  } else {
    Err(D::Error::custom("Missing base context"))
  }
}

/// A [VC Data Model](https://www.w3.org/TR/vc-data-model-2.0/) 2.0 Verifiable Credential.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Credential<T = Object> {
  /// The JSON-LD context(s) applicable to the `Credential`.
  #[serde(rename = "@context", deserialize_with = "deserialize_vc2_0_context")]
  pub context: OneOrMany<Context>,
  /// A unique `URI` that may be used to identify the `Credential`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub id: Option<Url>,
  /// One or more URIs defining the type of the `Credential`.
  #[serde(rename = "type")]
  pub types: OneOrMany<String>,
  /// One or more `Object`s representing the `Credential` subject(s).
  #[serde(rename = "credentialSubject")]
  pub credential_subject: OneOrMany<Subject>,
  /// A reference to the issuer of the `Credential`.
  pub issuer: Issuer,
  /// A timestamp of when the `Credential` becomes valid.
  #[serde(rename = "validFrom")]
  pub valid_from: Timestamp,
  /// A timestamp of when the `Credential` should no longer be considered valid.
  #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
  pub valid_until: Option<Timestamp>,
  /// Information used to determine the current status of the `Credential`.
  #[serde(default, rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
  pub credential_status: Option<Status>,
  /// Information used to assist in the enforcement of a specific `Credential` structure.
  #[serde(default, rename = "credentialSchema", skip_serializing_if = "OneOrMany::is_empty")]
  pub credential_schema: OneOrMany<Schema>,
  /// Service(s) used to refresh an expired `Credential`.
  #[serde(default, rename = "refreshService", skip_serializing_if = "OneOrMany::is_empty")]
  pub refresh_service: OneOrMany<RefreshService>,
  /// Terms-of-use specified by the `Credential` issuer.
  #[serde(default, rename = "termsOfUse", skip_serializing_if = "OneOrMany::is_empty")]
  pub terms_of_use: OneOrMany<Policy>,
  /// Human-readable evidence used to support the claims within the `Credential`.
  #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
  pub evidence: OneOrMany<Evidence>,
  /// Indicates that the `Credential` must only be contained within a
  /// [`Presentation`][crate::presentation::Presentation] with a proof issued from the `Credential` subject.
  #[serde(rename = "nonTransferable", skip_serializing_if = "Option::is_none")]
  pub non_transferable: Option<bool>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  pub properties: T,
  /// Optional cryptographic proof, unrelated to JWT.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proof: Option<Proof>,
}

impl<T> Credential<T> {
  /// Returns the base context for `Credential`s.
  pub fn base_context() -> &'static Context {
    &BASE_CONTEXT
  }

  /// Returns the base type for `Credential`s.
  pub fn base_type() -> &'static str {
    "VerifiableCredential"
  }

  /// Creates a `Credential` from a `CredentialBuilder`.
  pub fn from_builder(mut builder: CredentialBuilder<T>) -> Result<Self> {
    if builder.context.first() != Some(Self::base_context()) {
      builder.context.insert(0, Self::base_context().clone());
    }

    if builder.types.first().map(String::as_str) != Some(Self::base_type()) {
      builder.types.insert(0, Self::base_type().to_owned());
    }

    let this = Self {
      context: OneOrMany::Many(builder.context),
      id: builder.id,
      types: builder.types.into(),
      credential_subject: builder.subject.into(),
      issuer: builder.issuer.ok_or(Error::MissingIssuer)?,
      valid_from: builder.issuance_date.unwrap_or_default(),
      valid_until: builder.expiration_date,
      credential_status: builder.status,
      credential_schema: builder.schema.into(),
      refresh_service: builder.refresh_service.into(),
      terms_of_use: builder.terms_of_use.into(),
      evidence: builder.evidence.into(),
      non_transferable: builder.non_transferable,
      properties: builder.properties,
      proof: builder.proof,
    };

    this.check_structure()?;

    Ok(this)
  }

  /// Validates the semantic structure of the `Credential`.
  pub(crate) fn check_structure(&self) -> Result<()> {
    // Ensure the base context is present and in the correct location
    match self.context.get(0) {
      Some(context) if context == Self::base_context() => {}
      Some(_) | None => return Err(Error::MissingBaseContext),
    }

    // The set of types MUST contain the base type
    if !self.types.iter().any(|type_| type_ == Self::base_type()) {
      return Err(Error::MissingBaseType);
    }

    // Credentials MUST have at least one subject
    if self.credential_subject.is_empty() {
      return Err(Error::MissingSubject);
    }

    // Each subject is defined as one or more properties - no empty objects
    for subject in self.credential_subject.iter() {
      if subject.id.is_none() && subject.properties.is_empty() {
        return Err(Error::InvalidSubject);
      }
    }

    Ok(())
  }
}

impl<T> Display for Credential<T>
where
  T: Serialize,
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
    self.fmt_json(f)
  }
}

impl<T> CredentialSealed for Credential<T> {}

impl<T> CredentialT for Credential<T>
where
  T: Clone + Serialize + DeserializeOwned,
{
  type Properties = T;

  fn base_context(&self) -> &'static Context {
    Self::base_context()
  }

  fn type_(&self) -> &OneOrMany<String> {
    &self.types
  }

  fn context(&self) -> &OneOrMany<Context> {
    &self.context
  }

  fn subject(&self) -> &OneOrMany<Subject> {
    &self.credential_subject
  }

  fn issuer(&self) -> &Issuer {
    &self.issuer
  }

  fn valid_from(&self) -> Timestamp {
    self.valid_from
  }

  fn valid_until(&self) -> Option<Timestamp> {
    self.valid_until
  }

  fn properties(&self) -> &Self::Properties {
    &self.properties
  }

  fn status(&self) -> Option<&Status> {
    self.credential_status.as_ref()
  }

  fn non_transferable(&self) -> bool {
    self.non_transferable.unwrap_or_default()
  }

  fn serialize_jwt(&self, custom_claims: Option<Object>) -> Result<String> {
    self.serialize_jwt(custom_claims)
  }
}

impl<T> Credential<T>
where
  T: ToOwned<Owned = T> + Serialize + DeserializeOwned,
{
  /// Serializes the [`Credential`] as a JWT claims set
  /// in accordance with [VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
  ///
  /// The resulting string can be used as the payload of a JWS when issuing the credential.  
  pub fn serialize_jwt(&self, custom_claims: Option<Object>) -> Result<String> {
    let jwt_representation: CredentialJwtClaims<'_, T> = CredentialJwtClaims::new_v2(self, custom_claims)?;
    jwt_representation
      .to_json()
      .map_err(|err| Error::JwtClaimsSetSerializationError(err.into()))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn valid_from_json_str() {
    let json_credential = r#"
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "http://university.example/credentials/3732",
  "type": [
    "VerifiableCredential",
    "ExampleDegreeCredential"
  ],
  "issuer": "https://university.example/issuers/565049",
  "validFrom": "2010-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "ExampleBachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}
    "#;
    serde_json::from_str::<Credential>(json_credential).expect("valid VC using Data Model 2.0");
  }

  #[test]
  fn invalid_from_json_str() {
    let json_credential = include_str!("../../tests/fixtures/credential-1.json");
    let _error = serde_json::from_str::<Credential>(json_credential).unwrap_err();
  }
}
