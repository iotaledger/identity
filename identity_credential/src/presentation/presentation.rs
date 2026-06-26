// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;

use serde::de;
use serde::Deserialize;
use serde::Serialize;

use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Url;
use identity_core::convert::FmtJson;
use identity_core::convert::ToJson;
use serde::de::DeserializeOwned;

use crate::credential::Credential;
use crate::credential::CredentialV2;
use crate::credential::Policy;
use crate::credential::Proof;
use crate::credential::RefreshService;
use crate::error::Error;
use crate::error::Result;

use super::jwt_serialization::JwtPresentationV2Claims;
use super::jwt_serialization::PresentationJwtClaims;
use super::JwtPresentationOptions;
use super::PresentationBuilder;

/// Represents a bundle of one or more [`Credential`]s.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Presentation<CRED, T = Object> {
  /// The JSON-LD context(s) applicable to the `Presentation`.
  #[serde(rename = "@context")]
  pub context: OneOrMany<Context>,
  /// A unique `URI` that may be used to identify the `Presentation`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub id: Option<Url>,
  /// One or more URIs defining the type of the `Presentation`.
  #[serde(rename = "type")]
  pub types: OneOrMany<String>,
  /// Credential(s) expressing the claims of the `Presentation`.
  #[rustfmt::skip]
  #[serde(default = "Default::default", rename = "verifiableCredential", skip_serializing_if = "Vec::is_empty", deserialize_with = "deserialize_verifiable_credential", bound(deserialize = "CRED: serde::de::DeserializeOwned"))]
  pub verifiable_credential: Vec<CRED>,
  /// The entity that generated the `Presentation`.
  pub holder: Url,
  /// Service(s) used to refresh an expired [`Credential`] in the `Presentation`.
  #[serde(default, rename = "refreshService", skip_serializing_if = "OneOrMany::is_empty")]
  pub refresh_service: OneOrMany<RefreshService>,
  /// Terms-of-use specified by the `Presentation` holder.
  #[serde(default, rename = "termsOfUse", skip_serializing_if = "OneOrMany::is_empty")]
  pub terms_of_use: OneOrMany<Policy>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  pub properties: T,
  /// Optional cryptographic proof, unrelated to JWT.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proof: Option<Proof>,
}

/// Deserializes a `Vec<T>` while ensuring that it is not empty.
fn deserialize_verifiable_credential<'de, T: Deserialize<'de>, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
  D: de::Deserializer<'de>,
{
  let verifiable_credentials = Vec::<T>::deserialize(deserializer)?;

  (!verifiable_credentials.is_empty())
    .then_some(verifiable_credentials)
    .ok_or_else(|| de::Error::custom(Error::EmptyVerifiableCredentialArray))
}

impl<CRED, T> Presentation<CRED, T> {
  /// Returns the base JSON-LD context for `Presentation`s.
  #[deprecated(since = "1.8.0", note = "use `credential_context` instead")]
  pub fn base_context() -> &'static Context {
    Credential::<Object>::base_context()
  }

  /// Returns the presentation's JSON-LD base context.
  pub fn credential_context(&self) -> &Context {
    self.context.first().expect("context has at least one element")
  }

  /// Returns `true` if the presentation uses the VC Data Model v2.0 context.
  pub fn is_v2(&self) -> bool {
    self.credential_context() == CredentialV2::<()>::base_context()
  }

  /// Returns the base type for `Presentation`s.
  pub const fn base_type() -> &'static str {
    "VerifiablePresentation"
  }

  /// Creates a `PresentationBuilder` to configure a new Presentation.
  ///
  /// This is the same as [PresentationBuilder::new].
  pub fn builder(holder: Url, properties: T) -> PresentationBuilder<CRED, T> {
    PresentationBuilder::new(holder, properties)
  }

  /// Returns a new `Presentation` based on the `PresentationBuilder` configuration.
  pub fn from_builder(builder: PresentationBuilder<CRED, T>) -> Result<Self> {
    let this: Self = Self {
      context: builder.context.into(),
      id: builder.id,
      types: builder.types.into(),
      verifiable_credential: builder.credentials,
      holder: builder.holder,
      refresh_service: builder.refresh_service.into(),
      terms_of_use: builder.terms_of_use.into(),
      properties: builder.properties,
      proof: None,
    };
    this.check_structure()?;

    Ok(this)
  }

  /// Validates the semantic structure of the `Presentation`.
  ///
  /// # Warning
  ///
  /// This does not check the semantic structure of the contained credentials. This needs to be done as part of
  /// signature validation on the credentials as they are encoded as JWTs.
  pub fn check_structure(&self) -> Result<()> {
    let is_valid_base_context =
      |ctx: &Context| ctx == Credential::<()>::base_context() || ctx == CredentialV2::<()>::base_context();
    // Ensure the base context is present and in the correct location
    match self.context.first() {
      Some(context) if is_valid_base_context(context) => {}
      Some(_) | None => return Err(Error::MissingBaseContext),
    }

    // The set of types MUST contain the base type
    if !self.types.iter().any(|type_| type_ == Self::base_type()) {
      return Err(Error::MissingBaseType);
    }
    Ok(())
  }

  /// Sets the value of the proof property.
  ///
  /// Note that this proof is not related to JWT.
  pub fn set_proof(&mut self, proof: Option<Proof>) {
    self.proof = proof;
  }
}

impl<C, T> Presentation<C, T>
where
  T: Clone + Serialize + DeserializeOwned,
  C: Clone + Serialize + DeserializeOwned,
{
  /// Serializes the [Presentation] as a JWT claims set
  /// in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token) or
  /// [VC Data Model v2.0](https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose) depending on the
  /// base context used.
  ///
  /// The resulting string can be used as the payload of a JWS when presenting it.  
  pub fn serialize_jwt(&self, options: &JwtPresentationOptions) -> Result<String> {
    let context = self.credential_context();
    if context == Credential::<()>::base_context() {
      // VC Data Model v1.1
      let jwt_representation: PresentationJwtClaims<'_, C, T> = PresentationJwtClaims::new(self, options)?;
      jwt_representation
        .to_json()
        .map_err(|err| Error::JwtClaimsSetSerializationError(err.into()))
    } else if context == CredentialV2::<()>::base_context() {
      // VC Data Model v2.0
      JwtPresentationV2Claims::from_options(self.clone(), options)
        .to_json()
        .map_err(|err| Error::JwtClaimsSetSerializationError(err.into()))
    } else {
      Err(Error::MissingBaseContext)
    }
  }
}

impl<T> Display for Presentation<T>
where
  T: Serialize,
{
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    self.fmt_json(f)
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;
  use std::error::Error;

  use identity_core::common::Object;
  use identity_core::convert::FromJson;

  use crate::presentation::Presentation;

  #[test]
  fn test_presentation_deserialization() {
    // Example verifiable presentation taken from:
    // https://www.w3.org/TR/vc-data-model/#example-a-simple-example-of-a-verifiable-presentation
    // with some minor adjustments (adding the `holder` property and shortening the 'jws' values).
    assert!(Presentation::<Object>::from_json_value(json!({
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "holder": "did:test:abc1",
      "type": "VerifiablePresentation",
      "verifiableCredential": [{
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/1872",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "issuer": "https://example.edu/issuers/565049",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "alumniOf": {
            "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
            "name": [{
              "value": "Example University",
              "lang": "en"
            }, {
              "value": "Exemple d'Université",
              "lang": "fr"
            }]
          }
        },
        "proof": {
          "type": "RsaSignature2018",
          "created": "2017-06-18T21:19:10Z",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "https://example.edu/issuers/565049#key-1",
          "jws": "eyJhb...dBBPM"
        }
      }],
    }))
    .is_ok());
  }

  #[test]
  fn test_presentation_deserialization_without_credentials() {
    // Deserializing a Presentation without `verifiableCredential' property is allowed.
    assert!(Presentation::<()>::from_json_value(json!({
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "holder": "did:test:abc1",
      "type": "VerifiablePresentation"
    }))
    .is_ok());
  }

  #[test]
  fn test_presentation_deserialization_with_empty_credential_array() {
    assert_eq!(
      Presentation::<()>::from_json_value(json!({
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "holder": "did:test:abc1",
        "type": "VerifiablePresentation",
        "verifiableCredential": []
      }))
      .unwrap_err()
      .source()
      .unwrap()
      .to_string(),
      crate::error::Error::EmptyVerifiableCredentialArray.to_string()
    );
  }
}
