// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

#[cfg(feature = "jpt-bbs-plus")]
use jsonprooftoken::jpt::claims::JptClaims;
use serde::Deserialize;
use serde::Serialize;

use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use serde::de::DeserializeOwned;

use crate::credential::credential_v2::Credential as CredentialV2;
use crate::credential::Credential;
use crate::credential::Evidence;
use crate::credential::Issuer;
use crate::credential::Policy;
use crate::credential::Proof;
use crate::credential::RefreshService;
use crate::credential::Schema;
use crate::credential::Status;
use crate::credential::Subject;
use crate::Error;
use crate::Result;

/// A JWT representing a Verifiable Credential.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct JwtCredential(CredentialJwtClaims<'static>);

#[cfg(feature = "validator")]
impl TryFrom<JwtCredential> for Credential {
  type Error = Error;
  fn try_from(value: JwtCredential) -> std::result::Result<Self, Self::Error> {
    value.0.try_into_credential()
  }
}

/// Implementation of JWT Encoding/Decoding according to [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
///
/// This type is opinionated in the following ways:
/// 1. Serialization tries to duplicate as little as possible between the required registered claims and the `vc` entry.
/// 2. Only allows serializing/deserializing claims "exp, iss, nbf &/or iat, jti, sub and vc". Other custom properties
///    must be set in the `vc` entry.
#[derive(Serialize, Deserialize)]
pub(crate) struct CredentialJwtClaims<'credential, T = Object>
where
  T: ToOwned + Serialize,
  <T as ToOwned>::Owned: DeserializeOwned,
{
  /// Represents the expirationDate encoded as a UNIX timestamp.  
  #[serde(skip_serializing_if = "Option::is_none")]
  exp: Option<i64>,
  /// Represents the issuer.
  pub(crate) iss: Cow<'credential, Issuer>,

  /// Represents the issuanceDate encoded as a UNIX timestamp.
  #[serde(flatten)]
  issuance_date: IssuanceDateClaims,

  /// Represents the id property of the credential.
  #[serde(skip_serializing_if = "Option::is_none")]
  jti: Option<Cow<'credential, Url>>,

  /// Represents the subject's id.
  #[serde(skip_serializing_if = "Option::is_none")]
  sub: Option<Cow<'credential, Url>>,

  vc: InnerCredential<'credential, T>,

  #[serde(flatten, skip_serializing_if = "Option::is_none")]
  pub(crate) custom: Option<Object>,
}

impl<'credential, T> CredentialJwtClaims<'credential, T>
where
  T: ToOwned<Owned = T> + Serialize + DeserializeOwned,
{
  pub(crate) fn new(credential: &'credential Credential<T>, custom: Option<Object>) -> Result<Self> {
    let Credential {
      context,
      id,
      types,
      credential_subject: OneOrMany::One(subject),
      issuer,
      issuance_date,
      expiration_date,
      credential_status,
      credential_schema,
      refresh_service,
      terms_of_use,
      evidence,
      non_transferable,
      properties,
      proof,
    } = credential
    else {
      return Err(Error::MoreThanOneSubjectInJwt);
    };

    Ok(Self {
      exp: expiration_date.map(|value| Timestamp::to_unix(&value)),
      iss: Cow::Borrowed(issuer),
      issuance_date: IssuanceDateClaims::new(*issuance_date),
      jti: id.as_ref().map(Cow::Borrowed),
      sub: subject.id.as_ref().map(Cow::Borrowed),
      vc: InnerCredential {
        context: Cow::Borrowed(context),
        id: None,
        types: Cow::Borrowed(types),
        credential_subject: InnerCredentialSubject::new(subject),
        issuance_date: None,
        expiration_date: None,
        valid_from: None,
        valid_until: None,
        issuer: None,
        credential_schema: Cow::Borrowed(credential_schema),
        credential_status: credential_status.as_ref().map(Cow::Borrowed),
        refresh_service: Cow::Borrowed(refresh_service),
        terms_of_use: Cow::Borrowed(terms_of_use),
        evidence: Cow::Borrowed(evidence),
        non_transferable: *non_transferable,
        properties: Cow::Borrowed(properties),
        proof: proof.as_ref().map(Cow::Borrowed),
      },
      custom,
    })
  }

  pub(crate) fn new_v2(credential: &'credential CredentialV2<T>, custom: Option<Object>) -> Result<Self> {
    let CredentialV2 {
      context,
      id,
      types,
      credential_subject: OneOrMany::One(subject),
      issuer,
      valid_from,
      valid_until,
      credential_status,
      credential_schema,
      refresh_service,
      terms_of_use,
      evidence,
      non_transferable,
      properties,
      proof,
    } = credential
    else {
      return Err(Error::MoreThanOneSubjectInJwt);
    };

    Ok(Self {
      exp: valid_until.map(|value| Timestamp::to_unix(&value)),
      iss: Cow::Borrowed(issuer),
      issuance_date: IssuanceDateClaims::new(*valid_from),
      jti: id.as_ref().map(Cow::Borrowed),
      sub: subject.id.as_ref().map(Cow::Borrowed),
      vc: InnerCredential {
        context: Cow::Borrowed(context),
        id: None,
        types: Cow::Borrowed(types),
        credential_subject: InnerCredentialSubject::new(subject),
        issuance_date: None,
        expiration_date: None,
        valid_from: None,
        valid_until: None,
        issuer: None,
        credential_schema: Cow::Borrowed(credential_schema),
        credential_status: credential_status.as_ref().map(Cow::Borrowed),
        refresh_service: Cow::Borrowed(refresh_service),
        terms_of_use: Cow::Borrowed(terms_of_use),
        evidence: Cow::Borrowed(evidence),
        non_transferable: *non_transferable,
        properties: Cow::Borrowed(properties),
        proof: proof.as_ref().map(Cow::Borrowed),
      },
      custom,
    })
  }
}

#[cfg(feature = "validator")]
impl<T> CredentialJwtClaims<'_, T>
where
  T: ToOwned<Owned = T> + Serialize + DeserializeOwned,
{
  /// Checks whether the fields that are set in the `vc` object are consistent with the corresponding values
  /// set for the registered claims.
  fn check_consistency(&self) -> Result<()> {
    // Check consistency of issuer.
    let issuer_from_claims: &Issuer = self.iss.as_ref();
    if !self
      .vc
      .issuer
      .as_ref()
      .map(|value| value == issuer_from_claims)
      .unwrap_or(true)
    {
      return Err(Error::InconsistentCredentialJwtClaims("inconsistent issuer"));
    };

    // Check consistency of issuanceDate
    let issuance_date_from_claims = self.issuance_date.to_issuance_date()?;
    if !self
      .vc
      .issuance_date
      .map(|value| value == issuance_date_from_claims)
      .unwrap_or(true)
    {
      return Err(Error::InconsistentCredentialJwtClaims("inconsistent issuanceDate"));
    };

    // Check consistency of expirationDate
    if !self
      .vc
      .expiration_date
      .map(|value| self.exp.filter(|exp| *exp == value.to_unix()).is_some())
      .unwrap_or(true)
    {
      return Err(Error::InconsistentCredentialJwtClaims(
        "inconsistent credential expirationDate",
      ));
    };

    // Check consistency of id
    if !self
      .vc
      .id
      .as_ref()
      .map(|value| self.jti.as_ref().filter(|jti| jti.as_ref() == value).is_some())
      .unwrap_or(true)
    {
      return Err(Error::InconsistentCredentialJwtClaims("inconsistent credential id"));
    };

    // Check consistency of credentialSubject
    if let Some(ref inner_credential_subject_id) = self.vc.credential_subject.id {
      let subject_claim = self.sub.as_ref().ok_or(Error::InconsistentCredentialJwtClaims(
        "inconsistent credentialSubject: expected identifier in sub",
      ))?;
      if subject_claim.as_ref() != inner_credential_subject_id {
        return Err(Error::InconsistentCredentialJwtClaims(
          "inconsistent credentialSubject: identifiers do not match",
        ));
      }
    };

    Ok(())
  }

  /// Converts the JWT representation into a [`Credential`].
  ///
  /// # Errors
  /// Errors if either timestamp conversion or [`Self::check_consistency`] fails.
  pub(crate) fn try_into_credential(self) -> Result<Credential<T>> {
    self.check_consistency()?;

    let Self {
      exp,
      iss,
      issuance_date,
      jti,
      sub,
      vc,
      ..
    } = self;

    let InnerCredential {
      context,
      types,
      credential_subject,
      credential_status,
      credential_schema,
      refresh_service,
      terms_of_use,
      evidence,
      non_transferable,
      properties,
      proof,
      ..
    } = vc;

    Ok(Credential {
      context: context.into_owned(),
      id: jti.map(Cow::into_owned),
      types: types.into_owned(),
      credential_subject: {
        OneOrMany::One(Subject {
          id: sub.map(Cow::into_owned),
          properties: credential_subject.properties.into_owned(),
        })
      },
      issuer: iss.into_owned(),
      issuance_date: issuance_date.to_issuance_date()?,
      expiration_date: exp
        .map(Timestamp::from_unix)
        .transpose()
        .map_err(|_| Error::TimestampConversionError)?,
      credential_status: credential_status.map(Cow::into_owned),
      credential_schema: credential_schema.into_owned(),
      refresh_service: refresh_service.into_owned(),
      terms_of_use: terms_of_use.into_owned(),
      evidence: evidence.into_owned(),
      non_transferable,
      properties: properties.into_owned(),
      proof: proof.map(Cow::into_owned),
    })
  }

  /// Converts the JWT representation into a [`CredentialV2`].
  ///
  /// # Errors
  /// Errors if either timestamp conversion or [`Self::check_consistency`] fails.
  pub(crate) fn try_into_credential_v2(self) -> Result<CredentialV2<T>> {
    self.check_consistency()?;

    let Self {
      exp,
      iss,
      issuance_date,
      jti,
      sub,
      vc,
      ..
    } = self;

    let InnerCredential {
      context,
      types,
      credential_subject,
      credential_status,
      credential_schema,
      refresh_service,
      terms_of_use,
      evidence,
      non_transferable,
      properties,
      proof,
      ..
    } = vc;

    // Make sure inner credential contains the right context
    if context.first() != Some(&crate::credential::credential_v2::BASE_CONTEXT) {
      return Err(Error::MissingBaseContext);
    }

    Ok(CredentialV2 {
      context: context.into_owned(),
      id: jti.map(Cow::into_owned),
      types: types.into_owned(),
      credential_subject: {
        OneOrMany::One(Subject {
          id: sub.map(Cow::into_owned),
          properties: credential_subject.properties.into_owned(),
        })
      },
      issuer: iss.into_owned(),
      valid_from: issuance_date.to_issuance_date()?,
      valid_until: exp
        .map(Timestamp::from_unix)
        .transpose()
        .map_err(|_| Error::TimestampConversionError)?,
      credential_status: credential_status.map(Cow::into_owned),
      credential_schema: credential_schema.into_owned(),
      refresh_service: refresh_service.into_owned(),
      terms_of_use: terms_of_use.into_owned(),
      evidence: evidence.into_owned(),
      non_transferable,
      properties: properties.into_owned(),
      proof: proof.map(Cow::into_owned),
    })
  }
}

/// The [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token) states that issuanceDate
/// corresponds to the registered `nbf` claim, but `iat` is also used in the ecosystem.
/// This type aims to take care of this discrepancy on a best effort basis.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub(crate) struct IssuanceDateClaims {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) iat: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) nbf: Option<i64>,
}

impl IssuanceDateClaims {
  pub(crate) fn new(issuance_date: Timestamp) -> Self {
    Self {
      iat: None,
      nbf: Some(issuance_date.to_unix()),
    }
  }
  /// Produces the `issuanceDate` value from `nbf` if it is set,
  /// otherwise falls back to `iat`. If none of these values are set an error is returned.
  #[cfg(feature = "validator")]
  pub(crate) fn to_issuance_date(self) -> Result<Timestamp> {
    if let Some(timestamp) = self
      .nbf
      .map(Timestamp::from_unix)
      .transpose()
      .map_err(|_| Error::TimestampConversionError)?
    {
      Ok(timestamp)
    } else {
      Timestamp::from_unix(self.iat.ok_or(Error::TimestampConversionError)?)
        .map_err(|_| Error::TimestampConversionError)
    }
  }
}

#[derive(Serialize, Deserialize)]
struct InnerCredentialSubject<'credential> {
  // Do not serialize this to save space as the value must be included in the `sub` claim.
  #[cfg(feature = "validator")]
  #[serde(skip_serializing)]
  id: Option<Url>,

  #[serde(flatten)]
  properties: Cow<'credential, Object>,
}

impl<'credential> InnerCredentialSubject<'credential> {
  fn new(subject: &'credential Subject) -> Self {
    Self {
      #[cfg(feature = "validator")]
      id: None,
      properties: Cow::Borrowed(&subject.properties),
    }
  }
}

/// Mostly copied from [`VerifiableCredential`] with the entries corresponding
/// to registered claims being the exception.
#[derive(Serialize, Deserialize)]
struct InnerCredential<'credential, T = Object>
where
  T: ToOwned + Serialize,
  <T as ToOwned>::Owned: DeserializeOwned,
{
  /// The JSON-LD context(s) applicable to the `Credential`.
  #[serde(rename = "@context")]
  context: Cow<'credential, OneOrMany<Context>>,
  /// A unique `URI` that may be used to identify the `Credential`.
  #[serde(skip_serializing_if = "Option::is_none")]
  id: Option<Url>,
  /// One or more URIs defining the type of the `Credential`.
  #[serde(rename = "type")]
  types: Cow<'credential, OneOrMany<String>>,
  /// The issuer of the `Credential`.
  #[serde(skip_serializing_if = "Option::is_none")]
  issuer: Option<Issuer>,
  /// One or more `Object`s representing the `Credential` subject(s).
  #[serde(rename = "credentialSubject")]
  credential_subject: InnerCredentialSubject<'credential>,
  /// A timestamp of when the `Credential` becomes valid.
  #[serde(rename = "issuanceDate", skip_serializing_if = "Option::is_none")]
  issuance_date: Option<Timestamp>,
  /// A timestamp of when the `Credential` should no longer be considered valid.
  #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
  expiration_date: Option<Timestamp>,
  /// A timestamp of when the `Credential` becomes valid.
  #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
  valid_from: Option<Timestamp>,
  /// A timestamp of when the `Credential` should no longer be considered valid.
  #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
  valid_until: Option<Timestamp>,
  /// Information used to determine the current status of the `Credential`.
  #[serde(default, rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
  credential_status: Option<Cow<'credential, Status>>,
  /// Information used to assist in the enforcement of a specific `Credential` structure.
  #[serde(default, rename = "credentialSchema", skip_serializing_if = "OneOrMany::is_empty")]
  credential_schema: Cow<'credential, OneOrMany<Schema>>,
  /// Service(s) used to refresh an expired `Credential`.
  #[serde(default, rename = "refreshService", skip_serializing_if = "OneOrMany::is_empty")]
  refresh_service: Cow<'credential, OneOrMany<RefreshService>>,
  /// Terms-of-use specified by the `Credential` issuer.
  #[serde(default, rename = "termsOfUse", skip_serializing_if = "OneOrMany::is_empty")]
  terms_of_use: Cow<'credential, OneOrMany<Policy>>,
  /// Human-readable evidence used to support the claims within the `Credential`.
  #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
  evidence: Cow<'credential, OneOrMany<Evidence>>,
  /// Indicates that the `Credential` must only be contained within a
  /// [`Presentation`][crate::presentation::Presentation] with a proof issued from the `Credential` subject.
  #[serde(rename = "nonTransferable", skip_serializing_if = "Option::is_none")]
  non_transferable: Option<bool>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  properties: Cow<'credential, T>,
  /// Proof(s) used to verify a `Credential`
  #[serde(skip_serializing_if = "Option::is_none")]
  proof: Option<Cow<'credential, Proof>>,
}

#[cfg(feature = "jpt-bbs-plus")]
impl<'credential, T> From<CredentialJwtClaims<'credential, T>> for JptClaims
where
  T: ToOwned + Serialize,
  <T as ToOwned>::Owned: DeserializeOwned,
{
  fn from(item: CredentialJwtClaims<'credential, T>) -> Self {
    let CredentialJwtClaims {
      exp,
      iss,
      issuance_date,
      jti,
      sub,
      vc,
      custom,
    } = item;

    let mut claims = JptClaims::new();

    if let Some(exp) = exp {
      claims.set_exp(exp);
    }

    claims.set_iss(iss.url().to_string());

    if let Some(iat) = issuance_date.iat {
      claims.set_iat(iat);
    }

    if let Some(nbf) = issuance_date.nbf {
      claims.set_nbf(nbf);
    }

    if let Some(jti) = jti {
      claims.set_jti(jti.to_string());
    }

    if let Some(sub) = sub {
      claims.set_sub(sub.to_string());
    }

    claims.set_claim(Some("vc"), vc, true);

    if let Some(custom) = custom {
      claims.set_claim(None, custom, true);
    }

    claims
  }
}

#[cfg(test)]
mod tests {
  use identity_core::common::Object;
  use identity_core::convert::FromJson;
  use identity_core::convert::ToJson;

  use crate::credential::Credential;
  use crate::Error;

  use super::CredentialJwtClaims;

  #[test]
  fn roundtrip() {
    let credential_json: &str = r#"
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://example.edu/issuers/14",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science in Mechanical Engineering"
        }
      }
    }"#;

    let expected_serialization_json: &str = r#"
    {
      "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "jti": "http://example.edu/credentials/3732",
      "iss": "https://example.edu/issuers/14",
      "nbf":  1262373804,
      "vc": {
        "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "credentialSubject": {
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science in Mechanical Engineering"
          }
        }
      }
    }"#;

    let credential: Credential = Credential::from_json(credential_json).unwrap();
    let jwt_credential_claims: CredentialJwtClaims<'_> = CredentialJwtClaims::new(&credential, None).unwrap();
    let jwt_credential_claims_serialized: String = jwt_credential_claims.to_json().unwrap();
    // Compare JSON representations
    assert_eq!(
      Object::from_json(expected_serialization_json).unwrap(),
      Object::from_json(&jwt_credential_claims_serialized).unwrap()
    );

    // Retrieve the credential from the JWT serialization
    let retrieved_credential: Credential = {
      CredentialJwtClaims::<'static, Object>::from_json(&jwt_credential_claims_serialized)
        .unwrap()
        .try_into_credential()
        .unwrap()
    };

    assert_eq!(credential, retrieved_credential);
  }

  #[test]
  fn claims_duplication() {
    let credential_json: &str = r#"
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://example.edu/issuers/14",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "expirationDate": "2025-09-13T15:56:23Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science in Mechanical Engineering"
        }
      }
    }"#;

    // `sub`, `exp`, `jti`, `iss`, `nbf` are duplicated in `vc`.
    let claims_json: &str = r#"
    {
      "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "jti": "http://example.edu/credentials/3732",
      "iss": "https://example.edu/issuers/14",
      "nbf":  1262373804,
      "exp": 1757778983,
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "https://example.edu/issuers/14",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "expirationDate": "2025-09-13T15:56:23Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science in Mechanical Engineering"
          }
        }
      }
    }"#;

    let credential: Credential = Credential::from_json(credential_json).unwrap();
    let credential_from_claims: Credential = CredentialJwtClaims::<'_, Object>::from_json(&claims_json)
      .unwrap()
      .try_into_credential()
      .unwrap();

    assert_eq!(credential, credential_from_claims);
  }

  #[test]
  fn inconsistent_issuer() {
    // issuer is inconsistent (15 instead of 14).
    let claims_json: &str = r#"
    {
      "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "jti": "http://example.edu/credentials/3732",
      "iss": "https://example.edu/issuers/14",
      "nbf":  1262373804,
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "https://example.edu/issuers/15",
        "credentialSubject": {
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science in Mechanical Engineering"
          }
        }
      }
    }"#;

    let credential_from_claims_result: Result<Credential, _> =
      CredentialJwtClaims::<'_, Object>::from_json(&claims_json)
        .unwrap()
        .try_into_credential();
    assert!(matches!(
      credential_from_claims_result.unwrap_err(),
      Error::InconsistentCredentialJwtClaims("inconsistent issuer")
    ));
  }

  #[test]
  fn inconsistent_id() {
    let claims_json: &str = r#"
    {
      "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "jti": "http://example.edu/credentials/3732",
      "iss": "https://example.edu/issuers/14",
      "nbf":  1262373804,
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "id": "http://example.edu/credentials/1111",
        "credentialSubject": {
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science in Mechanical Engineering"
          }
        }
      }
    }"#;

    let credential_from_claims_result: Result<Credential, _> =
      CredentialJwtClaims::<'_, Object>::from_json(&claims_json)
        .unwrap()
        .try_into_credential();
    assert!(matches!(
      credential_from_claims_result.unwrap_err(),
      Error::InconsistentCredentialJwtClaims("inconsistent credential id")
    ));
  }

  #[test]
  fn inconsistent_subject() {
    let claims_json: &str = r#"
    {
      "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "jti": "http://example.edu/credentials/3732",
      "iss": "https://example.edu/issuers/14",
      "nbf":  1262373804,
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "https://example.edu/issuers/14",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": {
          "id": "did:example:1111111111111111111111111",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science in Mechanical Engineering"
          }
        }
      }
    }"#;

    let credential_from_claims_result: Result<Credential, _> =
      CredentialJwtClaims::<'_, Object>::from_json(&claims_json)
        .unwrap()
        .try_into_credential();
    assert!(matches!(
      credential_from_claims_result.unwrap_err(),
      Error::InconsistentCredentialJwtClaims("inconsistent credentialSubject: identifiers do not match")
    ));
  }

  #[test]
  fn inconsistent_issuance_date() {
    // issuer is inconsistent (15 instead of 14).
    let claims_json: &str = r#"
    {
      "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "jti": "http://example.edu/credentials/3732",
      "iss": "https://example.edu/issuers/14",
      "nbf":  1262373804,
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "https://example.edu/issuers/14",
        "issuanceDate": "2020-01-01T19:23:24Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science in Mechanical Engineering"
          }
        }
      }
    }"#;

    let credential_from_claims_result: Result<Credential, _> =
      CredentialJwtClaims::<'_, Object>::from_json(&claims_json)
        .unwrap()
        .try_into_credential();
    assert!(matches!(
      credential_from_claims_result.unwrap_err(),
      Error::InconsistentCredentialJwtClaims("inconsistent issuanceDate")
    ));
  }

  #[test]
  fn inconsistent_expiration_date() {
    // issuer is inconsistent (15 instead of 14).
    let claims_json: &str = r#"
    {
      "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "jti": "http://example.edu/credentials/3732",
      "iss": "https://example.edu/issuers/14",
      "nbf":  1262373804,
      "exp": 1757778983,
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "https://example.edu/issuers/14",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "expirationDate": "2026-09-13T15:56:23Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science in Mechanical Engineering"
          }
        }
      }
    }"#;

    let credential_from_claims_result: Result<Credential, _> =
      CredentialJwtClaims::<'_, Object>::from_json(&claims_json)
        .unwrap()
        .try_into_credential();
    assert!(matches!(
      credential_from_claims_result.unwrap_err(),
      Error::InconsistentCredentialJwtClaims("inconsistent credential expirationDate")
    ));
  }
}
