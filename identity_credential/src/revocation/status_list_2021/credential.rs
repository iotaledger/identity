// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

use identity_core::common::Context;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

/// The type of a `StatusList2021Credential`.
pub const CREDENTIAL_TYPE: &str = "StatusList2021Credential";
const CREDENTIAL_SUBJECT_TYPE: &str = "StatusList2021";

/// [Error](std::error::Error) type that represents the possible errors that can be
/// encountered when dealing with [`StatusList2021Credential`]s.
#[derive(Clone, Debug, Error, strum::IntoStaticStr, PartialEq, Eq)]
pub enum StatusList2021CredentialError {
  /// The provided [`Credential`] has more than one `credentialSubject`.
  #[error("A StatusList2021Credential may only have one credentialSubject")]
  MultipleCredentialSubject,
  /// The provided [`Credential`] has an invalid property.
  #[error("Invalid property \"{0}\"")]
  InvalidProperty(&'static str),
  /// The provided [`Credential`] doesn't have a mandatory property.
  #[error("Missing property \"{0}\"")]
  MissingProperty(&'static str),
  /// Inner status list failures.
  #[error(transparent)]
  StatusListError(#[from] StatusListError),
  /// Missing status list id.
  #[error("Cannot set the status of a credential without a \"credentialSubject.id\".")]
  Unreferenceable,
  /// Credentials cannot be unrevoked.
  #[error("A previously revoked credential cannot be unrevoked.")]
  UnreversibleRevocation,
}

use crate::credential::Credential;
use crate::credential::CredentialBuilder;
use crate::credential::Issuer;
use crate::credential::Proof;
use crate::credential::Subject;

use super::status_list::StatusListError;
use super::StatusList2021;
use super::StatusList2021Entry;

/// A parsed [StatusList2021Credential](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021credential).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Credential", into = "Credential")]
pub struct StatusList2021Credential {
  inner: Credential,
  subject: StatusList2021CredentialSubject,
}

impl Display for StatusList2021Credential {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", &self.inner)
  }
}

impl From<StatusList2021Credential> for Credential {
  fn from(value: StatusList2021Credential) -> Self {
    value.into_inner()
  }
}

impl Deref for StatusList2021Credential {
  type Target = Credential;
  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl TryFrom<Credential> for StatusList2021Credential {
  type Error = StatusList2021CredentialError;
  fn try_from(mut credential: Credential) -> Result<Self, Self::Error> {
    let has_right_credential_type = credential.types.contains(&CREDENTIAL_TYPE.to_owned());
    let subject = StatusList2021CredentialSubject::try_from_credential(&mut credential)?;

    if has_right_credential_type {
      Ok(Self {
        inner: credential,
        subject,
      })
    } else {
      Err(StatusList2021CredentialError::InvalidProperty("type"))
    }
  }
}

impl StatusList2021Credential {
  /// Returns the inner "raw" [`Credential`].
  pub fn into_inner(self) -> Credential {
    let Self { mut inner, subject } = self;
    inner.credential_subject = OneOrMany::One(subject.into());
    inner
  }

  /// Returns the id of this credential.
  pub fn id(&self) -> Option<&Url> {
    self.subject.id.as_ref()
  }

  /// Returns the purpose of this status list.
  pub fn purpose(&self) -> StatusPurpose {
    self.subject.status_purpose
  }

  fn status_list(&self) -> Result<StatusList2021, StatusListError> {
    StatusList2021::try_from_encoded_str(&self.subject.encoded_list)
  }

  /// Sets the credential status of a given [`Credential`],
  /// mapping it to the `index`-th entry of this [`StatusList2021Credential`].
  ///
  /// ## Note:
  /// - A revoked credential cannot ever be unrevoked and will lead to a
  ///   [`StatusList2021CredentialError::UnreversibleRevocation`].
  /// - Trying to set `revoked_or_suspended` to `false` for an already valid credential will have no impact.
  pub fn set_credential_status(
    &mut self,
    credential: &mut Credential,
    index: usize,
    revoked_or_suspended: bool,
  ) -> Result<StatusList2021Entry, StatusList2021CredentialError> {
    let id = self
      .id()
      .cloned()
      .ok_or(StatusList2021CredentialError::Unreferenceable)?;
    let entry = StatusList2021Entry::new(id, self.purpose(), index, None);

    self.set_entry(index, revoked_or_suspended)?;
    credential.credential_status = Some(entry.clone().into());

    Ok(entry)
  }

  /// Apply `update_fn` to the status list encoded in this credential.
  pub fn update<F>(&mut self, update_fn: F) -> Result<(), StatusList2021CredentialError>
  where
    F: FnOnce(&mut MutStatusList) -> Result<(), StatusList2021CredentialError>,
  {
    let mut encapsuled_status_list = MutStatusList {
      status_list: self.status_list()?,
      purpose: self.purpose(),
    };
    update_fn(&mut encapsuled_status_list)?;

    self.subject.encoded_list = encapsuled_status_list.status_list.into_encoded_str();
    Ok(())
  }

  /// Sets the `index`-th entry to `value`
  pub(crate) fn set_entry(&mut self, index: usize, value: bool) -> Result<(), StatusList2021CredentialError> {
    let mut status_list = self.status_list()?;
    let entry_status = status_list.get(index)?;
    if self.purpose() == StatusPurpose::Revocation && !value && entry_status {
      return Err(StatusList2021CredentialError::UnreversibleRevocation);
    }
    status_list.set(index, value)?;
    self.subject.encoded_list = status_list.into_encoded_str();

    Ok(())
  }

  /// Returns the status of the `index-th` entry.
  pub fn entry(&self, index: usize) -> Result<CredentialStatus, StatusList2021CredentialError> {
    let status_list = self.status_list()?;
    Ok(match (self.purpose(), status_list.get(index)?) {
      (StatusPurpose::Revocation, true) => CredentialStatus::Revoked,
      (StatusPurpose::Suspension, true) => CredentialStatus::Suspended,
      _ => CredentialStatus::Valid,
    })
  }
}

/// A wrapper over the [`StatusList2021`] contained in a [`StatusList2021Credential`]
/// that allows for its mutation.
pub struct MutStatusList {
  status_list: StatusList2021,
  purpose: StatusPurpose,
}

impl MutStatusList {
  /// Sets the value of the `index`-th entry in the status list.
  pub fn set_entry(&mut self, index: usize, value: bool) -> Result<(), StatusList2021CredentialError> {
    let entry_status = self.status_list.get(index)?;
    if self.purpose == StatusPurpose::Revocation && !value && entry_status {
      return Err(StatusList2021CredentialError::UnreversibleRevocation);
    }
    self.status_list.set(index, value)?;
    Ok(())
  }
}

/// The status of a credential referenced inside a [`StatusList2021Credential`]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialStatus {
  /// A revoked credential
  Revoked,
  /// A suspended credential
  Suspended,
  /// A valid credential
  Valid,
}

/// [`StatusList2021Credential`]'s purpose.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusPurpose {
  /// Used for revocation.
  #[default]
  Revocation,
  /// Used for suspension.
  Suspension,
}

impl Display for StatusPurpose {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let s = match self {
      Self::Revocation => "revocation",
      Self::Suspension => "suspension",
    };
    write!(f, "{s}")
  }
}

impl FromStr for StatusPurpose {
  type Err = ();
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "revocation" => Ok(Self::Revocation),
      "suspension" => Ok(Self::Suspension),
      _ => Err(()),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct StatusList2021CredentialSubject {
  status_purpose: StatusPurpose,
  encoded_list: String,
  id: Option<Url>,
}

impl From<StatusList2021CredentialSubject> for Subject {
  fn from(value: StatusList2021CredentialSubject) -> Self {
    let properties = [
      (
        "statusPurpose".to_owned(),
        Value::String(value.status_purpose.to_string()),
      ),
      ("type".to_owned(), Value::String(CREDENTIAL_SUBJECT_TYPE.to_owned())),
      ("encodedList".to_owned(), Value::String(value.encoded_list)),
    ]
    .into_iter()
    .collect();

    if let Some(id) = value.id {
      Subject::with_id_and_properties(id, properties)
    } else {
      Subject::with_properties(properties)
    }
  }
}

impl StatusList2021CredentialSubject {
  /// Parse a StatusListCredentialSubject out of a credential, without copying.
  fn try_from_credential(credential: &mut Credential) -> Result<Self, StatusList2021CredentialError> {
    let OneOrMany::One(mut subject) = std::mem::take(&mut credential.credential_subject) else {
      return Err(StatusList2021CredentialError::MultipleCredentialSubject);
    };
    if let Some(subject_type) = subject.properties.get("type") {
      if subject_type.as_str() != Some(CREDENTIAL_SUBJECT_TYPE) {
        return Err(StatusList2021CredentialError::InvalidProperty("credentialSubject.type"));
      }
    } else {
      return Err(StatusList2021CredentialError::MissingProperty("credentialSubject.type"));
    }
    let status_purpose = subject
      .properties
      .get("statusPurpose")
      .ok_or(StatusList2021CredentialError::MissingProperty(
        "credentialSubject.statusPurpose",
      ))
      .and_then(|value| {
        value
          .as_str()
          .and_then(|purpose| StatusPurpose::from_str(purpose).ok())
          .ok_or(StatusList2021CredentialError::InvalidProperty(
            "credentialSubject.statusPurpose",
          ))
      })?;
    let encoded_list = subject
      .properties
      .get_mut("encodedList")
      .ok_or(StatusList2021CredentialError::MissingProperty(
        "credentialSubject.encodedList",
      ))
      .and_then(|value| {
        if let Value::String(ref mut s) = value {
          Ok(s)
        } else {
          Err(StatusList2021CredentialError::InvalidProperty(
            "credentialSubject.encodedList",
          ))
        }
      })
      .map(std::mem::take)?;

    Ok(StatusList2021CredentialSubject {
      id: subject.id,
      encoded_list,
      status_purpose,
    })
  }
}

/// Builder type for [`StatusList2021Credential`].
#[derive(Debug, Default)]
pub struct StatusList2021CredentialBuilder {
  inner_builder: CredentialBuilder,
  credential_subject: StatusList2021CredentialSubject,
}

impl StatusList2021CredentialBuilder {
  /// Creates a new [`StatusList2021CredentialBuilder`] from a [`StatusList2021`].
  pub fn new(status_list: StatusList2021) -> Self {
    let credential_subject = StatusList2021CredentialSubject {
      encoded_list: status_list.into_encoded_str(),
      ..Default::default()
    };
    Self {
      credential_subject,
      ..Default::default()
    }
  }

  /// Sets `credentialSubject.statusPurpose`.
  pub const fn purpose(mut self, purpose: StatusPurpose) -> Self {
    self.credential_subject.status_purpose = purpose;
    self
  }

  /// Sets `credentialSubject.id`.
  pub fn subject_id(mut self, id: Url) -> Self {
    self.credential_subject.id = Some(id);
    self
  }

  /// Sets `expirationDate`.
  pub const fn expiration_date(mut self, time: Timestamp) -> Self {
    self.inner_builder.expiration_date = Some(time);
    self
  }

  /// Sets `issuer`.
  pub fn issuer(mut self, issuer: Issuer) -> Self {
    self.inner_builder.issuer = Some(issuer);
    self
  }

  /// Adds a `@context` entry.
  pub fn context(mut self, ctx: Context) -> Self {
    self.inner_builder.context.push(ctx);
    self
  }

  /// Adds a `type` entry.
  pub fn add_type(mut self, type_: String) -> Self {
    self.inner_builder.types.push(type_);
    self
  }

  /// Adds a credential proof.
  pub fn proof(mut self, proof: Proof) -> Self {
    self.inner_builder.proof = Some(proof);
    self
  }

  /// Consumes this [`StatusList2021CredentialBuilder`] into a [`StatusList2021Credential`].
  pub fn build(mut self) -> Result<StatusList2021Credential, crate::Error> {
    let id = self.credential_subject.id.clone().map(|mut url| {
      url.set_fragment(None);
      url
    });
    self.inner_builder.id = id;
    self
      .inner_builder
      .type_(CREDENTIAL_TYPE)
      .issuance_date(Timestamp::now_utc())
      .subject(Subject {
        id: self.credential_subject.id.clone(),
        ..Default::default()
      })
      .build()
      .map(|mut credential| {
        credential.credential_subject = OneOrMany::default();
        StatusList2021Credential {
          subject: self.credential_subject,
          inner: credential,
        }
      })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const STATUS_LIST_2021_CREDENTIAL_SAMPLE: &str = r#"
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "id": "https://example.com/credentials/status/3",
  "type": ["VerifiableCredential", "StatusList2021Credential"],
  "issuer": "did:example:12345",
  "issuanceDate": "2021-04-05T14:27:40Z",
  "credentialSubject": {
    "id": "https://example.com/status/3#list",
    "type": "StatusList2021",
    "statusPurpose": "revocation",
    "encodedList": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
  }
}
  "#;

  #[test]
  fn status_purpose_serialization_works() {
    assert_eq!(
      serde_json::to_string(&StatusPurpose::Revocation).ok(),
      Some(format!("\"{}\"", StatusPurpose::Revocation))
    );
  }
  #[test]
  fn status_purpose_deserialization_works() {
    assert_eq!(
      serde_json::from_str::<StatusPurpose>("\"suspension\"").ok(),
      Some(StatusPurpose::Suspension),
    )
  }
  #[test]
  fn status_list_2021_credential_deserialization_works() {
    let credential = serde_json::from_str::<StatusList2021Credential>(STATUS_LIST_2021_CREDENTIAL_SAMPLE)
      .expect("Failed to deserialize");
    assert_eq!(credential.purpose(), StatusPurpose::Revocation);
  }
  #[test]
  fn revoked_credential_cannot_be_unrevoked() {
    let url = Url::parse("http://example.com").unwrap();
    let mut status_list_credential = StatusList2021CredentialBuilder::new(StatusList2021::default())
      .issuer(Issuer::Url(url.clone()))
      .purpose(StatusPurpose::Revocation)
      .subject_id(url)
      .build()
      .unwrap();

    assert!(status_list_credential.set_entry(420, false).is_ok());
    status_list_credential.set_entry(420, true).unwrap();
    assert_eq!(
      status_list_credential.set_entry(420, false),
      Err(StatusList2021CredentialError::UnreversibleRevocation)
    );
  }
  #[test]
  fn suspended_credential_can_be_unsuspended() {
    let url = Url::parse("http://example.com").unwrap();
    let mut status_list_credential = StatusList2021CredentialBuilder::new(StatusList2021::default())
      .issuer(Issuer::Url(url.clone()))
      .purpose(StatusPurpose::Suspension)
      .subject_id(url)
      .build()
      .unwrap();

    assert!(status_list_credential.set_entry(420, false).is_ok());
    status_list_credential.set_entry(420, true).unwrap();
    assert!(status_list_credential.set_entry(420, false).is_ok());
  }
}
