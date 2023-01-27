// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::credential::Credential;
use crate::credential::DomainLinkageConfiguration;
use crate::credential::Issuer;
use crate::credential::Subject;
use crate::error::Result;
use crate::Error;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;

/// Convenient builder to create a spec compliant Linked Data Domain Linkage Credential.
///
/// See: <https://identity.foundation/.well-known/resources/did-configuration/#linked-data-proof-format>
///
/// The builder expects `issuer`, `expirationDate` and `origin` to be set.
/// Setting `issuanceDate` is optional. If unset the current time will be used.
#[derive(Debug, Default)]
pub struct DomainLinkageCredentialBuilder {
  pub(crate) issuer: Option<Url>,
  pub(crate) issuance_date: Option<Timestamp>,
  pub(crate) expiration_date: Option<Timestamp>,
  pub(crate) origin: Option<Url>,
}

impl DomainLinkageCredentialBuilder {
  /// Creates a new `DomainLinkageCredentialBuilder`.
  pub fn new() -> Self {
    Self::default()
  }

  /// Sets the value of the `issuer`, only the URL is used, other properties are ignored.
  ///
  /// The issuer will also be set as the `credentialSubject`.
  #[must_use]
  pub fn issuer(mut self, value: Issuer) -> Self {
    let issuer: Url = match value {
      Issuer::Url(url) => url,
      Issuer::Obj(data) => data.id,
    };
    self.issuer = Some(issuer);
    self
  }

  /// Sets the value of the `Credential` `issuanceDate`.
  #[must_use]
  pub fn issuance_date(mut self, value: Timestamp) -> Self {
    self.issuance_date = Some(value);
    self
  }

  /// Sets the value of the `Credential` `expirationDate`.
  #[must_use]
  pub fn expiration_date(mut self, value: Timestamp) -> Self {
    self.expiration_date = Some(value);
    self
  }

  /// Sets the origin in `credentialSubject`.
  #[must_use]
  pub fn origin(mut self, value: Url) -> Self {
    self.origin = Some(value);
    self
  }

  /// Returns a new `Credential` based on the `DomainLinkageCredentialBuilder` configuration.
  pub fn build(self) -> Result<Credential<Object>> {
    let origin: Url = self.origin.ok_or(Error::MissingOrigin)?;
    let mut properties: Object = Object::new();
    properties.insert("origin".into(), origin.into_string().into());
    let issuer: Url = self.issuer.ok_or(Error::MissingIssuer)?;

    Ok(Credential {
      context: OneOrMany::Many(vec![
        Credential::<Object>::base_context().clone(),
        DomainLinkageConfiguration::well_known_context().clone(),
      ]),
      id: None,
      types: OneOrMany::Many(vec![
        Credential::<Object>::base_type().to_owned(),
        DomainLinkageConfiguration::domain_linkage_type().to_owned(),
      ]),
      credential_subject: OneOrMany::One(Subject::with_id_and_properties(issuer.clone(), properties)),
      issuer: Issuer::Url(issuer),
      issuance_date: self.issuance_date.unwrap_or_else(Timestamp::now_utc),
      expiration_date: Some(self.expiration_date.ok_or(Error::MissingExpirationDate)?),
      credential_status: None,
      credential_schema: Vec::new().into(),
      refresh_service: Vec::new().into(),
      terms_of_use: Vec::new().into(),
      evidence: Vec::new().into(),
      non_transferable: None,
      properties: Object::new(),
      proof: None,
    })
  }
}

#[cfg(test)]
mod tests {
  use crate::credential::domain_linkage_credential_builder::DomainLinkageCredentialBuilder;
  use crate::credential::Credential;
  use crate::credential::Issuer;
  use crate::error::Result;
  use crate::Error;
  use identity_core::common::Timestamp;
  use identity_core::common::Url;

  #[test]
  fn test_builder_with_all_fields_set_succeeds() {
    let issuer = Issuer::Url(Url::parse("did:example:issuer").unwrap());
    let _credential: Credential = DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .expiration_date(Timestamp::now_utc())
      .issuer(issuer)
      .origin(Url::parse("http://www.example.com").unwrap())
      .build()
      .unwrap();
  }

  #[test]
  fn test_builder_no_issuer() {
    let credential: Result<Credential> = DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .expiration_date(Timestamp::now_utc())
      .origin(Url::parse("http://www.example.com").unwrap())
      .build();

    assert!(matches!(credential, Err(Error::MissingIssuer)));
  }

  #[test]
  fn test_builder_no_origin() {
    let issuer = Issuer::Url(Url::parse("did:example:issuer").unwrap());
    let credential: Result<Credential> = DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .expiration_date(Timestamp::now_utc())
      .issuer(issuer)
      .build();

    assert!(matches!(credential, Err(Error::MissingOrigin)));
  }

  #[test]
  fn test_builder_no_expiration_date() {
    let issuer = Issuer::Url(Url::parse("did:example:issuer").unwrap());
    let credential: Result<Credential> = DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .issuer(issuer)
      .origin(Url::parse("http://www.example.com").unwrap())
      .build();

    assert!(matches!(credential, Err(Error::MissingExpirationDate)));
  }
}
