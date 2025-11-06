// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::credential::credential_v2::Credential as CredentialV2;
use crate::credential::Credential;
use crate::credential::Issuer;
use crate::credential::Subject;
use crate::domain_linkage::DomainLinkageConfiguration;
use crate::error::Result;
use crate::Error;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_did::CoreDID;
use identity_did::DID;

use crate::utils::url_only_includes_origin;

/// Convenient builder to create a spec compliant Domain Linkage Credential.
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

  /// Sets the value of the `issuer`.
  ///
  /// The issuer will also be set as `credentialSubject.id`.
  #[must_use]
  pub fn issuer(mut self, did: CoreDID) -> Self {
    self.issuer = Some(did.into_url().into());
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
  ///
  /// Must be a domain origin.
  #[must_use]
  pub fn origin(mut self, value: Url) -> Self {
    self.origin = Some(value);
    self
  }

  /// Returns a new `Credential` based on the `DomainLinkageCredentialBuilder` configuration.
  pub fn build(self) -> Result<Credential<Object>> {
    let origin: Url = self.origin.ok_or(Error::MissingOrigin)?;
    if origin.domain().is_none() {
      return Err(Error::DomainLinkageError(
        "origin must be a domain with http(s) scheme".into(),
      ));
    }
    if !url_only_includes_origin(&origin) {
      return Err(Error::DomainLinkageError(
        "origin must not contain any path, query or fragment".into(),
      ));
    }

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

  /// Returns a new VC Data Model 2.0 `Credential` based on the `DomainLinkageCredentialBuilder` configuration.
  pub fn build_v2(self) -> Result<CredentialV2<Object>> {
    let origin: Url = self.origin.ok_or(Error::MissingOrigin)?;
    if origin.domain().is_none() {
      return Err(Error::DomainLinkageError(
        "origin must be a domain with http(s) scheme".into(),
      ));
    }
    if !url_only_includes_origin(&origin) {
      return Err(Error::DomainLinkageError(
        "origin must not contain any path, query or fragment".into(),
      ));
    }

    let mut properties: Object = Object::new();
    properties.insert("origin".into(), origin.into_string().into());
    let issuer: Url = self.issuer.ok_or(Error::MissingIssuer)?;

    Ok(CredentialV2 {
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
      valid_from: self.issuance_date.unwrap_or_else(Timestamp::now_utc),
      valid_until: Some(self.expiration_date.ok_or(Error::MissingExpirationDate)?),
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
  use crate::credential::Credential;
  use crate::domain_linkage::DomainLinkageCredentialBuilder;
  use crate::error::Result;
  use crate::Error;
  use identity_core::common::Timestamp;
  use identity_core::common::Url;
  use identity_did::CoreDID;

  #[test]
  fn test_builder_with_all_fields_set_succeeds() {
    let issuer: CoreDID = "did:example:issuer".parse().unwrap();
    assert!(DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .expiration_date(Timestamp::now_utc())
      .issuer(issuer)
      .origin(Url::parse("http://www.example.com").unwrap())
      .build()
      .is_ok());
  }

  #[test]
  fn test_builder_origin_is_not_a_domain() {
    let issuer: CoreDID = "did:example:issuer".parse().unwrap();
    let err: Error = DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .expiration_date(Timestamp::now_utc())
      .issuer(issuer)
      .origin(Url::parse("did:example:origin").unwrap())
      .build()
      .unwrap_err();
    assert!(matches!(err, Error::DomainLinkageError(_)));
  }
  #[test]
  fn test_builder_origin_is_a_url() {
    let urls = [
      "https://example.com/foo?bar=420#baz",
      "https://example.com/?bar=420",
      "https://example.com/#baz",
      "https://example.com/?bar=420#baz",
    ];
    let issuer: CoreDID = "did:example:issuer".parse().unwrap();
    for url in urls {
      let err: Error = DomainLinkageCredentialBuilder::new()
        .issuance_date(Timestamp::now_utc())
        .expiration_date(Timestamp::now_utc())
        .issuer(issuer.clone())
        .origin(Url::parse(url).unwrap())
        .build()
        .unwrap_err();
      assert!(matches!(err, Error::DomainLinkageError(_)));
    }
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
    let issuer: CoreDID = "did:example:issuer".parse().unwrap();
    let credential: Result<Credential> = DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .expiration_date(Timestamp::now_utc())
      .issuer(issuer)
      .build();

    assert!(matches!(credential, Err(Error::MissingOrigin)));
  }

  #[test]
  fn test_builder_no_expiration_date() {
    let issuer: CoreDID = "did:example:issuer".parse().unwrap();
    let credential: Result<Credential> = DomainLinkageCredentialBuilder::new()
      .issuance_date(Timestamp::now_utc())
      .issuer(issuer)
      .origin(Url::parse("http://www.example.com").unwrap())
      .build();

    assert!(matches!(credential, Err(Error::MissingExpirationDate)));
  }
}
