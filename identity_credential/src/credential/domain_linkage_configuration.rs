// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::credential::Credential;
use crate::error::Result;
use identity_core::common::Context;
use identity_core::common::Url;
use identity_core::convert::FmtJson;
use serde::Deserialize;
use std::fmt::Display;
use std::fmt::Formatter;

use crate::Error::DomainLinkageError;

lazy_static! {
  static ref WELL_KNOWN_CONTEXT: Context =
    Context::Url(Url::parse("https://identity.foundation/.well-known/did-configuration/v1").unwrap());
}

/// DID Configuration Resource which contains Domain Linkage Credentials.
/// It can be placed in an origin's `.well-known` directory to prove linkage between the origin and a DID.
/// See: <https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource>
///
/// Note:
/// - Only [Linked Data Proof Format](https://identity.foundation/.well-known/resources/did-configuration/#linked-data-proof-format)
///   is supported.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "__DomainLinkageConfiguration")]
pub struct DomainLinkageConfiguration(__DomainLinkageConfiguration);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct __DomainLinkageConfiguration {
  /// Fixed context.
  #[serde(rename = "@context")]
  context: Context,
  /// Linked credentials.
  linked_dids: Vec<Credential>,
}

impl __DomainLinkageConfiguration {
  /// Validates the semantic structure.
  fn check_structure(&self) -> Result<()> {
    if &self.context != DomainLinkageConfiguration::well_known_context() {
      return Err(DomainLinkageError("invalid JSON-LD context".into()));
    }
    if self.linked_dids.is_empty() {
      return Err(DomainLinkageError("empty linked_dids list".into()));
    }
    Ok(())
  }
}

impl TryFrom<__DomainLinkageConfiguration> for DomainLinkageConfiguration {
  type Error = &'static str;

  fn try_from(config: __DomainLinkageConfiguration) -> Result<Self, Self::Error> {
    config.check_structure()?;
    Ok(Self(config))
  }
}

impl Display for DomainLinkageConfiguration {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    self.fmt_json(f)
  }
}

impl DomainLinkageConfiguration {
  /// Creates a new DID Configuration Resource.
  pub fn new(linked_dids: Vec<Credential>) -> Self {
    Self(__DomainLinkageConfiguration {
      context: Self::well_known_context().clone(),
      linked_dids,
    })
  }

  pub(crate) fn well_known_context() -> &'static Context {
    &WELL_KNOWN_CONTEXT
  }

  pub(crate) const fn domain_linkage_type() -> &'static str {
    "DomainLinkageCredential"
  }

  /// List of Domain Linkage Credentials.
  pub fn linked_dids(&self) -> &Vec<Credential> {
    &self.0.linked_dids
  }

  /// List of the issuers of the Domain Linkage Credentials.
  pub fn issuers(&self) -> impl Iterator<Item = &Url> {
    self.0.linked_dids.iter().map(|linked_did| linked_did.issuer.url())
  }

  /// List of domain Linkage Credentials.
  pub fn linked_dids_mut(&mut self) -> &mut Vec<Credential> {
    &mut self.0.linked_dids
  }
}

#[cfg(feature = "domain-linkage-fetch")]
mod __fetch_configuration {
  use crate::credential::DomainLinkageConfiguration;
  use crate::error::Result;
  use crate::Error::DomainLinkageError;
  use futures::StreamExt;
  use identity_core::common::Url;
  use identity_core::convert::FromJson;
  use reqwest::redirect::Policy;
  use reqwest::Client;

  impl DomainLinkageConfiguration {
    /// Fetches the the DID Configuration resource via a GET request at the
    /// well-known location: "`domain`/.well-known/did-configuration.json".
    ///
    /// The maximum size of the domain linkage configuration that can be retrieved with this method is 1 MiB.
    /// To download larger ones, use your own HTTP client.
    pub async fn fetch_configuration(mut domain: Url) -> Result<DomainLinkageConfiguration> {
      if domain.scheme() != "https" {
        return Err(DomainLinkageError("domain` does not use `https` protocol".into()));
      }
      domain.set_path(".well-known/did-configuration.json");

      let client: Client = reqwest::ClientBuilder::new()
        .https_only(true)
        .redirect(Policy::none())
        .build()
        .map_err(|err| DomainLinkageError(Box::new(err)))?;

      // We use a stream so we can limit the size of the response to 1 MiB.
      let mut stream = client
        .get(domain.to_string())
        .send()
        .await
        .map_err(|err| DomainLinkageError(Box::new(err)))?
        .bytes_stream();

      let mut json: Vec<u8> = Vec::new();
      while let Some(item) = stream.next().await {
        match item {
          Ok(bytes) => {
            json.extend(bytes);
            if json.len() > 1_048_576 {
              return Err(DomainLinkageError(
                "domain linkage configuration can not exceed 1 MiB".into(),
              ));
            }
          }
          Err(err) => return Err(DomainLinkageError(Box::new(err))),
        }
      }
      let domain_linkage_configuration: DomainLinkageConfiguration =
        DomainLinkageConfiguration::from_json_slice(&json).map_err(|err| DomainLinkageError(Box::new(err)))?;
      Ok(domain_linkage_configuration)
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::credential::domain_linkage_configuration::DomainLinkageConfiguration;
  use identity_core::convert::FromJson;
  use identity_core::error::Result;
  use serde_json::json;
  use serde_json::Value;

  #[test]
  fn test_from_json_valid() {
    const JSON1: &str = include_str!("../../tests/fixtures/dn-config-valid.json");
    DomainLinkageConfiguration::from_json(JSON1).unwrap();
  }

  #[test]
  fn test_from_json_invalid_context() {
    const JSON1: &str = include_str!("../../tests/fixtures/dn-config-invalid-context.json");
    let deserialization_result: Result<DomainLinkageConfiguration> = DomainLinkageConfiguration::from_json(JSON1);
    assert!(deserialization_result.is_err());
  }

  #[test]
  fn test_from_json_extra_property() {
    const JSON1: &str = include_str!("../../tests/fixtures/dn-config-extra-property.json");
    let deserialization_result: Result<DomainLinkageConfiguration> = DomainLinkageConfiguration::from_json(JSON1);
    assert!(deserialization_result.is_err());
  }

  #[test]
  fn test_from_json_empty_linked_did() {
    let json_value: Value = json!({
      "@context": "https://identity.foundation/.well-known/did-configuration/v1",
      "linked_dids": []
    });
    let deserialization_result: Result<DomainLinkageConfiguration> =
      DomainLinkageConfiguration::from_json_value(json_value);
    assert!(deserialization_result.is_err());
  }
}
