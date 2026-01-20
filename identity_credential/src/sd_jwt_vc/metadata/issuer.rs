// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Url;
use identity_verification::jwk::JwkSet;
use serde::Deserialize;
use serde::Serialize;

use crate::sd_jwt_vc::Error;
use crate::sd_jwt_vc::SdJwtVc;

/// Path used to query [`IssuerMetadata`] for a given JWT VC issuer.
pub const WELL_KNOWN_VC_ISSUER: &str = "/.well-known/jwt-vc-issuer";

/// SD-JWT VC issuer's metadata. Contains information about one issuer's
/// public keys, either as an embedded JWK Set or a reference to one.
/// ## Notes
/// - [`IssuerMetadata::issuer`] must exactly match [`SdJwtVcClaims::iss`](crate::sd_jwt_vc::SdJwtVcClaims::iss) in
///   order to be considered valid.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct IssuerMetadata {
  /// Issuer URI.
  pub issuer: Url,
  /// JWK Set containing the issuer's public keys.
  #[serde(flatten)]
  pub jwks: Jwks,
}

impl IssuerMetadata {
  /// Checks the validity of this [`IssuerMetadata`].
  /// [`IssuerMetadata::issuer`] must match `sd_jwt_vc`'s iss claim's value.
  pub fn validate(&self, sd_jwt_vc: &SdJwtVc) -> Result<(), Error> {
    let expected_issuer = sd_jwt_vc.claims().iss.as_ref().ok_or_else(|| {
      Error::InvalidIssuerMetadata(anyhow::anyhow!(
        "SD-JWT VC is missing 'iss' claim required for issuer metadata validation"
      ))
    })?;
    let actual_issuer = &self.issuer;
    if actual_issuer != expected_issuer {
      Err(Error::InvalidIssuerMetadata(anyhow::anyhow!(
        "expected issuer \"{expected_issuer}\", but found \"{actual_issuer}\""
      )))
    } else {
      Ok(())
    }
  }
}

/// JWK Set containing the issuer's public keys or a URL string referencing them.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub enum Jwks {
  /// Reference to a JWK set.
  #[serde(rename = "jwks_uri")]
  Uri(Url),
  /// An embedded JWK set.
  #[serde(rename = "jwks")]
  Object(JwkSet),
}

#[cfg(test)]
mod tests {
  use super::*;

  const EXAMPLE_URI_ISSUER_METADATA: &str = r#"
{
  "issuer":"https://example.com",
  "jwks_uri":"https://jwt-vc-issuer.example.org/my_public_keys.jwks"
}
  "#;
  const EXAMPLE_JWKS_ISSUER_METADATA: &str = r#"
{
  "issuer":"https://example.com",
  "jwks":{
    "keys":[
      {
        "kid":"doc-signer-05-25-2022",
        "e":"AQAB",
        "n":"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyklBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70pRM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKveqXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
        "kty":"RSA"
      }
    ]
  }
}
  "#;

  #[test]
  fn deserializing_uri_metadata_works() {
    let issuer_metadata: IssuerMetadata = serde_json::from_str(EXAMPLE_URI_ISSUER_METADATA).unwrap();
    assert!(matches!(issuer_metadata.jwks, Jwks::Uri(_)));
  }

  #[test]
  fn deserializing_jwks_metadata_works() {
    let issuer_metadata: IssuerMetadata = serde_json::from_str(EXAMPLE_JWKS_ISSUER_METADATA).unwrap();
    assert!(matches!(issuer_metadata.jwks, Jwks::Object { .. }));
  }
}
