// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_verification::jwk::JwkSet;
use sd_jwt::Sha256Hasher;
use serde_json::json;

use crate::sd_jwt_vc::metadata::IssuerMetadata;
use crate::sd_jwt_vc::metadata::Jwks;
use crate::sd_jwt_vc::metadata::TypeMetadata;
use crate::sd_jwt_vc::tests::TestJwsVerifier;
use crate::sd_jwt_vc::Error;
use crate::sd_jwt_vc::SdJwtVcBuilder;

use super::TestResolver;
use super::TestSigner;

fn issuer_metadata() -> IssuerMetadata {
  let mut jwk_set = JwkSet::new();
  jwk_set.add(super::signer_secret_jwk());

  IssuerMetadata {
    issuer: "https://example.com".parse().unwrap(),
    jwks: Jwks::Object(jwk_set),
  }
}

fn test_resolver() -> TestResolver {
  let mut test_resolver = TestResolver::new();
  test_resolver.insert_resource("https://example.com/.well-known/jwt-vc-issuer/", issuer_metadata());
  test_resolver.insert_resource("https://example.com/education_credential", vc_metadata());

  test_resolver
}

#[tokio::test]
async fn validation_of_valid_token_works() -> anyhow::Result<()> {
  let sd_jwt_credential = SdJwtVcBuilder::new(json!({
    "name": "John Doe",
    "address": {
      "street_address": "A random street",
      "number": "3a"
    },
    "degree": []
  }))?
  .header("kid", "key1")
  .vct("https://example.com/education_credential".parse::<Url>()?)
  .iat(Timestamp::now_utc())
  .iss("https://example.com".parse()?)
  .make_concealable("/address/street_address")?
  .make_concealable("/address")?
  .finish(&TestSigner, "HS256")
  .await?;

  let resolver = test_resolver();
  sd_jwt_credential
    .validate(&resolver, &TestJwsVerifier, &Sha256Hasher::new())
    .await?;
  Ok(())
}

#[tokio::test]
async fn validation_of_invalid_token_fails() -> anyhow::Result<()> {
  let sd_jwt_credential = SdJwtVcBuilder::new(json!({
    "name": "John Doe",
    "address": {
      "street_address": "A random street",
      "number": "3a"
    },
    "degree": []
  }))?
  .header("kid", "invalid_key")
  .vct("https://example.com/education_credential".parse::<Url>()?)
  .iat(Timestamp::now_utc())
  .iss("https://example.com".parse()?)
  .make_concealable("/address/street_address")?
  .make_concealable("/address")?
  .finish(&TestSigner, "HS256")
  .await?;

  let resolver = test_resolver();
  let error = sd_jwt_credential
    .validate(&resolver, &TestJwsVerifier, &Sha256Hasher::new())
    .await
    .unwrap_err();
  assert!(matches!(error, Error::Verification(_)));

  Ok(())
}

fn vc_metadata() -> TypeMetadata {
  serde_json::from_str(
    r#"{
  "vct": "https://example.com/education_credential",
  "name": "Betelgeuse Education Credential - Preliminary Version",
  "description": "This is our development version of the education credential. Don't panic.",
  "claims": [
    {
      "path": ["name"],
      "display": [
        {
          "lang": "de-DE",
          "label": "Vor- und Nachname",
          "description": "Der Name des Studenten"
        },
        {
          "lang": "en-US",
          "label": "Name",
          "description": "The name of the student"
        }
      ],
      "sd": "allowed"
    },
    {
      "path": ["address"],
      "display": [
        {
          "lang": "de-DE",
          "label": "Adresse",
          "description": "Adresse zum Zeitpunkt des Abschlusses"
        },
        {
          "lang": "en-US",
          "label": "Address",
          "description": "Address at the time of graduation"
        }
      ],
      "sd": "always"
    },
    {
      "path": ["address", "street_address"],
      "display": [
        {
          "lang": "de-DE",
          "label": "Straße"
        },
        {
          "lang": "en-US",
          "label": "Street Address"
        }
      ],
      "sd": "always",
      "svg_id": "address_street_address"
    },
    {
      "path": ["degrees", null],
      "display": [
        {
          "lang": "de-DE",
          "label": "Abschluss",
          "description": "Der Abschluss des Studenten"
        },
        {
          "lang": "en-US",
          "label": "Degree",
          "description": "Degree earned by the student"
        }
      ],
      "sd": "allowed"
    }
  ],
  "schema_url": "https://example.com/credential-schema",
  "schema_url#integrity": "sha256-o984vn819a48ui1llkwPmKjZ5t0WRL5ca_xGgX3c1VLmXfh"
}"#,
  )
  .unwrap()
}
