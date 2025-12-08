// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_verification::jws::Decoder;
use serde::Deserialize;
use serde::Serialize;

use crate::credential::CredentialV2;
use crate::credential::EnvelopedVc;
use crate::credential::VcDataUrl;

/// A wrapper around a JSON Web Token (JWK).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Jwt(String);

impl Jwt {
  /// Creates a new `Jwt` from the given string.
  pub fn new(jwt_string: String) -> Self {
    Self(jwt_string)
  }

  /// Returns a reference of the JWT string.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl From<String> for Jwt {
  fn from(jwt: String) -> Self {
    Self::new(jwt)
  }
}

impl From<Jwt> for String {
  fn from(jwt: Jwt) -> Self {
    jwt.0
  }
}

impl AsRef<str> for Jwt {
  fn as_ref(&self) -> &str {
    &self.0
  }
}

/// A compact JWT containing within its payload a data model 2.0 Verifiable Credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JwtVcV2(Box<str>);

impl AsRef<str> for JwtVcV2 {
  fn as_ref(&self) -> &str {
    &self.0
  }
}

impl JwtVcV2 {
  /// Returns the string representation of this [JwtVcV2].
  pub const fn as_str(&self) -> &str {
    &self.0
  }

  /// Converts this [JwtVcV2] into an [EnvelopedVc] of media type "application/vc+jwt" to be used within a verifiable
  /// presentation.
  pub fn into_enveloped_vc(self) -> EnvelopedVc {
    let data_url = VcDataUrl::parse(&format!("data:application/vc+jwt,{}", self.as_str())).expect("valid data url");
    EnvelopedVc::new(data_url)
  }

  /// Parses a compact JWT string into a [JwtVcV2].
  pub fn parse(jwt: &str) -> Result<Self, JwtVcV2ParsingError> {
    let decoded_jws = Decoder::new()
      .decode_compact_serialization(jwt.as_bytes(), None)
      .map_err(|e| JwtVcV2ParsingError { source: e.into() })?;

    // Ensure the payload can be deserialized as a CredentialV2.
    let _credential: CredentialV2<Object> =
      serde_json::from_slice(decoded_jws.claims()).map_err(|e| JwtVcV2ParsingError { source: e.into() })?;

    Ok(Self(jwt.to_owned().into_boxed_str()))
  }
}

/// An attempt to parse a [JwtVcV2] failed.
#[derive(Debug, thiserror::Error)]
#[error("failed to parse a JWT-encoded Verifiable Credential v2.0")]
#[non_exhaustive]
pub struct JwtVcV2ParsingError {
  source: Box<dyn std::error::Error + Send + Sync>,
}

impl TryFrom<EnvelopedVc> for JwtVcV2 {
  type Error = JwtVcV2ParsingError;

  fn try_from(enveloped_vc: EnvelopedVc) -> Result<Self, Self::Error> {
    let data_url = &enveloped_vc.id;
    if data_url.media_type() != "application/vc+jwt" {
      return Err(JwtVcV2ParsingError {
        source: format!(
          "invalid media type: `{}`, expected `application/vc+jwt`",
          data_url.media_type()
        )
        .into(),
      });
    }

    let jwt_str = enveloped_vc.id.encoded_data();
    Self::parse(jwt_str)
  }
}
