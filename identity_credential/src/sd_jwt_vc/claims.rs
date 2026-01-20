// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::ops::DerefMut;

use identity_core::common::StringOrUrl;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use sd_jwt::Disclosure;
use sd_jwt::SdJwtClaims;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use super::Error;
use super::Result;
use super::Status;

/// JOSE payload claims for SD-JWT VC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SdJwtVcClaims {
  /// Issuer. Explicitly indicated the issuer of the verifiable credential when not conveyed by other means.
  pub iss: Option<Url>,
  /// Not before.
  /// See [RFC7519 section 4.1.5](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5) for more information.
  pub nbf: Option<Timestamp>,
  /// Expiration.
  /// See [RFC7519 section 4.1.4](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4) for more information.
  pub exp: Option<Timestamp>,
  /// Verifiable credential type.
  /// See [SD-JWT VC specification](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.html#name-verifiable-credential-type-)
  /// for more information.
  pub vct: String,
  /// Token's status.
  /// See [OAuth status list specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-02)
  /// for more information.
  pub status: Option<Status>,
  /// Issued at.
  /// See [RFC7519 section 4.1.6](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6) for more information.
  pub iat: Option<Timestamp>,
  /// Subject.
  /// See [RFC7519 section 4.1.2](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2) for more information.
  pub sub: Option<StringOrUrl>,
  #[serde(flatten)]
  pub(crate) sd_jwt_claims: SdJwtClaims,
}

impl Deref for SdJwtVcClaims {
  type Target = SdJwtClaims;
  fn deref(&self) -> &Self::Target {
    &self.sd_jwt_claims
  }
}

impl DerefMut for SdJwtVcClaims {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.sd_jwt_claims
  }
}

impl SdJwtVcClaims {
  pub(crate) fn try_from_sd_jwt_claims(mut claims: SdJwtClaims, disclosures: &[Disclosure]) -> Result<Self> {
    let check_disclosed = |claim_name: &'static str| {
      disclosures
        .iter()
        .any(|disclosure| disclosure.claim_name.as_deref() == Some(claim_name))
        .then_some(Error::DisclosedClaim(claim_name))
    };
    let iss = claims
      .remove("iss")
      .map(|value| {
        value
          .as_str()
          .and_then(|s| Url::parse(s).ok())
          .ok_or_else(|| Error::InvalidClaimValue {
            name: "iss",
            expected: "URL",
            found: value,
          })
      })
      .transpose()?;
    let nbf = {
      if let Some(value) = claims.remove("nbf") {
        value
          .as_number()
          .and_then(|t| t.as_i64())
          .and_then(|t| Timestamp::from_unix(t).ok())
          .ok_or_else(|| Error::InvalidClaimValue {
            name: "nbf",
            expected: "unix timestamp",
            found: value,
          })
          .map(Some)?
      } else {
        if let Some(err) = check_disclosed("nbf") {
          return Err(err);
        }
        None
      }
    };
    let exp = {
      if let Some(value) = claims.remove("exp") {
        value
          .as_number()
          .and_then(|t| t.as_i64())
          .and_then(|t| Timestamp::from_unix(t).ok())
          .ok_or_else(|| Error::InvalidClaimValue {
            name: "exp",
            expected: "unix timestamp",
            found: value,
          })
          .map(Some)?
      } else {
        if let Some(err) = check_disclosed("exp") {
          return Err(err);
        }
        None
      }
    };
    let vct = claims
      .remove("vct")
      .ok_or(Error::MissingClaim("vct"))
      .map_err(|e| check_disclosed("vct").unwrap_or(e))
      .and_then(|value| {
        value
          .as_str()
          .map(ToOwned::to_owned)
          .ok_or_else(|| Error::InvalidClaimValue {
            name: "vct",
            expected: "String",
            found: value,
          })
      })?;
    let status = {
      if let Some(value) = claims.remove("status") {
        serde_json::from_value::<Status>(value.clone())
          .map_err(|_| Error::InvalidClaimValue {
            name: "status",
            expected: "credential's status object",
            found: value,
          })
          .map(Some)?
      } else {
        if let Some(err) = check_disclosed("status") {
          return Err(err);
        }
        None
      }
    };
    let sub = claims
      .remove("sub")
      .map(|value| {
        value
          .as_str()
          .and_then(|s| StringOrUrl::parse(s).ok())
          .ok_or_else(|| Error::InvalidClaimValue {
            name: "sub",
            expected: "String or URL",
            found: value,
          })
      })
      .transpose()?;
    let iat = claims
      .remove("iat")
      .map(|value| {
        value
          .as_number()
          .and_then(|t| t.as_i64())
          .and_then(|t| Timestamp::from_unix(t).ok())
          .ok_or_else(|| Error::InvalidClaimValue {
            name: "iat",
            expected: "unix timestamp",
            found: value,
          })
      })
      .transpose()?;

    Ok(Self {
      iss,
      nbf,
      exp,
      vct,
      status,
      iat,
      sub,
      sd_jwt_claims: claims,
    })
  }
}

impl From<SdJwtVcClaims> for SdJwtClaims {
  fn from(claims: SdJwtVcClaims) -> Self {
    let SdJwtVcClaims {
      iss,
      nbf,
      exp,
      vct,
      status,
      iat,
      sub,
      mut sd_jwt_claims,
    } = claims;

    iss.and_then(|iss| sd_jwt_claims.insert("iss".to_string(), Value::String(iss.to_string())));
    nbf.and_then(|t| sd_jwt_claims.insert("nbf".to_string(), Value::Number(t.to_unix().into())));
    exp.and_then(|t| sd_jwt_claims.insert("exp".to_string(), Value::Number(t.to_unix().into())));
    sd_jwt_claims.insert("vct".to_string(), Value::String(vct));
    status.and_then(|status| sd_jwt_claims.insert("status".to_string(), serde_json::to_value(status).unwrap()));
    iat.and_then(|t| sd_jwt_claims.insert("iat".to_string(), Value::Number(t.to_unix().into())));
    sub.and_then(|sub| sd_jwt_claims.insert("sub".to_string(), Value::String(sub.into())));

    sd_jwt_claims
  }
}
