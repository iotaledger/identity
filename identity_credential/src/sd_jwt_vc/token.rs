// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

use super::claims::SdJwtVcClaims;
use super::metadata::ClaimMetadata;
use super::metadata::IssuerMetadata;
use super::metadata::Jwks;
use super::metadata::TypeMetadata;
use super::metadata::WELL_KNOWN_VC_ISSUER;
use super::resolver::Error as ResolverErr;
use super::Error;
use super::Resolver;
use super::Result;
use super::SdJwtVcPresentationBuilder;
use crate::validator::JwtCredentialValidator as JwsUtils;
use crate::validator::KeyBindingJWTValidationOptions;
use anyhow::anyhow;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::ToJson as _;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkSet;
use identity_verification::jws::JwsVerifier;
use sd_jwt_payload_rework::Hasher;
use sd_jwt_payload_rework::JsonObject;
use sd_jwt_payload_rework::RequiredKeyBinding;
use sd_jwt_payload_rework::SdJwt;
use sd_jwt_payload_rework::SHA_ALG_NAME;
use serde_json::Value;

/// SD-JWT VC's JOSE header `typ`'s value.
pub const SD_JWT_VC_TYP: &str = "dc+sd-jwt";
/// SD-JWT VC's alternative JOSE header `typ`'s value.
/// This value is accepted for interoperability with older implementations.
pub const SD_JWT_VC_TYP_ALTERNATIVE: &str = "vc+sd-jwt";

#[derive(Debug, Clone, PartialEq, Eq)]
/// An SD-JWT carrying a verifiable credential as described in
/// [SD-JWT VC specification](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.html).
pub struct SdJwtVc {
  pub(crate) sd_jwt: SdJwt,
  pub(crate) parsed_claims: SdJwtVcClaims,
}

impl Deref for SdJwtVc {
  type Target = SdJwt;
  fn deref(&self) -> &Self::Target {
    &self.sd_jwt
  }
}

impl SdJwtVc {
  pub(crate) fn new(sd_jwt: SdJwt, claims: SdJwtVcClaims) -> Self {
    Self {
      sd_jwt,
      parsed_claims: claims,
    }
  }

  /// Parses a string into an [`SdJwtVc`].
  pub fn parse(s: &str) -> Result<Self> {
    s.parse()
  }

  /// Returns a reference to this [`SdJwtVc`]'s JWT claims.
  pub fn claims(&self) -> &SdJwtVcClaims {
    &self.parsed_claims
  }

  /// Prepares this [`SdJwtVc`] for a presentation, returning an [`SdJwtVcPresentationBuilder`].
  /// ## Errors
  /// - [`Error::SdJwt`] is returned if the provided `hasher`'s algorithm doesn't match the algorithm specified by
  ///   SD-JWT's `_sd_alg` claim. "sha-256" is used if the claim is missing.
  pub fn into_presentation(self, hasher: &dyn Hasher) -> Result<SdJwtVcPresentationBuilder> {
    SdJwtVcPresentationBuilder::new(self, hasher)
  }

  /// Returns the JSON object obtained by replacing all disclosures into their
  /// corresponding JWT concealable claims.
  pub fn into_disclosed_object(self, hasher: &dyn Hasher) -> Result<JsonObject> {
    SdJwt::from(self).into_disclosed_object(hasher).map_err(Error::SdJwt)
  }

  /// Retrieves this SD-JWT VC's issuer's metadata by querying its default location.
  /// ## Notes
  /// This method doesn't perform any validation of the retrieved [`IssuerMetadata`]
  /// besides its syntactical validity.
  /// To check if the retrieved [`IssuerMetadata`] is valid use [`IssuerMetadata::validate`].
  pub async fn issuer_metadata<R>(&self, resolver: &R) -> Result<Option<IssuerMetadata>>
  where
    R: Resolver<Url, Vec<u8>>,
  {
    let Some(iss) = self.claims().iss.as_ref() else {
      return Ok(None);
    };
    let metadata_url = {
      let origin = iss.origin().ascii_serialization();
      let path = iss.path();
      format!("{origin}{WELL_KNOWN_VC_ISSUER}{path}").parse().unwrap()
    };
    match resolver.resolve(&metadata_url).await {
      Err(ResolverErr::NotFound(_)) => Ok(None),
      Err(e) => Err(Error::Resolution {
        input: metadata_url.to_string(),
        source: e,
      }),
      Ok(json_res) => serde_json::from_slice(&json_res)
        .map_err(|e| Error::InvalidIssuerMetadata(e.into()))
        .map(Some),
    }
  }

  /// Retrieve this SD-JWT VC credential's type metadata [`TypeMetadata`].
  ///
  /// Returns the parsed [`TypeMetadata`] along with the raw [`Resolver`]'s response.
  /// The latter can be used to validate the `vct#integrity` claim if present.
  pub async fn type_metadata<R>(&self, resolver: &R) -> Result<(TypeMetadata, Vec<u8>)>
  where
    R: Resolver<String, Vec<u8>>,
  {
    let vct = self.claims().vct.clone();
    let raw = resolver
      .resolve(&vct)
      .await
      .map_err(|e| Error::Resolution { input: vct, source: e })?;
    let metadata = serde_json::from_slice(&raw).map_err(|e| Error::InvalidTypeMetadata(e.into()))?;

    Ok((metadata, raw))
  }

  /// Resolves the issuer's public key in JWK format.
  /// The issuer's JWK is first fetched through the issuer's metadata,
  /// if this attempt fails `resolver` is used to query the key directly
  /// through `kid`'s value.
  pub async fn issuer_jwk<R>(&self, resolver: &R) -> Result<Jwk>
  where
    R: Resolver<Url, Vec<u8>>,
  {
    let kid = self
      .header()
      .get("kid")
      .and_then(|value| value.as_str())
      .ok_or_else(|| Error::Verification(anyhow!("missing header claim `kid`")))?;

    // Try to find the key among issuer metadata jwk set.
    if let jwk @ Ok(_) = self.issuer_jwk_from_iss_metadata(resolver, kid).await {
      jwk
    } else {
      // Issuer has no metadata that can lead to its JWK. Let's see if it can be resolved directly.
      let jwk_uri = kid.parse::<Url>().map_err(|_| {
        Error::Verification(anyhow!(
          "JWK's kid \"{kid}\" could not be found in JKW set and cannot be resolved"
        ))
      })?;
      resolver
        .resolve(&jwk_uri)
        .await
        .map_err(|e| Error::Resolution {
          input: jwk_uri.to_string(),
          source: e,
        })
        .and_then(|bytes| {
          serde_json::from_slice(&bytes).map_err(|e| Error::Verification(anyhow!("invalid JWK: {}", e)))
        })
    }
  }

  async fn issuer_jwk_from_iss_metadata<R>(&self, resolver: &R, kid: &str) -> Result<Jwk>
  where
    R: Resolver<Url, Vec<u8>>,
  {
    let metadata = self
      .issuer_metadata(resolver)
      .await?
      .ok_or_else(|| Error::Verification(anyhow!("missing issuer metadata")))?;
    metadata.validate(self)?;

    let jwks = match metadata.jwks {
      Jwks::Object(jwks) => jwks,
      Jwks::Uri(jwks_uri) => resolver
        .resolve(&jwks_uri)
        .await
        .map_err(|e| Error::Resolution {
          input: jwks_uri.into_string(),
          source: e,
        })
        .and_then(|bytes| serde_json::from_slice::<JwkSet>(&bytes).map_err(|e| Error::Verification(e.into())))?,
    };
    jwks
      .iter()
      .find(|jwk| jwk.kid() == Some(kid))
      .cloned()
      .ok_or_else(|| Error::Verification(anyhow!("missing key \"{kid}\" in issuer JWK set")))
  }

  /// Verifies this [`SdJwtVc`] JWT's signature.
  pub fn verify_signature<V>(&self, jws_verifier: &V, jwk: &Jwk) -> Result<()>
  where
    V: JwsVerifier,
  {
    let sd_jwt_str = self.sd_jwt.to_string();
    let jws_input = {
      let jwt_str = sd_jwt_str
        .split_once('~')
        .expect("SD-JWT must contain a '~' separator")
        .0;
      JwsUtils::<V>::decode(jwt_str).map_err(|e| Error::Verification(e.into()))?
    };

    JwsUtils::<V>::verify_signature_raw(jws_input, jwk, jws_verifier)
      .map_err(|e| Error::Verification(e.into()))
      .and(Ok(()))
  }

  /// Checks the disclosability of this [`SdJwtVc`]'s claims against a list of [`ClaimMetadata`].
  /// ## Notes
  /// This check should be performed by the token's holder in order to assert the issuer's compliance with
  /// the credential's type.
  pub fn validate_claims_disclosability(&self, claims_metadata: &[ClaimMetadata]) -> Result<()> {
    let claims = Value::Object(self.parsed_claims.sd_jwt_claims.deref().clone());
    claims_metadata
      .iter()
      .try_fold((), |_, meta| meta.check_value_disclosability(&claims))
  }

  /// Check whether this [`SdJwtVc`] is valid.
  ///
  /// This method checks:
  /// - JWS signature
  /// - credential's type
  /// - claims' disclosability
  pub async fn validate<R, V>(&self, resolver: &R, jws_verifier: &V, hasher: &dyn Hasher) -> Result<()>
  where
    R: Resolver<Url, Vec<u8>>,
    R: Resolver<String, Vec<u8>>,
    R: Resolver<Url, Value>,
    V: JwsVerifier,
  {
    // Signature verification.
    // Fetch issuer's JWK.
    let jwk = self.issuer_jwk(resolver).await?;
    self.verify_signature(jws_verifier, &jwk)?;

    // Credential type.
    // Fetch type metadata. Skip integrity check.
    let fully_disclosed_token = self.clone().into_disclosed_object(hasher).map(Value::Object)?;
    let (type_metadata, _) = self.type_metadata(resolver).await?;
    type_metadata
      .validate_credential_with_resolver(&fully_disclosed_token, resolver)
      .await?;

    // Claims' disclosability.
    self.validate_claims_disclosability(type_metadata.claim_metadata())?;

    Ok(())
  }

  /// Verify the signature of this [`SdJwtVc`]'s [sd_jwt_payload_rework::KeyBindingJwt].
  pub fn verify_key_binding<V: JwsVerifier>(&self, jws_verifier: &V, jwk: &Jwk) -> Result<()> {
    let Some(kb_jwt) = self.key_binding_jwt() else {
      return Ok(());
    };
    let kb_jwt_str = kb_jwt.to_string();
    let jws_input = JwsUtils::<V>::decode(&kb_jwt_str).map_err(|e| Error::Verification(e.into()))?;

    JwsUtils::<V>::verify_signature_raw(jws_input, jwk, jws_verifier)
      .map_err(|e| Error::Verification(e.into()))
      .and(Ok(()))
  }

  /// Check the validity of this [`SdJwtVc`]'s [sd_jwt_payload_rework::KeyBindingJwt].
  /// # Notes
  /// Validation of the required key binding (specified through the `cnf` JWT's claim)
  /// is only partially validated - custom and "jwe" requirement are not checked.
  pub fn validate_key_binding<V: JwsVerifier>(
    &self,
    jws_verifier: &V,
    jwk: &Jwk,
    hasher: &dyn Hasher,
    options: &KeyBindingJWTValidationOptions,
  ) -> Result<()> {
    self.verify_key_binding(jws_verifier, jwk)?;

    if let Some(requirement) = self.required_key_bind() {
      if self.key_binding_jwt().is_none() {
        return Err(Error::Validation(anyhow!(
          "a key binding was required but none was provided"
        )));
      }
      match requirement {
        RequiredKeyBinding::Jwk(json_jwk) => {
          if jwk.to_json_value().unwrap().as_object().unwrap() != json_jwk {
            return Err(Error::Validation(anyhow!(
              "key used for signing KB-JWT does not match the key required in this SD-JWT"
            )));
          }
        }
        RequiredKeyBinding::Kid(kid) | RequiredKeyBinding::Jwu { kid, .. } => jwk
          .kid()
          .filter(|id| id == kid)
          .ok_or_else(|| {
            Error::Validation(anyhow::anyhow!(
              "the provided JWK doesn't have required `kid` \"{kid}\""
            ))
          })
          .map(|_| ())?,
        _ => (),
      }
    }

    let Some(kb_jwt) = self.key_binding_jwt() else {
      return Ok(());
    };
    let KeyBindingJWTValidationOptions {
      nonce,
      aud,
      earliest_issuance_date,
      latest_issuance_date,
      ..
    } = options;

    let issuance_date =
      Timestamp::from_unix(kb_jwt.claims().iat).map_err(|_| Error::Validation(anyhow!("invalid `iat` value")))?;

    if let Some(earliest_issuance_date) = earliest_issuance_date {
      if issuance_date < *earliest_issuance_date {
        return Err(Error::Validation(anyhow!(
          "this KB-JWT has been created earlier than `earliest_issuance_date`"
        )));
      }
    }

    if let Some(latest_issuance_date) = latest_issuance_date {
      if issuance_date > *latest_issuance_date {
        return Err(Error::Validation(anyhow!(
          "this KB-JWT has been created later than `latest_issuance_date`"
        )));
      }
    } else if issuance_date > Timestamp::now_utc() {
      return Err(Error::Validation(anyhow!("this KB-JWT has been created in the future")));
    }

    if let Some(nonce) = nonce {
      if nonce != &kb_jwt.claims().nonce {
        return Err(Error::Validation(anyhow!("invalid KB-JWT's nonce: expected {nonce}")));
      }
    }

    if let Some(aud) = aud {
      if aud != &kb_jwt.claims().aud {
        return Err(Error::Validation(anyhow!("invalid KB-JWT's `aud`: expected \"{aud}\"")));
      }
    }

    // Validate SD-JWT digest.
    if self.claims()._sd_alg.as_deref().unwrap_or(SHA_ALG_NAME) != hasher.alg_name() {
      return Err(Error::Validation(anyhow!("invalid hasher")));
    }
    let encoded_sd_jwt = self.to_string();
    let digest = {
      let last_tilde_idx = encoded_sd_jwt.rfind('~').expect("SD-JWT has a '~'");
      let sd_jwt_no_kb = &encoded_sd_jwt[..=last_tilde_idx];

      hasher.encoded_digest(sd_jwt_no_kb)
    };
    if kb_jwt.claims().sd_hash != digest {
      return Err(Error::Validation(anyhow!("invalid KB-JWT's `sd_hash`")));
    }

    Ok(())
  }
}

impl TryFrom<SdJwt> for SdJwtVc {
  type Error = Error;
  fn try_from(mut sd_jwt: SdJwt) -> std::result::Result<Self, Self::Error> {
    // Validate claims.
    let claims = {
      let claims = std::mem::take(sd_jwt.claims_mut());
      SdJwtVcClaims::try_from_sd_jwt_claims(claims, sd_jwt.disclosures())?
    };

    // Validate Header's typ.
    let typ = sd_jwt
      .header()
      .get("typ")
      .and_then(Value::as_str)
      .ok_or_else(|| Error::InvalidJoseType("null".to_string()))?;
    if !typ.contains(SD_JWT_VC_TYP) && !typ.contains(SD_JWT_VC_TYP_ALTERNATIVE) {
      return Err(Error::InvalidJoseType(typ.to_string()));
    }

    Ok(Self {
      sd_jwt,
      parsed_claims: claims,
    })
  }
}

impl FromStr for SdJwtVc {
  type Err = Error;
  fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
    s.parse::<SdJwt>().map_err(Error::SdJwt).and_then(TryInto::try_into)
  }
}

impl Display for SdJwtVc {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.sd_jwt)
  }
}

impl From<SdJwtVc> for SdJwt {
  fn from(value: SdJwtVc) -> Self {
    let SdJwtVc {
      mut sd_jwt,
      parsed_claims,
    } = value;
    // Put back `parsed_claims`.
    *sd_jwt.claims_mut() = parsed_claims.into();

    sd_jwt
  }
}

#[cfg(test)]
mod tests {
  use std::sync::LazyLock;

  use identity_core::common::Url;

  use super::*;

  const EXAMPLE_SD_JWT_VC: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCJ9.eyJfc2QiOiBbIjBIWm1uU0lQejMzN2tTV2U3QzM0bC0tODhnekppLWVCSjJWel9ISndBVGciLCAiOVpicGxDN1RkRVc3cWFsNkJCWmxNdHFKZG1lRU9pWGV2ZEpsb1hWSmRSUSIsICJJMDBmY0ZVb0RYQ3VjcDV5eTJ1anFQc3NEVkdhV05pVWxpTnpfYXdEMGdjIiwgIklFQllTSkdOaFhJbHJRbzU4eWtYbTJaeDN5bGw5WmxUdFRvUG8xN1FRaVkiLCAiTGFpNklVNmQ3R1FhZ1hSN0F2R1RyblhnU2xkM3o4RUlnX2Z2M2ZPWjFXZyIsICJodkRYaHdtR2NKUXNCQ0EyT3RqdUxBY3dBTXBEc2FVMG5rb3ZjS09xV05FIiwgImlrdXVyOFE0azhxM1ZjeUE3ZEMtbU5qWkJrUmVEVFUtQ0c0bmlURTdPVFUiLCAicXZ6TkxqMnZoOW80U0VYT2ZNaVlEdXZUeWtkc1dDTmcwd1RkbHIwQUVJTSIsICJ3elcxNWJoQ2t2a3N4VnZ1SjhSRjN4aThpNjRsbjFqb183NkJDMm9hMXVnIiwgInpPZUJYaHh2SVM0WnptUWNMbHhLdUVBT0dHQnlqT3FhMXoySW9WeF9ZRFEiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgInZjdCI6ICJodHRwczovL2JtaS5idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwgImFnZV9lcXVhbF9vcl9vdmVyIjogeyJfc2QiOiBbIkZjOElfMDdMT2NnUHdyREpLUXlJR085N3dWc09wbE1Makh2UkM0UjQtV2ciLCAiWEx0TGphZFVXYzl6Tl85aE1KUm9xeTQ2VXNDS2IxSXNoWnV1cVVGS1NDQSIsICJhb0NDenNDN3A0cWhaSUFoX2lkUkNTQ2E2NDF1eWNuYzh6UGZOV3o4bngwIiwgImYxLVAwQTJkS1dhdnYxdUZuTVgyQTctRVh4dmhveHY1YUhodUVJTi1XNjQiLCAiazVoeTJyMDE4dnJzSmpvLVZqZDZnNnl0N0Fhb25Lb25uaXVKOXplbDNqbyIsICJxcDdaX0t5MVlpcDBzWWdETzN6VnVnMk1GdVBOakh4a3NCRG5KWjRhSS1jIl19LCAiX3NkX2FsZyI6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX19.CaXec2NNooWAy4eTxYbGWI--UeUL0jpC7Zb84PP_09Z655BYcXUTvfj6GPk4mrNqZUU5GT6QntYR8J9rvcBjvA~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyJNMEpiNTd0NDF1YnJrU3V5ckRUM3hBIiwgIjE4IiwgdHJ1ZV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3MjA0NTQyOTUsICJzZF9oYXNoIjogIlZFejN0bEtqOVY0UzU3TTZoRWhvVjRIc19SdmpXZWgzVHN1OTFDbmxuZUkifQ.GqtiTKNe3O95GLpdxFK_2FZULFk6KUscFe7RPk8OeVLiJiHsGvtPyq89e_grBplvGmnDGHoy8JAt1wQqiwktSg";
  static EXAMPLE_ISSUER: LazyLock<Url> = LazyLock::new(|| "https://example.com/issuer".parse().unwrap());
  const EXAMPLE_VCT: &str = "https://bmi.bund.example/credential/pid/1.0";

  #[test]
  fn simple_sd_jwt_is_not_a_valid_sd_jwt_vc() {
    let sd_jwt: SdJwt = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1FyazFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZzZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZkx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1REw4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSLWFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzIiwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAiczBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTSjFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1cFJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZXd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2bmNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4anZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25VbGRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0MG9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.gR6rSL7urX79CNEvTQnP1MH5xthG11ucIV44SqKFZ4Pvlu_u16RfvXQd4k4CAIBZNKn2aTI18TfvFwV97gJFoA~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ~"
      .parse().unwrap();
    let err = SdJwtVc::try_from(sd_jwt).unwrap_err();
    assert!(matches!(err, Error::MissingClaim("vct")))
  }

  #[test]
  fn parsing_a_valid_sd_jwt_vc_works() {
    let sd_jwt_vc: SdJwtVc = EXAMPLE_SD_JWT_VC.parse().unwrap();
    assert_eq!(sd_jwt_vc.claims().iss, Some(EXAMPLE_ISSUER.clone()));
    assert_eq!(sd_jwt_vc.claims().vct.as_str(), EXAMPLE_VCT);
  }
}
