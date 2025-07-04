// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::credential::CredentialJwtClaims;
use crate::validator::CompoundCredentialValidationError;
use crate::validator::DecodedJwtCredential;
use crate::validator::FailFast;
use crate::validator::JwtCredentialValidationOptions;
use crate::validator::JwtCredentialValidator;
use crate::validator::JwtCredentialValidatorUtils;
use crate::validator::JwtValidationError;
use crate::validator::SignerContext;
use identity_core::common::Timestamp;
use identity_core::convert::FromJson;
use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use identity_document::verifiable::JwsVerificationOptions;
use identity_verification::jwk::Jwk;
use identity_verification::jws::DecodedJws;
use identity_verification::jws::Decoder;
use identity_verification::jws::JwsValidationItem;
use identity_verification::jws::JwsVerifier;
use itertools::Itertools;
use sd_jwt_payload::KeyBindingJwtClaims;
use sd_jwt_payload::SdJwt;
use sd_jwt_payload::SdObjectDecoder;
use serde_json::Value;

use super::KeyBindingJWTValidationOptions;
use super::KeyBindingJwtError;

/// A type for decoding and validating [`SdJwt`]s.
#[non_exhaustive]
pub struct SdJwtCredentialValidator<V: JwsVerifier>(V, SdObjectDecoder);

impl<V: JwsVerifier> SdJwtCredentialValidator<V> {
  /// Creates a new [`SdJwtValidator`]that delegates cryptographic signature verification to the given
  /// `signature_verifier`.
  pub fn with_signature_verifier(signature_verifier: V, sd_decoder: SdObjectDecoder) -> Self {
    Self(signature_verifier, sd_decoder)
  }

  /// Decodes and validates a [`Credential`] issued as an SD-JWT. A [`DecodedJwtCredential`] is returned upon success.
  /// The credential is constructed by replacing disclosures following the
  /// [`Selective Disclosure for JWTs (SD-JWT)`](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html) standard.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// * The key binding JWT is not validated. If needed, it must be validated separately using
  ///   `SdJwtValidator::validate_key_binding_jwt`.
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
  ///   trusted. This section contains more information on additional checks that should be carried out before and after
  ///   calling this method.
  ///
  /// ## The state of the issuer's DID Document
  /// The caller must ensure that `issuer` represents an up-to-date DID Document.
  ///
  /// ## Properties that are not validated
  ///  There are many properties defined in [The Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) that are **not** validated, such as:
  /// `proof`, `credentialStatus`, `type`, `credentialSchema`, `refreshService` **and more**.
  /// These should be manually checked after validation, according to your requirements.
  ///
  /// # Errors
  /// An error is returned whenever a validated condition is not satisfied.
  pub fn validate_credential<DOC, T>(
    &self,
    sd_jwt: &SdJwt,
    issuer: &DOC,
    options: &JwtCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<DecodedJwtCredential<T>, CompoundCredentialValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let issuers = std::slice::from_ref(issuer.as_ref());
    let credential = self
      .verify_signature(sd_jwt, issuers, &options.verification_options)
      .map_err(|err| CompoundCredentialValidationError {
        validation_errors: [err].into(),
      })?;

    JwtCredentialValidator::<V>::validate_decoded_credential(credential, issuers, options, fail_fast)
  }

  /// Decode and verify the JWS signature of a [`Credential`] issued as an SD-JWT using the DID Document of a trusted
  /// issuer and replaces the disclosures.
  ///
  /// A [`DecodedJwtCredential`] is returned upon success.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// ## Proofs
  ///  Only the JWS signature is verified. If the [`Credential`] contains a `proof` property this will not be verified
  /// by this method.
  ///
  /// # Errors
  /// * If the issuer' URL cannot be parsed.
  /// * If Signature verification fails.
  /// * If SD decoding fails.
  pub fn verify_signature<DOC, T>(
    &self,
    credential: &SdJwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DecodedJwtCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let SdJwt { jwt, disclosures, .. } = credential;
    let signature = JwtCredentialValidator::<V>::decode(jwt.as_str())?;
    let (public_key, method_id) = JwtCredentialValidator::<V>::parse_jwk(&signature, trusted_issuers, options)?;

    let DecodedJws { protected, claims, .. } =
      JwtCredentialValidator::<V>::verify_signature_raw(signature, public_key, &self.0)?;

    let value: Value = serde_json::from_slice(&claims).map_err(|err| {
      JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
    })?;
    let obj = value.as_object().ok_or(JwtValidationError::JwsDecodingError(
      identity_verification::jose::error::Error::InvalidClaim("sd-jwt claims could not be deserialized"),
    ))?;
    let decoded: String = Value::Object(self.1.decode(obj, disclosures).map_err(|e| {
      let err_str = format!("sd-jwt claims decoding failed, {e}");
      let err: &'static str = Box::leak(err_str.into_boxed_str());
      JwtValidationError::JwsDecodingError(identity_verification::jose::error::Error::InvalidClaim(err))
    })?)
    .to_string();

    let claims = CredentialJwtClaims::from_json(&decoded).map_err(|err| {
      JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
    })?;
    let custom_claims = claims.custom.clone();
    let credential = claims
      .try_into_credential()
      .map_err(JwtValidationError::CredentialStructure)?;

    let decoded_credential = DecodedJwtCredential {
      credential,
      header: Box::new(protected),
      custom_claims,
    };

    // Check that the DID component of the parsed `kid` does indeed correspond to the issuer in the credential before
    // returning.
    let issuer_id = JwtCredentialValidatorUtils::extract_issuer::<CoreDID, _>(&decoded_credential.credential)?;
    if &issuer_id != method_id.did() {
      return Err(JwtValidationError::IdentifierMismatch {
        signer_ctx: SignerContext::Issuer,
      });
    };

    Ok(decoded_credential)
  }

  /// Validates a Key Binding JWT (KB-JWT) according to `https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-key-binding-jwt`.
  /// The Validation process includes:
  ///   * Signature validation using public key materials defined in the `holder` document.
  ///   * `typ` value in KB-JWT header.
  ///   * `sd_hash` claim value in the KB-JWT claim.
  ///   * Optional `nonce`, `aud` and issuance date validation.
  pub fn validate_key_binding_jwt<DOC>(
    &self,
    sd_jwt: &SdJwt,
    holder: &DOC,
    options: &KeyBindingJWTValidationOptions,
  ) -> Result<KeyBindingJwtClaims, KeyBindingJwtError>
  where
    DOC: AsRef<CoreDocument>,
  {
    // Check if KB exists in the SD-JWT.
    let kb_jwt = if let Some(kb_jwt) = &sd_jwt.key_binding_jwt {
      kb_jwt.clone()
    } else {
      return Err(KeyBindingJwtError::MissingKeyBindingJwt);
    };

    // Calculate the digest from the `sd_jwt.jwt` and the disclosures.
    let jws_decoder = Decoder::new();
    let decoded: JwsValidationItem<'_> = jws_decoder
      .decode_compact_serialization(sd_jwt.jwt.as_bytes(), None)
      .map_err(|err| KeyBindingJwtError::JwtValidationError(JwtValidationError::JwsDecodingError(err)))?;
    let sd_jwt_claims: Value = serde_json::from_slice(decoded.claims())
      .map_err(|_| KeyBindingJwtError::DeserializationError("failed to deserialize sd-jwt claims".to_string()))?;
    let sd_jwt_claims_object = sd_jwt_claims
      .as_object()
      .ok_or(KeyBindingJwtError::DeserializationError(
        "failed to deserialize sd-jwt claims".to_string(),
      ))?;
    let hasher = self.1.determine_hasher(sd_jwt_claims_object)?;
    let disclosures = sd_jwt.disclosures.iter().join("~");
    let hash_payload = format!("{}~{}~", sd_jwt.jwt, disclosures);
    let digest = hasher.encoded_digest(&hash_payload);

    // Verify the signature of the KB-JWT and extract claims.
    let kb_decoded: JwsValidationItem<'_> = jws_decoder
      .decode_compact_serialization(kb_jwt.as_bytes(), None)
      .map_err(JwtValidationError::JwsDecodingError)?;
    let typ: &str = kb_decoded
      .protected_header()
      .ok_or(KeyBindingJwtError::InvalidHeaderTypValue)?
      .typ()
      .ok_or(KeyBindingJwtError::InvalidHeaderTypValue)?;

    if typ != KeyBindingJwtClaims::KB_JWT_HEADER_TYP {
      return Err(KeyBindingJwtError::InvalidHeaderTypValue);
    }
    let method_id: DIDUrl = match &options.jws_options.method_id {
      Some(method_id) => method_id.clone(),
      None => {
        let kid: &str = kb_decoded.protected_header().and_then(|header| header.kid()).ok_or(
          JwtValidationError::MethodDataLookupError {
            source: None,
            message: "could not extract kid from protected header",
            signer_ctx: SignerContext::Holder,
          },
        )?;

        // Convert kid to DIDUrl
        DIDUrl::parse(kid).map_err(|err| JwtValidationError::MethodDataLookupError {
          source: Some(err.into()),
          message: "could not parse kid as a DID Url",
          signer_ctx: SignerContext::Issuer,
        })?
      }
    };

    // Obtain the public key from the holder's DID document
    let public_key: &Jwk = holder
      .as_ref()
      .resolve_method(&method_id, options.jws_options.method_scope)
      .and_then(|method| method.data().public_key_jwk())
      .ok_or_else(|| JwtValidationError::MethodDataLookupError {
        source: None,
        message: "could not extract JWK from a method identified by kid",
        signer_ctx: SignerContext::Holder,
      })?;
    let decoded: JwsValidationItem<'_> = jws_decoder
      .decode_compact_serialization(kb_jwt.as_bytes(), None)
      .map_err(|err| KeyBindingJwtError::JwtValidationError(JwtValidationError::JwsDecodingError(err)))?;
    let decoded_kb_jws = decoded.verify(&self.0, public_key).unwrap();

    let kb_jwt_claims: KeyBindingJwtClaims = serde_json::from_slice(&decoded_kb_jws.claims)
      .map_err(|_| KeyBindingJwtError::DeserializationError("failed to deserialize kb-jwt claims".into()))?;

    // Check if the `_sd_hash` matches.
    if kb_jwt_claims.sd_hash != digest {
      return Err(KeyBindingJwtError::InvalidDigest);
    }

    if let Some(nonce) = &options.nonce {
      if *nonce != kb_jwt_claims.nonce {
        return Err(KeyBindingJwtError::InvalidNonce);
      }
    }

    if let Some(aud) = &options.aud {
      if *aud != kb_jwt_claims.aud {
        return Err(KeyBindingJwtError::AudienceMismatch);
      }
    }

    let issuance_date = Timestamp::from_unix(kb_jwt_claims.iat)
      .map_err(|_| KeyBindingJwtError::IssuanceDate("deserialization of `iat` failed".to_string()))?;

    if let Some(earliest_issuance_date) = options.earliest_issuance_date {
      if issuance_date < earliest_issuance_date {
        return Err(KeyBindingJwtError::IssuanceDate(
          "value is earlier than `earliest_issuance_date`".to_string(),
        ));
      }
    }

    if let Some(latest_issuance_date) = options.latest_issuance_date {
      if issuance_date > latest_issuance_date {
        return Err(KeyBindingJwtError::IssuanceDate(
          "value is later than `latest_issuance_date`".to_string(),
        ));
      }
    } else if issuance_date > Timestamp::now_utc() {
      return Err(KeyBindingJwtError::IssuanceDate("value is in the future".to_string()));
    }

    Ok(kb_jwt_claims)
  }
}
