// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::credential::Credential;
use crate::credential::CredentialJwtClaims;
use crate::credential::CredentialV2;
use crate::validator::FailFast;
use crate::validator::JwtCredentialValidationOptions;
use crate::validator::JwtCredentialValidator;
use crate::validator::JwtCredentialValidatorUtils;
use crate::validator::JwtValidationError;
use crate::validator::SignerContext;
use crate::validator::UnexpectedValue;
use anyhow::Context as _;
use identity_core::common::Timestamp;
use identity_core::convert::FromJson;
use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use identity_document::verifiable::JwsVerificationOptions;
use identity_verification::jwk::Jwk;
use identity_verification::jws::Decoder;
use identity_verification::jws::JwsValidationItem;
use identity_verification::jws::JwsVerifier;
use sd_jwt::Hasher;
use sd_jwt::RequiredKeyBinding;
use sd_jwt::SdJwt;
use serde_json::Value;

use super::KeyBindingJwtError;
use super::KeyBindingJwtValidationOptions;

/// Errors that can occur when validating an SD-JWT credential.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SdJwtCredentialValidatorError {
  /// The SD-JWT token is valid, but the disclosed claims could not be used to construct a well-formed credential.
  #[error("failed to construct a well-formed credential from SD-JWT disclosed claims")]
  CredentialStructure(#[source] Box<dyn std::error::Error + Send + Sync>),
  /// Failed to verify the JWS signature.
  #[error(transparent)]
  JwsVerification(#[from] JwtValidationError),
  /// SD-JWT specific error like: disclosure processing, or hasher mismatch.
  #[error(transparent)]
  SdJwt(#[from] sd_jwt::Error),
}

/// A type validating [`SdJwt`]s.
#[non_exhaustive]
pub struct SdJwtCredentialValidator<V: JwsVerifier>(V, Box<dyn Hasher>);

impl<V: JwsVerifier> SdJwtCredentialValidator<V> {
  /// Creates a new [`SdJwtCredentialValidator`] that delegates cryptographic signature verification to the given
  /// `signature_verifier` and SD-JWT decoding to the given `hasher`.
  pub fn new<H: Hasher + 'static>(signature_verifier: V, hasher: H) -> Self {
    Self(signature_verifier, Box::new(hasher))
  }

  /// Decodes and validates a [Credential] issued as an SD-JWT.
  /// The credential is constructed by replacing disclosures following the
  /// [Selective Disclosure for JWTs (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html) standard.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// * The key binding JWT is not validated. If needed, it must be validated separately using
  ///   [SdJwtCredentialValidator::validate_key_binding_jwt].
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
    trusted_issuers: &[DOC],
    options: &JwtCredentialValidationOptions,
  ) -> Result<Credential<T>, SdJwtCredentialValidatorError>
  where
    T: Clone + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    // Verify the JWS signature.
    let vm_id = self.verify_signature_impl(&sd_jwt.presentation(), trusted_issuers, &options.verification_options)?;
    let hasher = self.1.as_ref();

    // Try to construct a credential from the disclosed claims.
    let disclosed_claims = sd_jwt.clone().into_disclosed_object(hasher)?;
    let credential_jwt_claims: CredentialJwtClaims<'_, T> = serde_json::from_value(Value::Object(disclosed_claims))
      .map_err(|e| SdJwtCredentialValidatorError::CredentialStructure(e.into()))?;
    let credential = credential_jwt_claims
      .try_into_credential()
      .map_err(|e| SdJwtCredentialValidatorError::CredentialStructure(e.into()))?;
    JwtCredentialValidator::<V>::validate_decoded_credential(
      &credential,
      trusted_issuers,
      options,
      FailFast::FirstError,
    )
    .map_err(|mut errs| SdJwtCredentialValidatorError::JwsVerification(errs.validation_errors.swap_remove(0)))?;

    let issuer_id = JwtCredentialValidatorUtils::extract_issuer::<CoreDID, _>(&credential)?;
    if &issuer_id != vm_id.did() {
      return Err(
        JwtValidationError::IdentifierMismatch {
          signer_ctx: SignerContext::Issuer,
        }
        .into(),
      );
    }

    Ok(credential)
  }

  /// Decodes and validates a [CredentialV2] issued as an SD-JWT.
  /// The credential is constructed by replacing disclosures following the
  /// [Selective Disclosure for JWTs (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html) standard.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// * The key binding JWT is not validated. If needed, it must be validated separately using
  ///   [SdJwtCredentialValidator::validate_key_binding_jwt].
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
  ///   trusted. This section contains more information on additional checks that should be carried out before and after
  ///   calling this method.
  ///
  /// ## The state of the issuer's DID Document
  /// The caller must ensure that `issuer` represents an up-to-date DID Document.
  ///
  /// ## Properties that are not validated
  /// There are many properties defined in [The Verifiable Credentials Data Model v2](https://www.w3.org/TR/vc-data-model-2.0/)
  /// that are **not** validated, such as:
  /// `proof`, `credentialStatus`, `type`, `credentialSchema`, `refreshService` **and more**.
  /// These should be manually checked after validation, according to your requirements.
  ///
  /// # Errors
  /// An error is returned whenever a validated condition is not satisfied.
  pub fn validate_credential_v2<DOC, T>(
    &self,
    sd_jwt: &SdJwt,
    trusted_issuers: &[DOC],
    options: &JwtCredentialValidationOptions,
  ) -> Result<CredentialV2<T>, SdJwtCredentialValidatorError>
  where
    T: Clone + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    // Verify the JWS signature.
    let vm_id = self.verify_signature_impl(&sd_jwt.presentation(), trusted_issuers, &options.verification_options)?;
    let hasher = self.1.as_ref();

    // Try to construct a credential from the disclosed claims.
    let disclosed_claims = sd_jwt.clone().into_disclosed_object(hasher)?;
    let credential = CredentialV2::<T>::from_json_value(Value::Object(disclosed_claims))
      .map_err(|e| SdJwtCredentialValidatorError::CredentialStructure(e.into()))?;
    JwtCredentialValidator::<V>::validate_decoded_credential(
      &credential,
      trusted_issuers,
      options,
      FailFast::FirstError,
    )
    .map_err(|mut errs| SdJwtCredentialValidatorError::JwsVerification(errs.validation_errors.swap_remove(0)))?;

    let issuer_id = JwtCredentialValidatorUtils::extract_issuer::<CoreDID, _>(&credential)?;
    if &issuer_id != vm_id.did() {
      return Err(
        JwtValidationError::IdentifierMismatch {
          signer_ctx: SignerContext::Issuer,
        }
        .into(),
      );
    }

    Ok(credential)
  }

  /// Decode and verify the JWS signature of an SD-JWT using the DID Document of a trusted issuer.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// # Errors
  /// An error is returned whenever:
  /// - The JWS signature is invalid;
  /// - The issuer's public key could not be determined or is not found within the trusted issuers' documents;
  pub fn verify_signature<DOC>(
    &self,
    sd_jwt: &SdJwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<(), JwtValidationError>
  where
    DOC: AsRef<CoreDocument>,
  {
    let sd_jwt_str = sd_jwt.presentation();
    let _ = self.verify_signature_impl(&sd_jwt_str, trusted_issuers, options)?;

    Ok(())
  }

  fn verify_signature_impl<DOC>(
    &self,
    sd_jwt: &str,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DIDUrl, JwtValidationError>
  where
    DOC: AsRef<CoreDocument>,
  {
    let jwt_str = sd_jwt
      .split_once('~')
      .expect("valid SD-JWT contains at least one `~`")
      .0;
    let signature = JwtCredentialValidator::<V>::decode(jwt_str).expect("SD-JWT has a valid JWS");
    let (public_key, method_id) = JwtCredentialValidator::<V>::parse_jwk(&signature, trusted_issuers, options)?;

    JwtCredentialValidator::<V>::verify_signature_raw(signature, public_key, &self.0)?;
    Ok(method_id)
  }

  /// Validates a [Key Binding JWT (KB-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html#name-key-binding-jwt)
  /// according to [RFC9901](https://www.rfc-editor.org/rfc/rfc9901.html#key_binding_security).
  ///
  /// The Validation process includes:
  ///   - Signature validation using public key materials defined in the `holder` document.
  ///   - `sd_hash` claim value in the KB-JWT claim.
  ///   - Optional `nonce`, `aud`, and validity period validation.
  ///
  /// ## Notes
  /// If a KB-JWT is not required by the SD-JWT, this method returns successfully early.
  pub fn validate_key_binding_jwt<DOC>(
    &self,
    sd_jwt: &SdJwt,
    holder_document: &DOC,
    options: &KeyBindingJwtValidationOptions,
  ) -> Result<(), KeyBindingJwtError>
  where
    DOC: AsRef<CoreDocument>,
  {
    // Check if a KB-JWT is required.
    let Some(required_kb) = sd_jwt.required_key_bind() else {
      return Ok(());
    };
    // Check if KB exists in the SD-JWT.
    let Some(kb_jwt) = sd_jwt.key_binding_jwt() else {
      return Err(KeyBindingJwtError::MissingKeyBindingJwt);
    };

    let hasher = self.1.as_ref();
    let kb_jwt_str = kb_jwt.to_string();
    // Determine the holder's public key.
    let holder_pk = match required_kb {
      RequiredKeyBinding::Jwk(jwk) => Jwk::from_json_value(Value::Object(jwk.clone()))
        .context("failed to deserialize 'cnf' JWK")
        .map_err(|e| KeyBindingJwtError::DeserializationError(e.into()))?,
      RequiredKeyBinding::Kid(kid) => {
        let method_id = DIDUrl::parse(kid).map_err(|e| JwtValidationError::MethodDataLookupError {
          source: Some(e.into()),
          message: "could not parse kid as a DID Url",
          signer_ctx: SignerContext::Holder,
        })?;
        if holder_document.as_ref().id() != method_id.did() {
          return Err(KeyBindingJwtError::JwtValidationError(
            JwtValidationError::DocumentMismatch(SignerContext::Holder),
          ));
        }
        holder_document
          .as_ref()
          .resolve_method(&method_id, None)
          .and_then(|method| method.data().public_key_jwk())
          .ok_or_else(|| JwtValidationError::MethodDataLookupError {
            source: None,
            message: "could not extract JWK from a method identified by kid",
            signer_ctx: SignerContext::Holder,
          })?
          .clone()
      }
      _ => return Err(KeyBindingJwtError::UnsupportedCnfMethod),
    };

    let decoded: JwsValidationItem<'_> = Decoder::new()
      .decode_compact_serialization(kb_jwt_str.as_bytes(), None)
      .map_err(|err| KeyBindingJwtError::JwtValidationError(JwtValidationError::JwsDecodingError(err)))?;
    let _ = decoded.verify(&self.0, &holder_pk).map_err(|e| {
      KeyBindingJwtError::JwtValidationError(JwtValidationError::Signature {
        source: e,
        signer_ctx: SignerContext::Holder,
      })
    })?;

    // Make sure the passed Hasher matches the one used in the SD-JWT.
    if sd_jwt.claims()._sd_alg.as_deref().unwrap_or(sd_jwt::SHA_ALG_NAME) != hasher.alg_name() {
      return Err(sd_jwt::Error::InvalidHasher(hasher.alg_name().to_owned()).into());
    }

    let digest = {
      let sd_jwt_str = sd_jwt.to_string();
      let last_tilde_index = sd_jwt_str.rfind('~').expect("valid SD-JWT contains at least one `~`");
      hasher.encoded_digest(&sd_jwt_str[..last_tilde_index + 1])
    };

    // Check if the `_sd_hash` matches.
    let sd_hash = kb_jwt.claims().sd_hash.as_str();
    if sd_hash != digest.as_str() {
      return Err(KeyBindingJwtError::InvalidDigest(UnexpectedValue {
        expected: Some(digest.into()),
        found: sd_hash.into(),
      }));
    }

    if let Some(nonce) = options.nonce.as_deref() {
      if nonce != kb_jwt.claims().nonce {
        return Err(KeyBindingJwtError::InvalidNonce(UnexpectedValue {
          expected: Some(nonce.to_owned().into()),
          found: kb_jwt.claims().nonce.clone().into(),
        }));
      }
    }

    if let Some(aud) = options.aud.as_deref() {
      if aud != kb_jwt.claims().aud {
        return Err(KeyBindingJwtError::AudienceMismatch(UnexpectedValue {
          expected: Some(aud.to_owned().into()),
          found: kb_jwt.claims().aud.clone().into(),
        }));
      }
    }

    let issuance_date = Timestamp::from_unix(kb_jwt.claims().iat)
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

    Ok(())
  }
}
