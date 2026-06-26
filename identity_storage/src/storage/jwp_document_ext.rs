// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use super::JwkStorageDocumentError as Error;
use crate::key_id_storage::MethodDigest;
use crate::try_undo_key_generation;
use crate::JwkGenOutput;
use crate::JwkStorageBbsPlusExt;
use crate::KeyIdStorage;
use crate::KeyType;
use crate::Storage;
use crate::StorageResult;
use async_trait::async_trait;
use identity_core::common::Object;
use identity_core::convert::ToJson;
use identity_credential::credential::Credential;
use identity_credential::credential::Jpt;
use identity_credential::credential::JwpCredentialOptions;
use identity_credential::presentation::JwpPresentationOptions;
use identity_credential::presentation::SelectiveDisclosurePresentation;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use identity_verification::MethodData;
use identity_verification::MethodScope;
use identity_verification::VerificationMethod;
use jsonprooftoken::encoding::SerializationType;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use jsonprooftoken::jpt::claims::JptClaims;
use jsonprooftoken::jwk::key::Jwk;
use jsonprooftoken::jwp::header::IssuerProtectedHeader;
use jsonprooftoken::jwp::header::PresentationProtectedHeader;
use jsonprooftoken::jwp::issued::JwpIssuedBuilder;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Handle JWP-based operations on DID Documents.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait JwpDocumentExt {
  /// Generate new key material in the given `storage` and insert a new verification method with the corresponding
  /// public key material into the DID document. This supports BBS+ keys.
  async fn generate_method_jwp<K, I>(
    &mut self,
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: ProofAlgorithm,
    fragment: Option<&str>,
    scope: MethodScope,
  ) -> StorageResult<String>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage;

  /// Compute a JWP in the Issued form representing the Verifiable Credential
  /// See [JSON Web Proof draft](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof#name-issued-form)
  async fn create_issued_jwp<K, I>(
    &self,
    storage: &Storage<K, I>,
    fragment: &str,
    jpt_claims: &JptClaims,
    options: &JwpCredentialOptions,
  ) -> StorageResult<String>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage;

  /// Compute a JWP in the Presented form representing the presented Verifiable Credential after the Selective
  /// Disclosure of attributes See [JSON Web Proof draft](https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof#name-presented-form)
  async fn create_presented_jwp(
    &self,
    presentation: &mut SelectiveDisclosurePresentation,
    method_id: &str,
    options: &JwpPresentationOptions,
  ) -> StorageResult<String>;

  /// Produces a JPT where the payload is produced from the given `credential`.
  async fn create_credential_jpt<K, I, T>(
    &self,
    credential: &Credential<T>,
    storage: &Storage<K, I>,
    fragment: &str,
    options: &JwpCredentialOptions,
    custom_claims: Option<Object>,
  ) -> StorageResult<Jpt>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage,
    T: ToOwned<Owned = T> + Serialize + DeserializeOwned + Sync;

  /// Produces a JPT where the payload contains the Selective Disclosed attributes of a `credential`.
  async fn create_presentation_jpt(
    &self,
    presentation: &mut SelectiveDisclosurePresentation,
    method_id: &str,
    options: &JwpPresentationOptions,
  ) -> StorageResult<Jpt>;
}

// ====================================================================================================================
// CoreDocument
// ====================================================================================================================

generate_method_for_document_type!(
  CoreDocument,
  ProofAlgorithm,
  JwkStorageBbsPlusExt,
  JwkStorageBbsPlusExt::generate_bbs,
  generate_method_core_document
);

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwpDocumentExt for CoreDocument {
  async fn generate_method_jwp<K, I>(
    &mut self,
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: ProofAlgorithm,
    fragment: Option<&str>,
    scope: MethodScope,
  ) -> StorageResult<String>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage,
  {
    generate_method_core_document(self, storage, key_type, alg, fragment, scope).await
  }

  async fn create_issued_jwp<K, I>(
    &self,
    storage: &Storage<K, I>,
    fragment: &str,
    jpt_claims: &JptClaims,
    options: &JwpCredentialOptions,
  ) -> StorageResult<String>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage,
  {
    // Obtain the method corresponding to the given fragment.
    let method: &VerificationMethod = self.resolve_method(fragment, None).ok_or(Error::MethodNotFound)?;
    let MethodData::PublicKeyJwk(ref jwk) = method.data() else {
      return Err(Error::NotPublicKeyJwk);
    };

    // Extract JwsAlgorithm.
    let alg: ProofAlgorithm = jwk
      .alg()
      .unwrap_or("")
      .parse()
      .map_err(|_| Error::InvalidJwpAlgorithm)?;

    let typ = "JPT".to_string();

    let kid = if let Some(ref kid) = options.kid {
      kid.clone()
    } else {
      method.id().to_string()
    };

    let mut issuer_header = IssuerProtectedHeader::new(alg);
    issuer_header.set_typ(Some(typ));
    issuer_header.set_kid(Some(kid));

    // Get the key identifier corresponding to the given method from the KeyId storage.
    let method_digest: MethodDigest = MethodDigest::new(method).map_err(Error::MethodDigestConstructionError)?;
    let key_id = <I as KeyIdStorage>::get_key_id(storage.key_id_storage(), &method_digest)
      .await
      .map_err(Error::KeyIdStorageError)?;

    let jwp_builder = JwpIssuedBuilder::new(issuer_header, jpt_claims.clone());

    let header = jwp_builder.get_issuer_protected_header().map_or_else(
      || Err(Error::JwpBuildingError),
      |h| h.to_json_vec().map_err(|_| Error::JwpBuildingError),
    )?;

    let data = jwp_builder.get_payloads().map_or_else(
      || Err(Error::JwpBuildingError),
      |p| p.to_bytes().map_err(|_| Error::JwpBuildingError),
    )?;

    let signature = <K as JwkStorageBbsPlusExt>::sign_bbs(storage.key_storage(), &key_id, &data, &header, jwk)
      .await
      .map_err(Error::KeyStorageError)?;

    jwp_builder
      .build_with_proof(signature)
      .map_err(|_| Error::JwpBuildingError)?
      .encode(SerializationType::COMPACT)
      .map_err(|err| Error::EncodingError(Box::new(err)))
  }

  async fn create_presented_jwp(
    &self,
    presentation: &mut SelectiveDisclosurePresentation,
    method_id: &str,
    options: &JwpPresentationOptions,
  ) -> StorageResult<String> {
    // Obtain the method corresponding to the given fragment.
    let method: &VerificationMethod = self.resolve_method(method_id, None).ok_or(Error::MethodNotFound)?;
    let MethodData::PublicKeyJwk(ref jwk) = method.data() else {
      return Err(Error::NotPublicKeyJwk);
    };

    // Extract JwsAlgorithm.
    let alg: ProofAlgorithm = jwk
      .alg()
      .unwrap_or("")
      .parse()
      .map_err(|_| Error::InvalidJwpAlgorithm)?;

    let public_key: Jwk = jwk.try_into().map_err(|_| Error::NotPublicKeyJwk)?;

    let mut presentation_header = PresentationProtectedHeader::new(alg.into());
    presentation_header.set_nonce(options.nonce.clone());
    presentation_header.set_aud(options.audience.as_ref().map(|u| u.to_string()));

    presentation.set_presentation_header(presentation_header);

    let jwp_builder = presentation.builder();

    let presented_jwp = jwp_builder.build(&public_key).map_err(|_| Error::JwpBuildingError)?;

    Ok(
      presented_jwp
        .encode(SerializationType::COMPACT)
        .map_err(|e| Error::EncodingError(Box::new(e)))?,
    )
  }

  async fn create_credential_jpt<K, I, T>(
    &self,
    credential: &Credential<T>,
    storage: &Storage<K, I>,
    fragment: &str,
    options: &JwpCredentialOptions,
    custom_claims: Option<Object>,
  ) -> StorageResult<Jpt>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage,
    T: ToOwned<Owned = T> + Serialize + DeserializeOwned + Sync,
  {
    let jpt_claims = credential
      .serialize_jpt(custom_claims)
      .map_err(Error::ClaimsSerializationError)?;

    self
      .create_issued_jwp(storage, fragment, &jpt_claims, options)
      .await
      .map(Jpt::new)
  }

  async fn create_presentation_jpt(
    &self,
    presentation: &mut SelectiveDisclosurePresentation,
    method_id: &str,
    options: &JwpPresentationOptions,
  ) -> StorageResult<Jpt> {
    self
      .create_presented_jwp(presentation, method_id, options)
      .await
      .map(Jpt::new)
  }
}

// ====================================================================================================================
// IotaDocument
// ====================================================================================================================
#[cfg(feature = "iota-document")]
mod iota_document {
  use super::*;
  use identity_iota_core::IotaDocument;

  generate_method_for_document_type!(
    IotaDocument,
    ProofAlgorithm,
    JwkStorageBbsPlusExt,
    JwkStorageBbsPlusExt::generate_bbs,
    generate_method_iota_document
  );

  #[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
  #[cfg_attr(feature = "send-sync-storage", async_trait)]
  impl JwpDocumentExt for IotaDocument {
    async fn generate_method_jwp<K, I>(
      &mut self,
      storage: &Storage<K, I>,
      key_type: KeyType,
      alg: ProofAlgorithm,
      fragment: Option<&str>,
      scope: MethodScope,
    ) -> StorageResult<String>
    where
      K: JwkStorageBbsPlusExt,
      I: KeyIdStorage,
    {
      generate_method_iota_document(self, storage, key_type, alg, fragment, scope).await
    }

    async fn create_issued_jwp<K, I>(
      &self,
      storage: &Storage<K, I>,
      fragment: &str,
      jpt_claims: &JptClaims,
      options: &JwpCredentialOptions,
    ) -> StorageResult<String>
    where
      K: JwkStorageBbsPlusExt,
      I: KeyIdStorage,
    {
      self
        .core_document()
        .create_issued_jwp(storage, fragment, jpt_claims, options)
        .await
    }

    async fn create_presented_jwp(
      &self,
      presentation: &mut SelectiveDisclosurePresentation,
      method_id: &str,
      options: &JwpPresentationOptions,
    ) -> StorageResult<String> {
      self
        .core_document()
        .create_presented_jwp(presentation, method_id, options)
        .await
    }

    async fn create_credential_jpt<K, I, T>(
      &self,
      credential: &Credential<T>,
      storage: &Storage<K, I>,
      fragment: &str,
      options: &JwpCredentialOptions,
      custom_claims: Option<Object>,
    ) -> StorageResult<Jpt>
    where
      K: JwkStorageBbsPlusExt,
      I: KeyIdStorage,
      T: ToOwned<Owned = T> + Serialize + DeserializeOwned + Sync,
    {
      self
        .core_document()
        .create_credential_jpt(credential, storage, fragment, options, custom_claims)
        .await
    }

    async fn create_presentation_jpt(
      &self,
      presentation: &mut SelectiveDisclosurePresentation,
      method_id: &str,
      options: &JwpPresentationOptions,
    ) -> StorageResult<Jpt> {
      self
        .core_document()
        .create_presentation_jpt(presentation, method_id, options)
        .await
    }
  }
}
