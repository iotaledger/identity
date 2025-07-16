// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use crate::JwkGenOutput;
use crate::JwkStorage;
#[cfg(feature = "jpt-bbs-plus")]
use crate::JwkStorageBbsPlusExt;
use crate::JwkStorageDocumentError as Error;
#[cfg(feature = "pqc")]
use crate::JwkStoragePQ;
#[cfg(feature = "hybrid")]
use crate::KeyId;
use crate::KeyIdStorage;
use crate::KeyType;
use crate::MethodDigest;
use async_trait::async_trait;
#[cfg(feature = "hybrid")]
use identity_did::DIDCompositeJwk;
use identity_did::DIDJwk;
use identity_document::document::CoreDocument;
#[cfg(feature = "hybrid")]
use identity_verification::jwk::CompositeAlgId;
#[cfg(feature = "hybrid")]
use identity_verification::jwk::CompositeJwk;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu::encode_b64_json;
#[cfg(feature = "jpt-bbs-plus")]
use jsonprooftoken::jpa::algs::ProofAlgorithm;

use super::Storage;
use super::StorageResult;

/// Extension trait for creating JWK-based DID documents for traditional, zk, PQ and hybrid keys
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait DidJwkDocumentExt {
  /// Create a JWK-based DID documents with traditional keys. Returns the DID document and the fragment
  async fn new_did_jwk<K, I>(
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: JwsAlgorithm,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStorage,
    I: KeyIdStorage;
  /// Create a JWK-based DID documents with PQ keys. Returns the DID document and the fragment
  #[cfg(feature = "pqc")]
  async fn new_did_jwk_pqc<K, I>(
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: JwsAlgorithm,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStoragePQ,
    I: KeyIdStorage;
  /// Create a JWK-based DID documents with zk keys. Returns the DID document and the fragment
  #[cfg(feature = "jpt-bbs-plus")]
  async fn new_did_jwk_zk<K, I>(
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: ProofAlgorithm,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage;

  /// Create a JWK-based DID documents with hybrid keys. Returns the DID document and the fragment
  #[cfg(feature = "hybrid")]
  async fn new_did_compositejwk<K, I>(
    storage: &Storage<K, I>,
    alg: identity_verification::jwk::CompositeAlgId,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStorage + JwkStoragePQ,
    I: KeyIdStorage;
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl DidJwkDocumentExt for CoreDocument {
  async fn new_did_jwk<K, I>(
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: JwsAlgorithm,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStorage,
    I: KeyIdStorage,
  {
    let JwkGenOutput { key_id, jwk } = K::generate(storage.key_storage(), key_type, alg)
      .await
      .map_err(Error::KeyStorageError)?;

    let b64 = encode_b64_json(&jwk).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let did =
      DIDJwk::parse(format!("{}{}", "did:jwk:", b64).as_str()).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let document = CoreDocument::expand_did_jwk(did).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let fragment = "0";

    let verification_method = document
      .resolve_method(fragment, None)
      .ok_or(identity_verification::Error::MissingIdFragment)
      .map_err(Error::VerificationMethodConstructionError)?;

    let method_digest = MethodDigest::new(verification_method).map_err(Error::MethodDigestConstructionError)?;

    I::insert_key_id(storage.key_id_storage(), method_digest, key_id.clone())
      .await
      .map_err(Error::KeyIdStorageError)?;

    Ok((document, fragment.to_string()))
  }

  #[cfg(feature = "pqc")]
  async fn new_did_jwk_pqc<K, I>(
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: JwsAlgorithm,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStoragePQ,
    I: KeyIdStorage,
  {
    let JwkGenOutput { key_id, jwk } = K::generate_pq_key(storage.key_storage(), key_type, alg)
      .await
      .map_err(Error::KeyStorageError)?;

    let b64 = encode_b64_json(&jwk).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let did =
      DIDJwk::parse(format!("{}{}", "did:jwk:", b64).as_str()).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let document = CoreDocument::expand_did_jwk(did).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let fragment = "0";

    let verification_method = document
      .resolve_method(fragment, None)
      .ok_or(identity_verification::Error::MissingIdFragment)
      .map_err(Error::VerificationMethodConstructionError)?;

    let method_digest = MethodDigest::new(verification_method).map_err(Error::MethodDigestConstructionError)?;

    I::insert_key_id(storage.key_id_storage(), method_digest, key_id.clone())
      .await
      .map_err(Error::KeyIdStorageError)?;

    Ok((document, fragment.to_string()))
  }

  #[cfg(feature = "jpt-bbs-plus")]
  async fn new_did_jwk_zk<K, I>(
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: ProofAlgorithm,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStorageBbsPlusExt,
    I: KeyIdStorage,
  {
    let JwkGenOutput { key_id, jwk } = K::generate_bbs(storage.key_storage(), key_type, alg)
      .await
      .map_err(Error::KeyStorageError)?;

    let b64 = encode_b64_json(&jwk).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let did =
      DIDJwk::parse(format!("{}{}", "did:jwk:", b64).as_str()).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let document = CoreDocument::expand_did_jwk(did).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let fragment = "0";

    let verification_method = document
      .resolve_method(fragment, None)
      .ok_or(identity_verification::Error::MissingIdFragment)
      .map_err(Error::VerificationMethodConstructionError)?;

    let method_digest = MethodDigest::new(verification_method).map_err(Error::MethodDigestConstructionError)?;

    I::insert_key_id(storage.key_id_storage(), method_digest, key_id.clone())
      .await
      .map_err(Error::KeyIdStorageError)?;

    Ok((document, fragment.to_string()))
  }

  #[cfg(feature = "hybrid")]
  async fn new_did_compositejwk<K, I>(
    storage: &Storage<K, I>,
    alg: CompositeAlgId,
  ) -> StorageResult<(CoreDocument, String)>
  where
    K: JwkStorage + JwkStoragePQ,
    I: KeyIdStorage,
  {
    use identity_verification::jwk::PostQuantumJwk;
    use identity_verification::jwk::TraditionalJwk;

    let (pq_key_type, pq_alg, trad_key_type, trad_alg) = match alg {
      CompositeAlgId::IdMldsa44Ed25519 => (
        KeyType::from_static_str("AKP"),
        JwsAlgorithm::ML_DSA_44,
        KeyType::from_static_str("Ed25519"),
        JwsAlgorithm::EdDSA,
      ),
      CompositeAlgId::IdMldsa65Ed25519 => (
        KeyType::from_static_str("AKP"),
        JwsAlgorithm::ML_DSA_65,
        KeyType::from_static_str("Ed25519"),
        JwsAlgorithm::EdDSA,
      ),
      _ => {
        return Err(Error::InvalidJwsAlgorithm);
      }
    };

    let JwkGenOutput {
      key_id: t_key_id,
      jwk: t_jwk,
    } = K::generate(storage.key_storage(), trad_key_type, trad_alg)
      .await
      .map_err(Error::KeyStorageError)?;

    let JwkGenOutput {
      key_id: pq_key_id,
      jwk: pq_jwk,
    } = K::generate_pq_key(storage.key_storage(), pq_key_type, pq_alg)
      .await
      .map_err(Error::KeyStorageError)?;

    let key_id = KeyId::new(format!("{}~{}", t_key_id.as_str(), pq_key_id.as_str()));

    let pq_jwk = PostQuantumJwk::try_from(pq_jwk).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let traditional_jwk = TraditionalJwk::try_from(t_jwk).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let composite_pk = CompositeJwk::new(alg, traditional_jwk, pq_jwk);

    let b64 = encode_b64_json(&composite_pk).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let did = DIDCompositeJwk::parse(format!("{}{}", "did:compositejwk:", b64).as_str())
      .map_err(|err| Error::EncodingError(Box::new(err)))?;

    let document = CoreDocument::expand_did_compositejwk(did).map_err(|err| Error::EncodingError(Box::new(err)))?;

    let fragment = "0";

    let verification_method = document
      .resolve_method(fragment, None)
      .ok_or(identity_verification::Error::MissingIdFragment)
      .map_err(Error::VerificationMethodConstructionError)?;

    let method_digest = MethodDigest::new(verification_method).map_err(Error::MethodDigestConstructionError)?;

    I::insert_key_id(storage.key_id_storage(), method_digest, key_id.clone())
      .await
      .map_err(Error::KeyIdStorageError)?;

    Ok((document, fragment.to_string()))
  }
}
