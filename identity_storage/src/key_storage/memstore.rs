// Copyright 2020-2025 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;

use async_trait::async_trait;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519Signature;
use fastcrypto::traits::KeyPair as _;
use fastcrypto::traits::Signer;
use identity_verification::jose::jwk::EdCurve;
use identity_verification::jose::jwk::Jwk;
use identity_verification::jose::jwk::JwkType;
use identity_verification::jose::jws::JwsAlgorithm;
use identity_verification::jwk::BlsCurve;
use identity_verification::jwk::FromJwk as _;
use identity_verification::jwk::ToJwk as _;
use rand::distributions::DistString;
use shared::Shared;
use tokio::sync::RwLockReadGuard;
use tokio::sync::RwLockWriteGuard;

use super::jwk_gen_output::JwkGenOutput;
use super::KeyId;
use super::KeyStorageError;
use super::KeyStorageErrorKind;
use super::KeyStorageResult;
use super::KeyType;
use crate::key_storage::JwkStorage;

/// The map from key ids to JWKs.
type JwkKeyStore = HashMap<KeyId, Jwk>;

/// An insecure, in-memory [`JwkStorage`] implementation that serves as an example and may be used in tests.
#[derive(Debug)]
pub struct JwkMemStore {
  jwk_store: Shared<JwkKeyStore>,
}

impl JwkMemStore {
  /// Creates a new, empty `JwkMemStore` instance.
  pub fn new() -> Self {
    Self {
      jwk_store: Shared::new(HashMap::new()),
    }
  }

  /// Returns the number of items contained in the [`JwkMemStore`].
  pub async fn count(&self) -> usize {
    self.jwk_store.read().await.keys().count()
  }

  /// Gets the public key corresponding to the given `key_id`.
  pub async fn get_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
    self
      .jwk_store
      .read()
      .await
      .get(key_id)
      .cloned()
      .map(|jwk| jwk.to_public().unwrap_or(jwk))
      .ok_or_else(|| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))
  }
}

// Refer to the `JwkStorage` interface docs for high-level documentation of the individual methods.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkStorage for JwkMemStore {
  async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    let key_type: MemStoreKeyType = MemStoreKeyType::try_from(&key_type)?;

    check_key_alg_compatibility(key_type, &alg)?;

    let keypair = match key_type {
      MemStoreKeyType::Ed25519 => Ed25519KeyPair::generate(&mut rand::thread_rng()),
      other => {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message(format!("{other} is not supported")),
        );
      }
    };

    let kid: KeyId = random_key_id();

    let mut jwk: Jwk = keypair.to_jwk().map_err(|err| {
      KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        .with_custom_message("could not convert `Ed25519KeyPair` to `Jwk`")
        .with_source(err)
    })?;
    jwk.set_alg(alg.name());
    jwk.set_kid(jwk.thumbprint_sha256_b64());
    let public_jwk: Jwk = jwk.to_public().expect("should only panic if kty == oct");

    let mut jwk_store: RwLockWriteGuard<'_, JwkKeyStore> = self.jwk_store.write().await;
    jwk_store.insert(kid.clone(), jwk);

    Ok(JwkGenOutput::new(kid, public_jwk))
  }

  async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId> {
    let key_type = MemStoreKeyType::try_from(&jwk)?;

    if !jwk.is_private() {
      return Err(
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("expected a Jwk with all private key components set"),
      );
    }

    match jwk.alg() {
      Some(alg) => {
        let alg: JwsAlgorithm = JwsAlgorithm::from_str(alg)
          .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm).with_source(err))?;
        check_key_alg_compatibility(key_type, &alg)?;
      }
      None => {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            .with_custom_message("expected a Jwk with an `alg` parameter"),
        );
      }
    }

    if jwk.alg().is_none() {
      return Err(
        KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
          .with_custom_message("expected a Jwk with an `alg` parameter"),
      );
    }

    let key_id: KeyId = random_key_id();

    let mut jwk_store: RwLockWriteGuard<'_, JwkKeyStore> = self.jwk_store.write().await;

    jwk_store.insert(key_id.clone(), jwk);

    Ok(key_id)
  }

  async fn sign(&self, key_id: &KeyId, data: &[u8], public_key: &Jwk) -> KeyStorageResult<Vec<u8>> {
    let jwk_store: RwLockReadGuard<'_, JwkKeyStore> = self.jwk_store.read().await;

    // Extract the required alg from the given public key
    let alg = public_key
      .alg()
      .ok_or(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
      .and_then(|alg_str| {
        JwsAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
      })?;

    // Check that `kty` is `Okp` and `crv = Ed25519`.
    match alg {
      JwsAlgorithm::EdDSA => {
        let okp_params = public_key.try_okp_params().map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message(format!("expected a Jwk with Okp params in order to sign with {alg}"))
            .with_source(err)
        })?;
        if okp_params.crv != EdCurve::Ed25519.name() {
          return Err(
            KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(format!(
              "expected Jwk with Okp {} crv in order to sign with {alg}",
              EdCurve::Ed25519
            )),
          );
        }
      }
      other => {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            .with_custom_message(format!("{other} is not supported")),
        );
      }
    };

    // Obtain the corresponding private key and sign `data`.
    let jwk: &Jwk = jwk_store
      .get(key_id)
      .ok_or_else(|| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))?;
    let secret_key = Ed25519KeyPair::from_jwk(jwk).map_err(|err| {
      KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        .with_custom_message("could not convert `Jwk` to `Ed25519KeyPair`")
        .with_source(err)
    })?;
    Ok(Signer::<Ed25519Signature>::sign(&secret_key, data).as_ref().to_vec())
  }

  async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
    let mut jwk_store: RwLockWriteGuard<'_, JwkKeyStore> = self.jwk_store.write().await;

    jwk_store
      .remove(key_id)
      .map(|_| ())
      .ok_or_else(|| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))
  }

  async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
    let jwk_store: RwLockReadGuard<'_, JwkKeyStore> = self.jwk_store.read().await;
    Ok(jwk_store.contains_key(key_id))
  }
}

#[derive(Debug, Copy, Clone)]
enum MemStoreKeyType {
  Ed25519,
  BLS12381G2,
}

impl JwkMemStore {
  const ED25519_KEY_TYPE_STR: &'static str = "Ed25519";
  /// The Ed25519 key type.
  pub const ED25519_KEY_TYPE: KeyType = KeyType::from_static_str(Self::ED25519_KEY_TYPE_STR);

  const BLS12381G2_KEY_TYPE_STR: &'static str = "BLS12381G2";
  /// The BLS12381G2 key type
  pub const BLS12381G2_KEY_TYPE: KeyType = KeyType::from_static_str(Self::BLS12381G2_KEY_TYPE_STR);

  const PQ_KEY_TYPE_STR: &'static str = "AKP";
  /// ML-DSA algorithms key types;
  pub const PQ_KEY_TYPE: KeyType = KeyType::from_static_str(Self::PQ_KEY_TYPE_STR);
}

impl MemStoreKeyType {
  const fn name(&self) -> &'static str {
    match self {
      MemStoreKeyType::Ed25519 => JwkMemStore::ED25519_KEY_TYPE_STR,
      MemStoreKeyType::BLS12381G2 => JwkMemStore::BLS12381G2_KEY_TYPE_STR,
    }
  }
}

impl Display for MemStoreKeyType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.name())
  }
}

impl TryFrom<&KeyType> for MemStoreKeyType {
  type Error = KeyStorageError;

  fn try_from(value: &KeyType) -> Result<Self, Self::Error> {
    match value.as_str() {
      JwkMemStore::ED25519_KEY_TYPE_STR => Ok(MemStoreKeyType::Ed25519),
      JwkMemStore::BLS12381G2_KEY_TYPE_STR => Ok(MemStoreKeyType::BLS12381G2),
      _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)),
    }
  }
}

impl TryFrom<&Jwk> for MemStoreKeyType {
  type Error = KeyStorageError;

  fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
    match jwk.kty() {
      JwkType::Okp => {
        let okp_params = jwk.try_okp_params().map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message("expected Okp parameters for a JWK with `kty` Okp")
            .with_source(err)
        })?;
        match okp_params.try_ed_curve().map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message("only Ed curves are supported for signing")
            .with_source(err)
        })? {
          EdCurve::Ed25519 => Ok(MemStoreKeyType::Ed25519),
          curve => Err(
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
              .with_custom_message(format!("{curve} not supported")),
          ),
        }
      }
      JwkType::Ec => {
        let ec_params = jwk.try_ec_params().map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message("expected EC parameters for a JWK with `kty` Ec")
            .with_source(err)
        })?;
        match ec_params.try_bls_curve().map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message("only Ed curves are supported for signing")
            .with_source(err)
        })? {
          BlsCurve::BLS12381G2 => Ok(MemStoreKeyType::BLS12381G2),
          curve => Err(
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
              .with_custom_message(format!("{curve} not supported")),
          ),
        }
      }
      other => Err(
        KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
          .with_custom_message(format!("Jwk `kty` {other} not supported")),
      ),
    }
  }
}

impl Default for JwkMemStore {
  fn default() -> Self {
    Self::new()
  }
}

/// Generate a random alphanumeric string of len 32.
fn random_key_id() -> KeyId {
  KeyId::new(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32))
}

/// Check that the key type can be used with the algorithm.
fn check_key_alg_compatibility(key_type: MemStoreKeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()> {
  match (key_type, alg) {
    (MemStoreKeyType::Ed25519, JwsAlgorithm::EdDSA) => Ok(()),
    (key_type, alg) => Err(
      KeyStorageError::new(crate::key_storage::KeyStorageErrorKind::KeyAlgorithmMismatch)
        .with_custom_message(format!("`cannot use key type `{key_type}` with algorithm `{alg}`")),
    ),
  }
}

#[cfg(feature = "pqc-liboqs")]
mod pqc_liboqs {
  use async_trait::async_trait;
  use identity_verification::jose::jwk::Jwk;
  use identity_verification::jose::jwk::JwkType;
  use identity_verification::jose::jws::JwsAlgorithm;
  use identity_verification::jwk::JwkParams;
  use identity_verification::jwk::PostQuantumJwk;
  use identity_verification::jwu;
  use oqs::sig::Algorithm;
  use oqs::sig::Sig;
  use std::str::FromStr;
  use tokio::sync::RwLockReadGuard;
  use tokio::sync::RwLockWriteGuard;

  use super::random_key_id;
  use super::JwkKeyStore;
  use super::JwkMemStore;
  use super::KeyId;
  use super::KeyStorageError;
  use super::KeyStorageErrorKind;
  use super::KeyStorageResult;
  use super::KeyType;
  use crate::key_storage::jwk_storage_pqc::JwkStoragePQ;
  use crate::JwkGenOutput;

  fn check_pq_alg_compatibility(alg: &JwsAlgorithm) -> KeyStorageResult<Algorithm> {
    match alg {
      JwsAlgorithm::ML_DSA_44 => Ok(Algorithm::MlDsa44),
      JwsAlgorithm::ML_DSA_65 => Ok(Algorithm::MlDsa65),
      JwsAlgorithm::ML_DSA_87 => Ok(Algorithm::MlDsa87),
      JwsAlgorithm::SLH_DSA_SHA2_128s => Ok(Algorithm::SphincsSha2128sSimple),
      JwsAlgorithm::SLH_DSA_SHAKE_128s => Ok(Algorithm::SphincsShake128sSimple),
      JwsAlgorithm::SLH_DSA_SHA2_128f => Ok(Algorithm::SphincsSha2128fSimple),

      JwsAlgorithm::SLH_DSA_SHAKE_128f => Ok(Algorithm::SphincsShake128fSimple),
      JwsAlgorithm::SLH_DSA_SHA2_192s => Ok(Algorithm::SphincsSha2192sSimple),
      JwsAlgorithm::SLH_DSA_SHAKE_192s => Ok(Algorithm::SphincsShake192sSimple),
      JwsAlgorithm::SLH_DSA_SHA2_192f => Ok(Algorithm::SphincsSha2192fSimple),
      JwsAlgorithm::SLH_DSA_SHAKE_192f => Ok(Algorithm::SphincsShake192fSimple),
      JwsAlgorithm::SLH_DSA_SHA2_256s => Ok(Algorithm::SphincsSha2256sSimple),
      JwsAlgorithm::SLH_DSA_SHAKE_256s => Ok(Algorithm::SphincsShake256sSimple),
      JwsAlgorithm::SLH_DSA_SHA2_256f => Ok(Algorithm::SphincsSha2256fSimple),
      JwsAlgorithm::SLH_DSA_SHAKE_256f => Ok(Algorithm::SphincsShake256fSimple),

      JwsAlgorithm::FALCON512 => Ok(Algorithm::Falcon512),
      JwsAlgorithm::FALCON1024 => Ok(Algorithm::Falcon1024),
      other => Err(
        KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
          .with_custom_message(format!("{other} is not supported")),
      ),
    }
  }

  /// JwkStoragePQ implementation for JwkMemStore based on liboqs.
  #[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
  #[cfg_attr(feature = "send-sync-storage", async_trait)]
  impl JwkStoragePQ for JwkMemStore {
    async fn generate_pq_key(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
      if key_type != JwkMemStore::PQ_KEY_TYPE {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message(format!("unsupported key type {key_type}")),
        );
      }

      let oqs_alg = check_pq_alg_compatibility(&alg)?;
      oqs::init();

      let scheme = Sig::new(oqs_alg).map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("signature scheme init failed".to_string())
          .with_source(err)
      })?;
      let (pk, sk) = scheme.keypair().map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("keypair generation failed!".to_string())
          .with_source(err)
      })?;

      let kid: KeyId = random_key_id();

      let public = jwu::encode_b64(pk.into_vec());
      let private = jwu::encode_b64(sk.into_vec());

      let mut jwk_params = match alg {
        JwsAlgorithm::ML_DSA_44 => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::ML_DSA_65 => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::ML_DSA_87 => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHA2_128s => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHAKE_128s => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHA2_128f => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHAKE_128f => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHA2_192s => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHAKE_192s => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHA2_192f => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHAKE_192f => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHA2_256s => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHAKE_256s => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHA2_256f => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::SLH_DSA_SHAKE_256f => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::FALCON512 => JwkParams::new(JwkType::Akp),
        JwsAlgorithm::FALCON1024 => JwkParams::new(JwkType::Akp),
        other => {
          return Err(
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
              .with_custom_message(format!("{other} is not supported")),
          );
        }
      };

      match jwk_params {
        JwkParams::Akp(ref mut params) => {
          params.public = public;
          params.private = Some(private);
        }
        _ => {
          return Err(
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).with_custom_message("Should NOT happen!"),
          )
        }
      }

      let mut jwk = Jwk::from_params(jwk_params);

      jwk.set_alg(alg.name());
      jwk.set_kid(jwk.thumbprint_sha256_b64());
      let public_jwk: Jwk = jwk.to_public().expect("should only panic if kty == oct");

      let mut jwk_store: RwLockWriteGuard<'_, JwkKeyStore> = self.jwk_store.write().await;
      jwk_store.insert(kid.clone(), jwk);

      Ok(JwkGenOutput::new(kid, public_jwk))
    }

    async fn pq_sign(
      &self,
      key_id: &KeyId,
      data: &[u8],
      public_key: &PostQuantumJwk,
      ctx: Option<&[u8]>,
    ) -> KeyStorageResult<Vec<u8>> {
      let jwk_store: RwLockReadGuard<'_, JwkKeyStore> = self.jwk_store.read().await;

      // Extract the required alg from the given public key
      let alg = public_key
        .alg()
        .ok_or(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
        .and_then(|alg_str| {
          JwsAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
        })?;

      let oqs_alg = check_pq_alg_compatibility(&alg)?;

      // Check that `kty` is `AKP`.
      match alg {
        JwsAlgorithm::ML_DSA_44
        | JwsAlgorithm::ML_DSA_65
        | JwsAlgorithm::ML_DSA_87
        | JwsAlgorithm::SLH_DSA_SHA2_128s
        | JwsAlgorithm::SLH_DSA_SHAKE_128s
        | JwsAlgorithm::SLH_DSA_SHA2_128f
        | JwsAlgorithm::SLH_DSA_SHAKE_128f
        | JwsAlgorithm::SLH_DSA_SHA2_192s
        | JwsAlgorithm::SLH_DSA_SHAKE_192s
        | JwsAlgorithm::SLH_DSA_SHA2_192f
        | JwsAlgorithm::SLH_DSA_SHAKE_192f
        | JwsAlgorithm::SLH_DSA_SHA2_256s
        | JwsAlgorithm::SLH_DSA_SHAKE_256s
        | JwsAlgorithm::SLH_DSA_SHA2_256f
        | JwsAlgorithm::SLH_DSA_SHAKE_256f
        | JwsAlgorithm::FALCON512
        | JwsAlgorithm::FALCON1024 => public_key.try_akp_params().map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message(format!("expected a Jwk with AKP params in order to sign with {alg}"))
            .with_source(err)
        })?,
        other => {
          return Err(
            KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
              .with_custom_message(format!("{other} is not supported")),
          );
        }
      };

      // Obtain the corresponding private key and sign `data`.
      let jwk: &Jwk = jwk_store
        .get(key_id)
        .ok_or_else(|| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))?;

      let params = jwk.try_akp_params().unwrap();

      let sk_bytes = params
        .private
        .as_deref()
        .map(jwu::decode_b64)
        .ok_or_else(|| {
          KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("expected Jwk `private` param to be present")
        })?
        .map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("unable to decode `private` param")
            .with_source(err)
        })?;
      oqs::init();

      let scheme = Sig::new(oqs_alg).map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("signature scheme init failed".to_string())
          .with_source(err)
      })?;

      let secret_key = scheme.secret_key_from_bytes(&sk_bytes).ok_or(
        KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("invalid private key".to_string()),
      )?;

      let signature: oqs::sig::Signature;

      if let Some(ctx) = ctx {
        if !scheme.has_ctx_str_support() {
          return Err(
            KeyStorageError::new(KeyStorageErrorKind::Unspecified)
              .with_custom_message("signature with ctx is not supported with this algorithm".to_string()),
          );
        }
        signature = scheme.sign_with_ctx_str(data, ctx, secret_key).map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("signature computation failed".to_string())
            .with_source(err)
        })?;
      } else {
        signature = scheme.sign(data, secret_key).map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("signature computation failed".to_string())
            .with_source(err)
        })?;
      }

      Ok(signature.into_vec())
    }
  }
}

#[cfg(feature = "jpt-bbs-plus")]
mod bbs_plus_impl {
  use std::str::FromStr as _;

  use crate::key_storage::bls::encode_bls_jwk;
  use crate::key_storage::bls::expand_bls_jwk;
  use crate::key_storage::bls::generate_bbs_keypair;
  use crate::key_storage::bls::sign_bbs;
  use crate::key_storage::bls::update_bbs_signature;
  use crate::JwkGenOutput;
  use crate::JwkMemStore;
  use crate::JwkStorageBbsPlusExt;
  use crate::KeyId;
  use crate::KeyStorageError;
  use crate::KeyStorageErrorKind;
  use crate::KeyStorageResult;
  use crate::KeyType;
  use crate::ProofUpdateCtx;
  use async_trait::async_trait;
  use identity_verification::jwk::BlsCurve;
  use identity_verification::jwk::Jwk;
  use jsonprooftoken::jpa::algs::ProofAlgorithm;

  use super::random_key_id;

  /// JwkStorageBbsPlusExt implementation for JwkMemStore
  #[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
  #[cfg_attr(feature = "send-sync-storage", async_trait)]
  impl JwkStorageBbsPlusExt for JwkMemStore {
    async fn generate_bbs(&self, key_type: KeyType, alg: ProofAlgorithm) -> KeyStorageResult<JwkGenOutput> {
      if key_type != JwkMemStore::BLS12381G2_KEY_TYPE {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message(format!("unsupported key type {key_type}")),
        );
      }

      let (private_key, public_key) = generate_bbs_keypair(alg)?;
      let (jwk, public_jwk) = encode_bls_jwk(&private_key, &public_key, alg);

      let kid: KeyId = random_key_id();
      let mut jwk_store = self.jwk_store.write().await;
      jwk_store.insert(kid.clone(), jwk);

      Ok(JwkGenOutput::new(kid, public_jwk))
    }

    async fn sign_bbs(
      &self,
      key_id: &KeyId,
      data: &[Vec<u8>],
      header: &[u8],
      public_key: &Jwk,
    ) -> KeyStorageResult<Vec<u8>> {
      let jwk_store = self.jwk_store.read().await;

      // Extract the required alg from the given public key
      let alg = public_key
        .alg()
        .and_then(|alg_str| ProofAlgorithm::from_str(alg_str).ok())
        .ok_or(KeyStorageErrorKind::UnsupportedProofAlgorithm)?;

      // Check the provided JWK represents a BLS12381G2 key.
      if !public_key
        .try_ec_params()
        .map(|ec| ec.crv == BlsCurve::BLS12381G2.to_string())
        .unwrap_or(false)
      {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message(format!("expected a key from the {} curve", BlsCurve::BLS12381G2)),
        );
      }

      // Obtain the corresponding private key.
      let jwk: &Jwk = jwk_store.get(key_id).ok_or(KeyStorageErrorKind::KeyNotFound)?;
      let (sk, pk) = expand_bls_jwk(jwk)?;

      sign_bbs(alg, data, &sk.expect("jwk is private"), &pk, header)
    }

    async fn update_signature(
      &self,
      key_id: &KeyId,
      public_key: &Jwk,
      signature: &[u8],
      ctx: ProofUpdateCtx,
    ) -> KeyStorageResult<Vec<u8>> {
      let jwk_store = self.jwk_store.read().await;

      // Extract the required alg from the given public key
      let alg = public_key
        .alg()
        .ok_or(KeyStorageErrorKind::UnsupportedProofAlgorithm)
        .and_then(|alg_str| {
          ProofAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedProofAlgorithm)
        })?;

      // Check the provided JWK represents a BLS12381G2 key.
      if !public_key
        .try_ec_params()
        .map(|ec| ec.crv == BlsCurve::BLS12381G2.to_string())
        .unwrap_or(false)
      {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
            .with_custom_message(format!("expected a key from the {} curve", BlsCurve::BLS12381G2)),
        );
      }

      // Obtain the corresponding private key.
      let jwk = jwk_store.get(key_id).ok_or(KeyStorageErrorKind::KeyNotFound)?;
      let sk = expand_bls_jwk(jwk)?.0.expect("jwk is private");

      // Update the signature.
      update_bbs_signature(alg, signature, &sk, &ctx)
    }
  }
}
pub(crate) mod shared {
  use core::fmt::Debug;
  use core::fmt::Formatter;
  use tokio::sync::RwLock;
  use tokio::sync::RwLockReadGuard;
  use tokio::sync::RwLockWriteGuard;

  #[derive(Default)]
  pub(crate) struct Shared<T>(RwLock<T>);

  impl<T> Shared<T> {
    pub(crate) fn new(data: T) -> Self {
      Self(RwLock::new(data))
    }

    pub(crate) async fn read(&self) -> RwLockReadGuard<'_, T> {
      self.0.read().await
    }

    pub(crate) async fn write(&self) -> RwLockWriteGuard<'_, T> {
      self.0.write().await
    }
  }

  impl<T: Debug> Debug for Shared<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
      Debug::fmt(&self.0, f)
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::key_storage::tests::utils::generate_ed25519;
  use fastcrypto::ed25519::Ed25519PublicKey;
  use fastcrypto::traits::ToFromBytes as _;
  use fastcrypto::traits::VerifyingKey as _;
  use identity_verification::jose::jwk::EcCurve;
  use identity_verification::jose::jwk::JwkParamsEc;
  use identity_verification::jwk::FromJwk as _;

  use super::*;

  #[tokio::test]
  async fn generate_and_sign() {
    let test_msg: &[u8] = b"test";
    let store: JwkMemStore = JwkMemStore::new();

    let JwkGenOutput { key_id, jwk } = store
      .generate(JwkMemStore::ED25519_KEY_TYPE, JwsAlgorithm::EdDSA)
      .await
      .unwrap();

    let signature = store.sign(&key_id, test_msg, &jwk.to_public().unwrap()).await.unwrap();

    let public_key = Ed25519PublicKey::from_jwk(&jwk).unwrap();
    let signature = Ed25519Signature::from_bytes(&signature).unwrap();

    assert!(public_key.verify(test_msg, &signature).is_ok());
    assert!(store.exists(&key_id).await.unwrap());
    store.delete(&key_id).await.unwrap();
  }

  #[tokio::test]
  async fn insert() {
    let store: JwkMemStore = JwkMemStore::new();

    let key_pair = generate_ed25519();
    let mut jwk: Jwk = key_pair.to_jwk().unwrap();

    // INVALID: Inserting a Jwk without an `alg` parameter should fail.
    let err = store.insert(jwk.clone()).await.unwrap_err();
    assert!(matches!(err.kind(), KeyStorageErrorKind::UnsupportedSignatureAlgorithm));

    // VALID: Inserting a Jwk with all private key components set should succeed.
    jwk.set_alg(JwsAlgorithm::EdDSA.name());
    store.insert(jwk.clone()).await.unwrap();

    // INVALID: Inserting a Jwk with all private key components unset should fail.
    let err = store.insert(jwk.to_public().unwrap()).await.unwrap_err();
    assert!(matches!(err.kind(), KeyStorageErrorKind::Unspecified))
  }

  #[tokio::test]
  async fn exists() {
    let store: JwkMemStore = JwkMemStore::new();
    assert!(!store.exists(&KeyId::new("non-existent-id")).await.unwrap());
  }

  #[tokio::test]
  async fn incompatible_key_type() {
    let store: JwkMemStore = JwkMemStore::new();

    let mut ec_params = JwkParamsEc::new();
    ec_params.crv = EcCurve::P256.name().to_string();
    ec_params.x = String::new();
    ec_params.y = String::new();
    ec_params.d = Some(String::new());
    let jwk_ec = Jwk::from_params(ec_params);

    let err = store.insert(jwk_ec).await.unwrap_err();
    assert!(matches!(err.kind(), KeyStorageErrorKind::UnsupportedKeyType));
  }

  #[tokio::test]
  async fn incompatible_key_alg() {
    let store: JwkMemStore = JwkMemStore::new();

    let key_pair = generate_ed25519();
    let mut jwk: Jwk = key_pair.to_jwk().unwrap();
    jwk.set_alg(JwsAlgorithm::ES256.name());

    // INVALID: Inserting an Ed25519 key with the ES256 alg is not compatible.
    let err = store.insert(jwk.clone()).await.unwrap_err();
    assert!(matches!(err.kind(), KeyStorageErrorKind::KeyAlgorithmMismatch));
  }
}
