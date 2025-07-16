// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

mod stronghold_jwk_storage;
#[cfg(any(feature = "bbs-plus", test))]
mod stronghold_jwk_storage_bbs_plus_ext;
mod stronghold_key_id;

use std::sync::Arc;

#[cfg(feature = "bbs-plus")]
use identity_storage::key_storage::bls::encode_bls_jwk;
use identity_storage::KeyId;
use identity_storage::KeyStorageError;
use identity_storage::KeyStorageErrorKind;
use identity_storage::KeyStorageResult;
use identity_verification::jwk::EdCurve;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsOkp;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
#[cfg(feature = "bbs-plus")]
use iota_stronghold::procedures::FatalProcedureError;
use iota_stronghold::procedures::KeyType as ProceduresKeyType;
#[cfg(feature = "bbs-plus")]
use iota_stronghold::procedures::Runner as _;
use iota_stronghold::procedures::StrongholdProcedure;
use iota_stronghold::Location;
use iota_stronghold::Stronghold;
#[cfg(feature = "bbs-plus")]
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use tokio::sync::MutexGuard;
#[cfg(feature = "bbs-plus")]
use zeroize::Zeroizing;
#[cfg(feature = "bbs-plus")]
use zkryptium::bbsplus::keys::BBSplusSecretKey;

use crate::stronghold_key_type::StrongholdKeyType;
use crate::utils::get_client;
use crate::utils::IDENTITY_VAULT_PATH;

/// Wrapper around a [`StrongholdSecretManager`] that implements the [`KeyIdStorage`](crate::KeyIdStorage)
/// and [`JwkStorage`](crate::JwkStorage) interfaces.
#[derive(Clone, Debug)]
pub struct StrongholdStorage(Arc<SecretManager>);

impl StrongholdStorage {
  /// Creates a new [`StrongholdStorage`].
  pub fn new(stronghold_secret_manager: StrongholdSecretManager) -> Self {
    Self(Arc::new(SecretManager::Stronghold(stronghold_secret_manager)))
  }

  /// Shared reference to the inner [`SecretManager`].
  pub fn as_secret_manager(&self) -> &SecretManager {
    self.0.as_ref()
  }

  /// Acquire lock of the inner [`Stronghold`].
  pub(crate) async fn get_stronghold(&self) -> MutexGuard<'_, Stronghold> {
    match *self.0 {
      SecretManager::Stronghold(ref stronghold) => stronghold.inner().await,
      _ => unreachable!("secret manager can be only constructed from stronghold"),
    }
  }

  async fn get_ed25519_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;

    let location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      key_id.to_string().as_bytes().to_vec(),
    );

    let public_key_procedure = iota_stronghold::procedures::PublicKey {
      ty: ProceduresKeyType::Ed25519,
      private_key: location,
    };

    let procedure_result = client
      .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure))
      .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound).with_source(err))?;

    let public_key: Vec<u8> = procedure_result.into();

    let mut params = JwkParamsOkp::new();
    params.x = jwu::encode_b64(public_key);
    EdCurve::Ed25519.name().clone_into(&mut params.crv);
    let mut jwk: Jwk = Jwk::from_params(params);
    jwk.set_alg(JwsAlgorithm::EdDSA.name());
    jwk.set_kid(jwk.thumbprint_sha256_b64());

    Ok(jwk)
  }

  #[cfg(feature = "bbs-plus")]
  async fn get_bls12381g2_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;

    let location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      key_id.to_string().as_bytes().to_vec(),
    );

    client
      .get_guards([location], |[sk]| {
        let sk = BBSplusSecretKey::from_bytes(&sk.borrow()).map_err(|e| FatalProcedureError::from(e.to_string()))?;
        let pk = sk.public_key();
        let public_jwk = encode_bls_jwk(&sk, &pk, ProofAlgorithm::BLS12381_SHA256).1;

        drop(Zeroizing::new(sk.to_bytes()));
        Ok(public_jwk)
      })
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound).with_source(e))
  }

  /// Attempts to retrieve the public key corresponding to the key of id `key_id`,
  /// returning it as a `key_type` encoded public JWK.
  pub async fn get_public_key_with_type(&self, key_id: &KeyId, key_type: StrongholdKeyType) -> KeyStorageResult<Jwk> {
    match key_type {
      StrongholdKeyType::Ed25519 => self.get_ed25519_public_key(key_id).await,
      #[cfg(feature = "bbs-plus")]
      StrongholdKeyType::Bls12381G2 => self.get_bls12381g2_public_key(key_id).await,
      #[allow(unreachable_patterns)]
      _ => Err(KeyStorageErrorKind::UnsupportedKeyType.into()),
    }
  }

  /// Retrieve the public key corresponding to `key_id`.
  #[deprecated(since = "1.3.0", note = "use `get_public_key_with_type` instead")]
  pub async fn get_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;

    let location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      key_id.to_string().as_bytes().to_vec(),
    );

    let public_key_procedure = iota_stronghold::procedures::PublicKey {
      ty: ProceduresKeyType::Ed25519,
      private_key: location,
    };

    let procedure_result = client
      .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure))
      .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound).with_source(err))?;

    let public_key: Vec<u8> = procedure_result.into();

    let mut params = JwkParamsOkp::new();
    params.x = jwu::encode_b64(public_key);
    EdCurve::Ed25519.name().clone_into(&mut params.crv);
    let mut jwk: Jwk = Jwk::from_params(params);
    jwk.set_alg(JwsAlgorithm::EdDSA.name());
    jwk.set_kid(jwk.thumbprint_sha256_b64());

    Ok(jwk)
  }
}
