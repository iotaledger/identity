// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use identity_storage::key_storage::bls::*;
use identity_storage::key_storage::JwkStorage;
use identity_storage::JwkGenOutput;
use identity_storage::JwkStorageBbsPlusExt;
use identity_storage::KeyId;
use identity_storage::KeyStorageError;
use identity_storage::KeyStorageErrorKind;
use identity_storage::KeyStorageResult;
use identity_storage::KeyType;
use identity_storage::ProofUpdateCtx;
use identity_verification::jwk::Jwk;
use iota_stronghold::procedures::FatalProcedureError;
use iota_stronghold::procedures::Products;
use iota_stronghold::procedures::Runner as _;
use iota_stronghold::Location;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use std::str::FromStr;
use zeroize::Zeroizing;
use zkryptium::bbsplus::keys::BBSplusSecretKey;

use crate::stronghold_key_type::*;
use crate::utils::*;
use crate::StrongholdStorage;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkStorageBbsPlusExt for StrongholdStorage {
  async fn generate_bbs(&self, key_type: KeyType, alg: ProofAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    let key_type = StrongholdKeyType::try_from(&key_type)?;

    if !matches!(key_type, StrongholdKeyType::Bls12381G2) {
      return Err(
        KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
          .with_custom_message(format!("{key_type} is not supported")),
      );
    }

    if !matches!(alg, ProofAlgorithm::BBS | ProofAlgorithm::BBS_SHAKE256) {
      return Err(KeyStorageErrorKind::UnsupportedProofAlgorithm.into());
    }

    // Get a key id that's not already used.
    let mut kid = random_key_id();
    while self.exists(&kid).await? {
      kid = random_key_id();
    }

    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;
    let target_key_location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      kid.to_string().as_bytes().to_vec(),
    );
    let jwk = client
      .exec_proc([], &target_key_location, |_| {
        let (sk, pk) = generate_bbs_keypair(alg).map_err(|e| FatalProcedureError::from(e.to_string()))?;
        let public_jwk = encode_bls_jwk(&sk, &pk, alg).1;

        Ok(Products {
          output: public_jwk,
          secret: Zeroizing::new(sk.to_bytes().to_vec()),
        })
      })
      .map_err(|e| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("Failed to execute stronghold procedure")
          .with_source(e)
      })?;

    persist_changes(self.as_secret_manager(), stronghold).await?;

    Ok(JwkGenOutput::new(kid, jwk))
  }

  async fn sign_bbs(
    &self,
    key_id: &KeyId,
    data: &[Vec<u8>],
    header: &[u8],
    public_key: &Jwk,
  ) -> KeyStorageResult<Vec<u8>> {
    // Extract the required alg from the given public key
    let alg = public_key
      .alg()
      .ok_or(KeyStorageErrorKind::UnsupportedProofAlgorithm)
      .and_then(|alg_str| {
        ProofAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedProofAlgorithm)
      })?;

    // Check `key_id` exists in store.
    if !self.exists(key_id).await? {
      return Err(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound));
    }

    let pk = expand_bls_jwk(public_key)
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(e))?
      .1;

    let sk_location = Location::Generic {
      vault_path: IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      record_path: key_id.to_string().as_bytes().to_vec(),
    };

    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;
    client
      .get_guards([sk_location], |[sk]| {
        let sk = BBSplusSecretKey::from_bytes(&sk.borrow()).map_err(|e| FatalProcedureError::from(e.to_string()))?;
        // Ensure `sk` and `pk` matches.
        if sk.public_key() != pk {
          return Err(FatalProcedureError::from(
            "`public_key` is not the public key of key with id `key_id`".to_owned(),
          ));
        }
        let signature_result =
          sign_bbs(alg, data, &sk, &pk, header).map_err(|e| FatalProcedureError::from(e.to_string()));
        // clean up `sk` to avoid leaking.
        drop(Zeroizing::new(sk.to_bytes()));
        signature_result
      })
      .map(|sig| sig.to_vec())
      .map_err(|e| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("Signature failed")
          .with_source(e)
      })
  }

  async fn update_signature(
    &self,
    key_id: &KeyId,
    public_key: &Jwk,
    signature: &[u8],
    ctx: ProofUpdateCtx,
  ) -> KeyStorageResult<Vec<u8>> {
    // Extract the required alg from the given public key
    let alg = public_key
      .alg()
      .ok_or(KeyStorageErrorKind::UnsupportedProofAlgorithm)
      .and_then(|alg_str| {
        ProofAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedProofAlgorithm)
      })?;

    // Check `key_id` exists in store.
    if !self.exists(key_id).await? {
      return Err(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound));
    }

    let sk_location = Location::Generic {
      vault_path: IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      record_path: key_id.to_string().as_bytes().to_vec(),
    };
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;

    client
      .get_guards([sk_location], |[sk]| {
        let sk = BBSplusSecretKey::from_bytes(&sk.borrow()).map_err(|e| FatalProcedureError::from(e.to_string()))?;
        let signature_update_result =
          update_bbs_signature(alg, signature, &sk, &ctx).map_err(|e| FatalProcedureError::from(e.to_string()));
        drop(Zeroizing::new(sk.to_bytes()));
        signature_update_result
      })
      .map_err(|e| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("Signature update failed")
          .with_source(e)
      })
  }
}
