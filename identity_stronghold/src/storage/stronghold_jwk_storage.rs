// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Wrapper around [`StrongholdSecretManager`](StrongholdSecretManager).

use async_trait::async_trait;
use identity_storage::key_storage::JwkStorage;
use identity_storage::JwkGenOutput;
use identity_storage::KeyId;
use identity_storage::KeyStorageError;
use identity_storage::KeyStorageErrorKind;
use identity_storage::KeyStorageResult;
use identity_storage::KeyType;
use identity_verification::jwk::EdCurve;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsOkp;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use iota_stronghold::procedures::Ed25519Sign;
use iota_stronghold::procedures::GenerateKey;
use iota_stronghold::procedures::KeyType as ProceduresKeyType;
use iota_stronghold::procedures::StrongholdProcedure;
use iota_stronghold::Location;
use std::str::FromStr;

use crate::ed25519;
use crate::stronghold_key_type::StrongholdKeyType;
use crate::utils::*;
use crate::StrongholdStorage;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkStorage for StrongholdStorage {
  async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    let stronghold = self.get_stronghold().await;

    let client = get_client(&stronghold)?;
    let key_type = StrongholdKeyType::try_from(&key_type)?;
    check_key_alg_compatibility(key_type, &alg)?;

    let keytype: ProceduresKeyType = match key_type {
      StrongholdKeyType::Ed25519 => ProceduresKeyType::Ed25519,
      StrongholdKeyType::Bls12381G2 => {
        return Err(
          KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(format!(
            "`{key_type}` is supported but `JwkStorageBbsPlusExt::generate_bbs` should be called instead."
          )),
        )
      }
    };

    let key_id: KeyId = random_key_id();
    let location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      key_id.to_string().as_bytes().to_vec(),
    );

    let generate_key_procedure = GenerateKey {
      ty: keytype.clone(),
      output: location.clone(),
    };

    client
      .execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure))
      .map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("stronghold generate key procedure failed")
          .with_source(err)
      })?;

    let public_key_procedure = iota_stronghold::procedures::PublicKey {
      ty: keytype,
      private_key: location,
    };

    let procedure_result = client
      .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure))
      .map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("stronghold public key procedure failed")
          .with_source(err)
      })?;
    let public_key: Vec<u8> = procedure_result.into();
    persist_changes(self.as_secret_manager(), stronghold).await?;

    let mut params = JwkParamsOkp::new();
    params.x = jwu::encode_b64(public_key);
    params.crv = EdCurve::Ed25519.name().to_string();
    let mut jwk: Jwk = Jwk::from_params(params);
    jwk.set_alg(alg.name());
    jwk.set_kid(jwk.thumbprint_sha256_b64());

    Ok(JwkGenOutput::new(key_id, jwk))
  }

  async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId> {
    let key_type = StrongholdKeyType::try_from(&jwk)?;
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
    let secret_key = ed25519::expand_secret_jwk(&jwk)?;
    let key_id: KeyId = random_key_id();

    let location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      key_id.to_string().as_bytes().to_vec(),
    );
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;
    client
      .vault(IDENTITY_VAULT_PATH.as_bytes())
      .write_secret(location, zeroize::Zeroizing::from(secret_key.to_bytes().to_vec()))
      .map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("stronghold write secret failed")
          .with_source(err)
      })?;

    persist_changes(self.as_secret_manager(), stronghold).await?;

    Ok(key_id)
  }

  async fn sign(&self, key_id: &KeyId, data: &[u8], public_key: &Jwk) -> KeyStorageResult<Vec<u8>> {
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

    let location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      key_id.to_string().as_bytes().to_vec(),
    );
    let procedure: Ed25519Sign = Ed25519Sign {
      private_key: location,
      msg: data.to_vec(),
    };

    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;

    let signature: [u8; 64] = client.execute_procedure(procedure).map_err(|err| {
      KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        .with_custom_message("stronghold Ed25519Sign procedure failed")
        .with_source(err)
    })?;

    Ok(signature.to_vec())
  }

  async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;
    let deleted = client
      .vault(IDENTITY_VAULT_PATH.as_bytes())
      .delete_secret(key_id.to_string().as_bytes())
      .map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("stronghold client error")
          .with_source(err)
      })?;

    if !deleted {
      return Err(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound));
    }

    persist_changes(self.as_secret_manager(), stronghold).await?;

    Ok(())
  }

  async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;
    let location = Location::generic(
      IDENTITY_VAULT_PATH.as_bytes().to_vec(),
      key_id.to_string().as_bytes().to_vec(),
    );
    let exists = client.record_exists(&location).map_err(|err| {
      KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        .with_custom_message("stronghold client error")
        .with_source(err)
    })?;
    Ok(exists)
  }
}
