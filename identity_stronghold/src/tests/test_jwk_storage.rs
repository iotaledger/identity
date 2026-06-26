// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use identity_verification::jwk::Jwk;
use identity_verification::jws::JwsAlgorithm;
use iota_sdk::client::Password;

use super::utils::create_stronghold_secret_manager;
use super::utils::create_temp_file;
use crate::tests::utils::generate_ed25519;
use crate::StrongholdStorage;
use identity_storage::key_storage::JwkStorage;
use identity_storage::key_storage::KeyType;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;

#[tokio::test]
async fn insert() {
  let stronghold_secret_manager = create_stronghold_secret_manager();
  let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);
  jwk_storage_tests::test_insertion(stronghold_storage).await;
}

#[tokio::test]
async fn retrieve() {
  let stronghold_secret_manager = create_stronghold_secret_manager();
  let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

  let generate = stronghold_storage
    .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
    .await
    .unwrap();
  let key_id = &generate.key_id;

  let pub_key: Jwk = stronghold_storage
    .get_public_key_with_type(key_id, crate::stronghold_key_type::StrongholdKeyType::Ed25519)
    .await
    .unwrap();
  assert_eq!(generate.jwk, pub_key);
}

#[tokio::test]
async fn incompatible_key_alg() {
  let stronghold_secret_manager = create_stronghold_secret_manager();
  let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);
  jwk_storage_tests::test_incompatible_key_alg(stronghold_storage).await;
}

#[tokio::test]
async fn incompatible_key_types() {
  let stronghold_secret_manager = create_stronghold_secret_manager();
  let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);
  jwk_storage_tests::test_incompatible_key_type(stronghold_storage).await;
}

#[tokio::test]
async fn generate_and_sign() {
  let stronghold_secret_manager = create_stronghold_secret_manager();
  let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);
  jwk_storage_tests::test_generate_and_sign(stronghold_storage).await;
}

#[tokio::test]
async fn key_exists() {
  let stronghold_secret_manager = create_stronghold_secret_manager();
  let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);
  jwk_storage_tests::test_key_exists(stronghold_storage).await;
}

// Tests the cases that require persisting to disk, generate, insert and delete.
#[tokio::test]
async fn write_to_disk() {
  iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
  const PASS: &str = "secure_password";
  let file: PathBuf = create_temp_file();
  let secret_manager = StrongholdSecretManager::builder()
    .password(Password::from(PASS.to_owned()))
    .build(file.clone())
    .unwrap();
  let stronghold_storage = StrongholdStorage::new(secret_manager);

  let generate = stronghold_storage
    .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
    .await
    .unwrap();
  let key_id = &generate.key_id;

  drop(stronghold_storage);

  let secret_manager = StrongholdSecretManager::builder()
    .password(Password::from(PASS.to_owned()))
    .build(&file)
    .unwrap();
  let stronghold_storage = StrongholdStorage::new(secret_manager);
  let exists = stronghold_storage.exists(key_id).await.unwrap();
  assert!(exists);
  stronghold_storage.delete(key_id).await.unwrap();

  drop(stronghold_storage);

  let secret_manager = StrongholdSecretManager::builder()
    .password(Password::from(PASS.to_owned()))
    .build(&file)
    .unwrap();
  let stronghold_storage = StrongholdStorage::new(secret_manager);
  let exists = stronghold_storage.exists(key_id).await.unwrap();
  assert!(!exists);

  let (private_key, public_key) = generate_ed25519();
  let mut jwk: Jwk = crate::ed25519::encode_jwk(&private_key, &public_key);
  jwk.set_alg(JwsAlgorithm::EdDSA.name());
  let key_id = stronghold_storage.insert(jwk).await.unwrap();

  drop(stronghold_storage);

  let secret_manager = StrongholdSecretManager::builder()
    .password(Password::from(PASS.to_owned()))
    .build(&file)
    .unwrap();
  let stronghold_storage = StrongholdStorage::new(secret_manager);
  let exists = stronghold_storage.exists(&key_id).await.unwrap();
  assert!(exists);
}

mod jwk_storage_tests {

  use crypto::signatures::ed25519::PublicKey;
  use crypto::signatures::ed25519::SecretKey;
  use crypto::signatures::ed25519::Signature;
  use identity_storage::key_storage::JwkStorage;
  use identity_storage::key_storage::KeyId;
  use identity_storage::key_storage::KeyStorageErrorKind;
  use identity_storage::key_storage::KeyType;
  use identity_verification::jose::jwk::EdCurve;
  use identity_verification::jose::jwk::Jwk;
  use identity_verification::jose::jwk::JwkParamsOkp;
  use identity_verification::jose::jwu;
  use identity_verification::jwk::EcCurve;
  use identity_verification::jwk::JwkParamsEc;
  use identity_verification::jws::JwsAlgorithm;

  use crate::ed25519;

  pub(crate) async fn test_insertion(store: impl JwkStorage) {
    let (private_key, public_key) = generate_ed25519();
    let mut jwk: Jwk = ed25519::encode_jwk(&private_key, &public_key);

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

  pub(crate) async fn test_incompatible_key_alg(store: impl JwkStorage) {
    let (private_key, public_key) = generate_ed25519();
    let mut jwk: Jwk = ed25519::encode_jwk(&private_key, &public_key);
    jwk.set_alg(JwsAlgorithm::ES256.name());

    // INVALID: Inserting an Ed25519 key with the ES256 alg is not compatible.
    let err = store.insert(jwk.clone()).await.unwrap_err();
    assert!(matches!(err.kind(), KeyStorageErrorKind::KeyAlgorithmMismatch));
  }

  pub(crate) async fn test_incompatible_key_type(store: impl JwkStorage) {
    let mut ec_params = JwkParamsEc::new();
    ec_params.crv = EcCurve::P256.name().to_string();
    ec_params.x = String::new();
    ec_params.y = String::new();
    ec_params.d = Some(String::new());
    let jwk_ec = Jwk::from_params(ec_params);

    let err = store.insert(jwk_ec).await.unwrap_err();
    assert!(matches!(err.kind(), KeyStorageErrorKind::UnsupportedKeyType));
  }
  pub(crate) async fn test_generate_and_sign(store: impl JwkStorage) {
    let test_msg: &[u8] = b"test";

    let generate = store
      .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
      .await
      .unwrap();

    let signature = store.sign(&generate.key_id, test_msg, &generate.jwk).await.unwrap();

    let signature: Signature = Signature::from_bytes(signature.try_into().unwrap());
    let public_key: PublicKey = expand_public_jwk(&generate.jwk);
    assert!(public_key.verify(&signature, test_msg));

    let key_id: KeyId = generate.key_id;
    assert!(store.exists(&key_id).await.unwrap());
    store.delete(&key_id).await.unwrap();
  }

  pub(crate) async fn test_key_exists(store: impl JwkStorage) {
    assert!(!store.exists(&KeyId::new("non-existent-id")).await.unwrap());
  }

  pub(crate) fn expand_public_jwk(jwk: &Jwk) -> PublicKey {
    let params: &JwkParamsOkp = jwk.try_okp_params().unwrap();

    if params.try_ed_curve().unwrap() != EdCurve::Ed25519 {
      panic!("expected an ed25519 jwk");
    }

    let pk: [u8; PublicKey::LENGTH] = jwu::decode_b64(params.x.as_str()).unwrap().try_into().unwrap();

    PublicKey::try_from(pk).unwrap()
  }

  pub(crate) fn generate_ed25519() -> (SecretKey, PublicKey) {
    let private_key = SecretKey::generate().unwrap();
    let public_key = private_key.public_key();
    (private_key, public_key)
  }
}
