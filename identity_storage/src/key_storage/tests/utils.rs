// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::key_storage::JwkStorage;
use crate::key_storage::KeyId;
use crate::key_storage::KeyStorageErrorKind;
use crate::key_storage::KeyType;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::ed25519::Ed25519Signature;
use fastcrypto::traits::KeyPair;
use fastcrypto::traits::ToFromBytes as _;
use fastcrypto::traits::VerifyingKey as _;
use identity_verification::jose::jwk::Jwk;
use identity_verification::jwk::EcCurve;
use identity_verification::jwk::FromJwk;
use identity_verification::jwk::JwkParamsEc;
use identity_verification::jwk::ToJwk as _;
use identity_verification::jws::JwsAlgorithm;

pub(crate) async fn test_insertion(store: impl JwkStorage) {
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

pub(crate) async fn test_incompatible_key_alg(store: impl JwkStorage) {
  let key_pair = generate_ed25519();
  let mut jwk: Jwk = key_pair.to_jwk().unwrap();
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

  let signature = Ed25519Signature::from_bytes(&signature).unwrap();
  let public_key = Ed25519PublicKey::from_jwk(&generate.jwk).unwrap();
  assert!(public_key.verify(test_msg, &signature).is_ok());

  let key_id: KeyId = generate.key_id;
  assert!(store.exists(&key_id).await.unwrap());
  store.delete(&key_id).await.unwrap();
}

pub(crate) async fn test_key_exists(store: impl JwkStorage) {
  assert!(!store.exists(&KeyId::new("non-existent-id")).await.unwrap());
}

pub(crate) fn generate_ed25519() -> Ed25519KeyPair {
  Ed25519KeyPair::generate(&mut rand::thread_rng())
}
