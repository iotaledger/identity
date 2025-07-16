// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use identity_storage::key_storage::bls::expand_bls_jwk;
use identity_storage::key_storage::bls::sign_bbs;
use identity_storage::JwkGenOutput;
use identity_storage::JwkStorage;
use identity_storage::JwkStorageBbsPlusExt;
use identity_storage::KeyStorageErrorKind;
use iota_stronghold::procedures::Runner;
use iota_stronghold::Location;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use rand::RngCore;
use zkryptium::bbsplus::keys::BBSplusSecretKey;

use crate::stronghold_key_type::StrongholdKeyType;
use crate::tests::utils::create_stronghold_secret_manager;
use crate::utils::get_client;
use crate::utils::IDENTITY_VAULT_PATH;
use crate::StrongholdStorage;

#[tokio::test]
async fn stronghold_bbs_keypair_gen_works() -> anyhow::Result<()> {
  let stronghold_storage = StrongholdStorage::new(create_stronghold_secret_manager());
  let JwkGenOutput { key_id, jwk, .. } = stronghold_storage
    .generate_bbs(StrongholdKeyType::Bls12381G2.into(), ProofAlgorithm::BLS12381_SHA256)
    .await?;

  assert!(jwk.is_public());
  assert!(stronghold_storage.exists(&key_id).await?);

  Ok(())
}

#[tokio::test]
async fn stronghold_bbs_keypair_gen_fails_with_wrong_key_type() -> anyhow::Result<()> {
  let stronghold_storage = StrongholdStorage::new(create_stronghold_secret_manager());
  let error = stronghold_storage
    .generate_bbs(StrongholdKeyType::Ed25519.into(), ProofAlgorithm::BLS12381_SHA256)
    .await
    .unwrap_err();
  assert!(matches!(error.kind(), KeyStorageErrorKind::UnsupportedKeyType));

  Ok(())
}

#[tokio::test]
async fn stronghold_bbs_keypair_gen_fails_with_wrong_alg() -> anyhow::Result<()> {
  let stronghold_storage = StrongholdStorage::new(create_stronghold_secret_manager());
  let error = stronghold_storage
    .generate_bbs(StrongholdKeyType::Bls12381G2.into(), ProofAlgorithm::MAC_H256)
    .await
    .unwrap_err();

  assert!(matches!(error.kind(), KeyStorageErrorKind::UnsupportedProofAlgorithm));

  Ok(())
}

#[tokio::test]
async fn stronghold_sign_bbs_works() -> anyhow::Result<()> {
  let stronghold_storage = StrongholdStorage::new(create_stronghold_secret_manager());
  let JwkGenOutput { key_id, jwk, .. } = stronghold_storage
    .generate_bbs(StrongholdKeyType::Bls12381G2.into(), ProofAlgorithm::BLS12381_SHA256)
    .await?;
  let pk = expand_bls_jwk(&jwk)?.1;
  let sk = {
    let stronghold = stronghold_storage.get_stronghold().await;
    let client = get_client(&stronghold)?;
    let sk_location = Location::Generic {
      vault_path: IDENTITY_VAULT_PATH.as_bytes().to_owned(),
      record_path: key_id.as_str().as_bytes().to_owned(),
    };
    client
      .get_guards([sk_location], |[sk]| Ok(BBSplusSecretKey::from_bytes(&sk.borrow())))
      .unwrap()
  }?;

  let mut data = vec![0; 1024];
  rand::thread_rng().fill_bytes(&mut data);
  let expected_signature = sign_bbs(
    ProofAlgorithm::BLS12381_SHA256,
    std::slice::from_ref(&data),
    &sk,
    &pk,
    &[],
  )?;

  let signature = stronghold_storage.sign_bbs(&key_id, &[data], &[], &jwk).await?;
  assert_eq!(signature, expected_signature);

  Ok(())
}
