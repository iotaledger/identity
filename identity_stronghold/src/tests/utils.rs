// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::signatures::ed25519::PublicKey;
use crypto::signatures::ed25519::SecretKey;
use identity_did::CoreDID;
use identity_verification::jwk::EdCurve;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsOkp;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use identity_verification::VerificationMethod;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::Password;
use rand::distributions::DistString;
use std::path::PathBuf;

pub(crate) fn create_verification_method() -> VerificationMethod {
  let secret: SecretKey = SecretKey::generate().unwrap();
  let public: PublicKey = secret.public_key();
  let jwk: Jwk = encode_public_ed25519_jwk(&public);
  let did: CoreDID = CoreDID::parse(format!("did:example:{}", jwk.thumbprint_sha256_b64())).unwrap();
  VerificationMethod::new_from_jwk(did, jwk, Some("#frag")).unwrap()
}

pub(crate) fn encode_public_ed25519_jwk(public_key: &PublicKey) -> Jwk {
  let x = jwu::encode_b64(public_key.as_ref());
  let mut params = JwkParamsOkp::new();
  params.x = x;
  params.d = None;
  params.crv = EdCurve::Ed25519.name().to_string();
  let mut jwk = Jwk::from_params(params);
  jwk.set_alg(JwsAlgorithm::EdDSA.name());
  jwk
}

pub(crate) fn generate_ed25519() -> (SecretKey, PublicKey) {
  let private_key = SecretKey::generate().unwrap();
  let public_key = private_key.public_key();
  (private_key, public_key)
}

pub(crate) fn create_stronghold_secret_manager() -> StrongholdSecretManager {
  iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
  let mut file = std::env::temp_dir();
  file.push("test_strongholds");
  file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
  file.set_extension("stronghold");

  StrongholdSecretManager::builder()
    .password(Password::from("secure_password".to_owned()))
    .build(&file)
    .unwrap()
}

pub(crate) fn create_temp_file() -> PathBuf {
  let mut file = std::env::temp_dir();
  file.push("test_strongholds");
  file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
  file.set_extension("stronghold");
  file
}
