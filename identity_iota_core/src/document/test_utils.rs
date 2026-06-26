// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::signatures::ed25519::PublicKey;
use crypto::signatures::ed25519::SecretKey;
use identity_verification::jwk::EdCurve;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsOkp;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use identity_verification::VerificationMethod;

use crate::IotaDID;

pub(crate) fn generate_method(controller: &IotaDID, fragment: &str) -> VerificationMethod {
  let secret: SecretKey = SecretKey::generate().unwrap();
  let public: PublicKey = secret.public_key();
  let jwk: Jwk = encode_public_ed25519_jwk(public.as_ref());
  VerificationMethod::new_from_jwk(controller.to_owned(), jwk, Some(fragment)).unwrap()
}

fn encode_public_ed25519_jwk(public_key: &[u8]) -> Jwk {
  let x = jwu::encode_b64(public_key);
  let mut params = JwkParamsOkp::new();
  params.x = x;
  params.d = None;
  params.crv = EdCurve::Ed25519.name().to_string();
  let mut jwk = Jwk::from_params(params);
  jwk.set_alg(JwsAlgorithm::EdDSA.name());
  jwk
}
