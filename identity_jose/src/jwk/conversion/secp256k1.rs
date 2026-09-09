// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use iota_sdk::crypto::secp256k1::Secp256k1PrivateKey;
use iota_sdk::crypto::ToFromBytes as _;
use iota_sdk::types::PublicKeyExt as _;
use iota_sdk::types::Secp256k1PublicKey;
use k256::PublicKey;
use k256::SecretKey;

use crate::jwk::Jwk;
use crate::jws::JwsAlgorithm;

pub(crate) fn pk_to_jwk(pk: &Secp256k1PublicKey) -> Jwk {
  let jwk_str = PublicKey::from_sec1_bytes(pk.as_bytes())
    .expect("valid secp256k1 pk")
    .to_jwk_string();
  let mut jwk: Jwk = serde_json::from_str(&jwk_str).expect("valid JWK encoded secp256k1");
  jwk.set_alg(JwsAlgorithm::ES256K.name());
  jwk
}

pub(crate) fn jwk_to_keypair(jwk: &Jwk) -> anyhow::Result<Secp256k1PrivateKey> {
  let sk = SecretKey::from_jwk_str(&serde_json::to_string(jwk)?)?;
  Secp256k1PrivateKey::from_bytes(&sk.to_bytes()).context("failed to create secp256k1 keypair from JWK")
}
