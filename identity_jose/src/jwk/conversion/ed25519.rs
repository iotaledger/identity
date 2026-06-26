// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519PrivateKey;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::ed25519::Ed25519PublicKeyAsBytes;
use fastcrypto::traits::KeyPair as _;
use fastcrypto::traits::SigningKey;
use fastcrypto::traits::ToFromBytes;

use crate::error::Error;
use crate::jwk::EdCurve;
use crate::jwk::Jwk;
use crate::jwk::JwkParamsOkp;
use crate::jwu;
use crate::jwu::decode_b64;
use crate::jwu::encode_b64;

pub(crate) fn from_public_jwk(jwk: &Jwk) -> anyhow::Result<Ed25519PublicKey> {
  let bytes = decode_b64(&jwk.try_okp_params()?.x)?;
  Ok(Ed25519PublicKey::from_bytes(&bytes)?)
}

pub(crate) fn jwk_to_keypair(jwk: &Jwk) -> Result<Ed25519KeyPair, Error> {
  let params: &JwkParamsOkp = jwk.try_okp_params()?;

  if params
    .try_ed_curve()
    .map_err(|err| Error::UnsupportedKeyType(err.to_string()))?
    != EdCurve::Ed25519
  {
    return Err(Error::UnsupportedKeyType(format!(
      "expected an {} key",
      EdCurve::Ed25519.name()
    )));
  }

  let sk: [u8; Ed25519PrivateKey::LENGTH] = params
    .d
    .as_deref()
    .map(jwu::decode_b64)
    .ok_or_else(|| Error::KeyConversion("expected Jwk `d` param to be present".to_string()))?
    .map_err(|err| Error::KeyConversion(format!("unable to decode `d` param; {err}")))?
    .try_into()
    .map_err(|_| Error::KeyConversion(format!("expected key of length {}", Ed25519PrivateKey::LENGTH)))?;

  Ed25519KeyPair::from_bytes(&sk).map_err(|_| Error::KeyConversion("invalid key".to_string()))
}

#[allow(dead_code)]
pub(crate) fn encode_jwk(key_pair: Ed25519KeyPair) -> Jwk {
  let x = jwu::encode_b64(key_pair.public().as_ref());
  let d = jwu::encode_b64(key_pair.private().as_ref());
  let mut params = JwkParamsOkp::new();
  params.x = x;
  params.d = Some(d);
  params.crv = EdCurve::Ed25519.name().to_string();
  Jwk::from_params(params)
}

#[allow(dead_code)]
pub(crate) fn pk_to_jwk(pk: &Ed25519PublicKeyAsBytes) -> Jwk {
  use crate::jws::JwsAlgorithm;

  let params = JwkParamsOkp {
    crv: EdCurve::Ed25519.to_string(),
    x: encode_b64(pk.0),
    d: None,
  };

  let mut jwk = Jwk::from_params(params);
  jwk.set_alg(JwsAlgorithm::EdDSA.name());

  jwk
}
