// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use identity_verification::jose::jwk::Jwk;
use identity_verification::jose::jwu;
use identity_verification::jwk::BlsCurve;
use identity_verification::jwk::JwkParamsEc;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use zkryptium::bbsplus::ciphersuites::BbsCiphersuite;
use zkryptium::bbsplus::ciphersuites::Bls12381Sha256;
use zkryptium::bbsplus::ciphersuites::Bls12381Shake256;
use zkryptium::bbsplus::keys::BBSplusPublicKey;
use zkryptium::bbsplus::keys::BBSplusSecretKey;
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BBSplus;
use zkryptium::schemes::generics::Signature;

use crate::key_storage::KeyStorageError;
use crate::key_storage::KeyStorageErrorKind;
use crate::key_storage::KeyStorageResult;
use crate::ProofUpdateCtx;

fn random_bbs_keypair<S>() -> Result<(BBSplusSecretKey, BBSplusPublicKey), zkryptium::errors::Error>
where
  S: BbsCiphersuite,
{
  KeyPair::<BBSplus<S>>::random().map(KeyPair::into_parts)
}

/// Generates a new BBS+ keypair using either `BLS12381-SHA256` or `BLS12381-SHAKE256`.
pub fn generate_bbs_keypair(alg: ProofAlgorithm) -> KeyStorageResult<(BBSplusSecretKey, BBSplusPublicKey)> {
  match alg {
    ProofAlgorithm::BLS12381_SHA256 => random_bbs_keypair::<Bls12381Sha256>(),
    ProofAlgorithm::BLS12381_SHAKE256 => random_bbs_keypair::<Bls12381Shake256>(),
    _ => return Err(KeyStorageErrorKind::UnsupportedProofAlgorithm.into()),
  }
  .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err))
}

/// Encodes a private BBS+ key into JWK.
pub fn encode_bls_jwk(
  private_key: &BBSplusSecretKey,
  public_key: &BBSplusPublicKey,
  alg: ProofAlgorithm,
) -> (Jwk, Jwk) {
  let (x, y) = public_key.to_coordinates();
  let x = jwu::encode_b64(x);
  let y = jwu::encode_b64(y);

  let d = jwu::encode_b64(private_key.to_bytes());
  let params = JwkParamsEc {
    x,
    y,
    d: Some(d),
    crv: BlsCurve::BLS12381G2.name().to_owned(),
  };

  let mut jwk = Jwk::from_params(params);

  jwk.set_alg(alg.to_string());
  jwk.set_kid(jwk.thumbprint_sha256_b64());
  let public_jwk = jwk.to_public().expect("kty != oct");

  (jwk, public_jwk)
}

/// Attempts to decode JWK into a BBS+ keypair.
pub fn expand_bls_jwk(jwk: &Jwk) -> KeyStorageResult<(Option<BBSplusSecretKey>, BBSplusPublicKey)> {
  // Check the provided JWK represents a BLS12381G2 key.
  let params = jwk
    .try_ec_params()
    .ok()
    .filter(|params| {
      params
        .try_bls_curve()
        .map(|curve| curve == BlsCurve::BLS12381G2)
        .unwrap_or(false)
    })
    .context(format!("not a {} curve key", BlsCurve::BLS12381G2))
    .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).with_source(e))?;

  let sk = params
    .d
    .as_deref()
    .map(|d| {
      jwu::decode_b64(d)
        .context("`d` parameter is not base64 encoded")
        .and_then(|bytes| BBSplusSecretKey::from_bytes(&bytes).context("invalid key size"))
    })
    .transpose()
    .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(e))?;

  let x = jwu::decode_b64(&params.x)
    .context("`x` parameter is not base64 encoded")
    .and_then(|bytes| bytes.try_into().ok().context("invalid coordinate size"))
    .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).with_source(e))?;
  let y = jwu::decode_b64(&params.y)
    .context("`y` parameter is not base64 encoded")
    .and_then(|bytes| bytes.try_into().ok().context("invalid coordinate size"))
    .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).with_source(e))?;

  let pk = BBSplusPublicKey::from_coordinates(&x, &y).map_err(|e| {
    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
      .with_source(e)
      .with_custom_message("invalid BBS+ public key".to_owned())
  })?;

  Ok((sk, pk))
}

fn _sign_bbs<S>(
  data: &[Vec<u8>],
  sk: &BBSplusSecretKey,
  pk: &BBSplusPublicKey,
  header: &[u8],
) -> Result<Vec<u8>, zkryptium::errors::Error>
where
  S: BbsCiphersuite,
{
  Signature::<BBSplus<S>>::sign(Some(data), sk, pk, Some(header)).map(|s| s.to_bytes().to_vec())
}

/// Signs data and header using the given keys.
pub fn sign_bbs(
  alg: ProofAlgorithm,
  data: &[Vec<u8>],
  sk: &BBSplusSecretKey,
  pk: &BBSplusPublicKey,
  header: &[u8],
) -> KeyStorageResult<Vec<u8>> {
  match alg {
    ProofAlgorithm::BLS12381_SHA256 => _sign_bbs::<Bls12381Sha256>(data, sk, pk, header),
    ProofAlgorithm::BLS12381_SHAKE256 => _sign_bbs::<Bls12381Shake256>(data, sk, pk, header),
    _ => return Err(KeyStorageErrorKind::UnsupportedProofAlgorithm.into()),
  }
  .map_err(|e| {
    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
      .with_source(e)
      .with_custom_message("signature failed".to_owned())
  })
}

fn _update_bbs_signature<S>(
  sig: &[u8; 80],
  sk: &BBSplusSecretKey,
  update_ctx: &ProofUpdateCtx,
) -> Result<[u8; 80], zkryptium::errors::Error>
where
  S: BbsCiphersuite,
{
  let sig = Signature::<BBSplus<S>>::from_bytes(sig)?;
  let ProofUpdateCtx {
    old_start_validity_timeframe,
    new_start_validity_timeframe,
    old_end_validity_timeframe,
    new_end_validity_timeframe,
    index_start_validity_timeframe,
    index_end_validity_timeframe,
    number_of_signed_messages,
  } = update_ctx;
  let half_updated = sig.update_signature(
    sk,
    old_start_validity_timeframe,
    new_start_validity_timeframe,
    *index_start_validity_timeframe,
    *number_of_signed_messages,
  )?;
  half_updated
    .update_signature(
      sk,
      old_end_validity_timeframe,
      new_end_validity_timeframe,
      *index_end_validity_timeframe,
      *number_of_signed_messages,
    )
    .map(|sig| sig.to_bytes())
}

/// Updates BBS+ signature's timeframe data.
pub fn update_bbs_signature(
  alg: ProofAlgorithm,
  sig: &[u8],
  sk: &BBSplusSecretKey,
  update_ctx: &ProofUpdateCtx,
) -> KeyStorageResult<Vec<u8>> {
  let exact_size_signature = sig.try_into().map_err(|_| {
    KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("invalid signature size".to_owned())
  })?;
  match alg {
    ProofAlgorithm::BLS12381_SHA256 => _update_bbs_signature::<Bls12381Sha256>(exact_size_signature, sk, update_ctx),
    ProofAlgorithm::BLS12381_SHAKE256 => {
      _update_bbs_signature::<Bls12381Shake256>(exact_size_signature, sk, update_ctx)
    }
    _ => return Err(KeyStorageErrorKind::UnsupportedProofAlgorithm.into()),
  }
  .map(Vec::from)
  .map_err(|e| {
    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
      .with_custom_message("signature failed")
      .with_source(e)
  })
}
