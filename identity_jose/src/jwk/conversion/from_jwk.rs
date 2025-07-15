// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::jwk::Jwk;
use crate::jwk::JwkParams;
use crate::jwk::JwkParamsEc;
use crate::jwu;
use anyhow::anyhow;
use anyhow::Context as _;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::secp256k1::Secp256k1KeyPair;
use fastcrypto::secp256r1::Secp256r1KeyPair;
use iota_interaction::types::crypto::IotaKeyPair;
use iota_interaction::types::crypto::PublicKey;
use iota_interaction::types::crypto::SignatureScheme as IotaSignatureScheme;

use super::ed25519;
use super::secp256k1;
use super::secp256r1;

/// Helper trait to convert implementing conversion from `Jwk`.
pub trait FromJwk: Sized {
  /// Error type used
  type Error;

  /// Create instance from `Jwk`.
  fn from_jwk(jwk: &Jwk) -> Result<Self, Self::Error>;
}

impl FromJwk for IotaKeyPair {
  type Error = Error;

  fn from_jwk(jwk: &Jwk) -> Result<Self, Self::Error> {
    let maybe_ed22519 = Ed25519KeyPair::from_jwk(jwk).map(IotaKeyPair::from);
    let maybe_secp256r1 = Secp256r1KeyPair::from_jwk(jwk).map(IotaKeyPair::from);
    let maybe_secp256k1 = Secp256k1KeyPair::from_jwk(jwk).map(IotaKeyPair::from);

    maybe_ed22519
      .or(maybe_secp256k1)
      .or(maybe_secp256r1)
      .map_err(|err| Error::KeyConversion(err.to_string()))
  }
}

impl FromJwk for PublicKey {
  type Error = Error;

  fn from_jwk(jwk: &Jwk) -> Result<Self, Self::Error> {
    match jwk.params() {
      JwkParams::Okp(params) => {
        if params.crv != "Ed25519" {
          return Err(Error::KeyConversion(format!("unsupported key type {}", params.crv)));
        }

        jwu::decode_b64(&params.x)
          .context("failed to base64 decode key")
          .and_then(|pk_bytes| {
            PublicKey::try_from_bytes(IotaSignatureScheme::ED25519, &pk_bytes).map_err(|e| anyhow!("{e}"))
          })
          .map_err(|err| Error::KeyConversion(err.to_string()))
      }
      JwkParams::Ec(JwkParamsEc { crv, x, y, .. }) => {
        let pk_bytes = {
          let mut decoded_x_bytes =
            jwu::decode_b64(x).map_err(|e| Error::KeyConversion(format!("failed to decode b64 x parameter: {e}")))?;
          let decoded_y_bytes =
            jwu::decode_b64(y).map_err(|e| Error::KeyConversion(format!("failed to decode b64 y parameter: {e}")))?;

          // build compressed public key
          let last_y = decoded_y_bytes
            .last()
            .ok_or_else(|| Error::KeyConversion("y parameter should not be empty".to_string()))?;
          if last_y % 2 == 0 {
            decoded_x_bytes.insert(0, 2);
          } else {
            decoded_x_bytes.insert(0, 3);
          }

          decoded_x_bytes
        };

        if jwk.alg() == Some("ES256") || crv == "P-256" {
          PublicKey::try_from_bytes(IotaSignatureScheme::Secp256r1, &pk_bytes)
            .map_err(|e| Error::KeyConversion(format!("not a secp256r1 key: {e}")))
        } else if jwk.alg() == Some("ES256K") || crv == "K-256" || crv == "secp256k1" {
          PublicKey::try_from_bytes(IotaSignatureScheme::Secp256k1, &pk_bytes)
            .map_err(|e| Error::KeyConversion(format!("not a secp256k1 key: {e}")))
        } else {
          Err(Error::KeyError("invalid EC key"))
        }
      }
      _ => Err(Error::KeyConversion("unsupported key".to_string())),
    }
  }
}

impl FromJwk for Ed25519KeyPair {
  type Error = Error;

  fn from_jwk(jwk: &Jwk) -> Result<Self, Self::Error> {
    ed25519::jwk_to_keypair(jwk).map_err(|err| Error::KeyConversion(err.to_string()))
  }
}

impl FromJwk for Secp256r1KeyPair {
  type Error = Error;

  fn from_jwk(jwk: &Jwk) -> Result<Self, Self::Error> {
    secp256r1::jwk_to_keypair(jwk).map_err(|err| Error::KeyConversion(err.to_string()))
  }
}

impl FromJwk for Secp256k1KeyPair {
  type Error = Error;

  fn from_jwk(jwk: &Jwk) -> Result<Self, Self::Error> {
    secp256k1::jwk_to_keypair(jwk).map_err(|err| Error::KeyConversion(err.to_string()))
  }
}

impl FromJwk for Ed25519PublicKey {
  type Error = Error;

  fn from_jwk(jwk: &Jwk) -> Result<Self, Self::Error> {
    ed25519::from_public_jwk(jwk).map_err(|err| Error::KeyConversion(err.to_string()))
  }
}

#[cfg(test)]
mod tests {
  use super::FromJwk;
  use crate::jwk::Jwk;
  use crate::jwu::encode_b64;

  #[derive(PartialEq)]
  enum KeyType {
    Private,
    Public,
  }

  fn get_ed25519_jwk(key_type: KeyType) -> Jwk {
    use fastcrypto::traits::KeyPair as _;

    let keypair = fastcrypto::ed25519::Ed25519KeyPair::generate(&mut rand::thread_rng());
    let mut params = crate::jwk::JwkParamsOkp::new();
    let x = encode_b64(keypair.public().as_ref());
    params.x = x;
    if key_type == KeyType::Private {
      let d = encode_b64(keypair.private().as_ref());
      params.d = Some(d);
    }
    params.crv = crate::jwk::EdCurve::Ed25519.name().to_string();

    Jwk::from_params(params)
  }

  fn get_secp256r1_jwk(key_type: KeyType) -> Jwk {
    let sk = p256::SecretKey::random(&mut rand::thread_rng());
    let jwk_string = if key_type == KeyType::Private {
      &sk.to_jwk_string()
    } else {
      &sk.public_key().to_jwk_string()
    };
    let jwk: Jwk = serde_json::from_str(jwk_string).unwrap();

    jwk
  }

  fn get_secp256k1_jwk(key_type: KeyType) -> Jwk {
    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let jwk_string = if key_type == KeyType::Private {
      &sk.to_jwk_string()
    } else {
      &sk.public_key().to_jwk_string()
    };
    let jwk: Jwk = serde_json::from_str(jwk_string).unwrap();
    dbg!(jwk_string);

    jwk
  }

  #[test]
  fn can_convert_from_jwk_to_ed22519_iota_keypair() {
    let jwk = get_ed25519_jwk(KeyType::Private);
    let result = iota_interaction::types::crypto::IotaKeyPair::from_jwk(&jwk);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_jwk_to_ecp256r1_iota_keypair() {
    let jwk = get_secp256r1_jwk(KeyType::Private);
    let result = iota_interaction::types::crypto::IotaKeyPair::from_jwk(&jwk);
    dbg!(&result);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_jwk_to_secp256k1_iota_keypair() {
    let jwk = get_secp256k1_jwk(KeyType::Private);
    let result = iota_interaction::types::crypto::IotaKeyPair::from_jwk(&jwk);
    dbg!(&result);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_octet_keypair_jwk_to_iota_public_key() {
    let jwk = get_ed25519_jwk(KeyType::Public);
    let result = iota_interaction::types::crypto::PublicKey::from_jwk(&jwk);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_secp256r1_jwk_to_iota_public_key() {
    let jwk = get_secp256r1_jwk(KeyType::Public);
    let result = iota_interaction::types::crypto::PublicKey::from_jwk(&jwk);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_secp256k1_jwk_to_iota_public_key() {
    let jwk = get_secp256k1_jwk(KeyType::Public);
    let result = iota_interaction::types::crypto::PublicKey::from_jwk(&jwk);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_jwk_to_ed25519_key_pair() {
    let jwk = get_ed25519_jwk(KeyType::Private);
    let result = fastcrypto::ed25519::Ed25519KeyPair::from_jwk(&jwk);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_jwk_to_secp256r1_key_pair() {
    let jwk = get_secp256r1_jwk(KeyType::Private);
    let result = fastcrypto::secp256r1::Secp256r1KeyPair::from_jwk(&jwk);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_jwk_to_secp256k1_key_pair() {
    let jwk = get_secp256k1_jwk(KeyType::Private);
    let result = fastcrypto::secp256k1::Secp256k1KeyPair::from_jwk(&jwk);

    assert!(result.is_ok());
  }

  #[test]
  fn can_convert_from_jwk_to_ed25519_public_key() {
    let jwk = get_ed25519_jwk(KeyType::Public);
    let result = fastcrypto::ed25519::Ed25519PublicKey::from_jwk(&jwk);

    assert!(result.is_ok());
  }
}
