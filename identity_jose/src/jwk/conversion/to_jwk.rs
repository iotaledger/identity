// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

use iota_sdk::crypto::ed25519::Ed25519PrivateKey;
use iota_sdk::types::PublicKey;

use crate::error::Error;
use crate::jwk::Jwk;

use super::ed25519;
use super::secp256k1;
use super::secp256r1;

/// Helper trait to convert an arbitrary key type to `Jwk`.
pub trait ToJwk {
  /// Error type used
  type Error;

  /// Converts instance to `Jwk`.
  fn to_jwk(&self) -> Result<Jwk, Self::Error>;
}

impl ToJwk for PublicKey {
  type Error = Error;

  fn to_jwk(&self) -> Result<Jwk, Self::Error> {
    let jwk = match self {
      PublicKey::Ed25519(pk) => ed25519::pk_to_jwk(pk),
      PublicKey::Secp256r1(pk) => secp256r1::pk_to_jwk(pk),
      PublicKey::Secp256k1(pk) => secp256k1::pk_to_jwk(pk),
      _ => return Err(Error::KeyConversion("unsupported key type".to_string())),
    };

    Ok(jwk)
  }
}

impl ToJwk for Ed25519PrivateKey {
  type Error = Infallible;

  fn to_jwk(&self) -> Result<Jwk, Self::Error> {
    Ok(ed25519::encode_jwk(self.clone()))
  }
}

#[cfg(test)]
mod tests {
  use iota_sdk::crypto::ed25519::Ed25519PrivateKey;

use super::ToJwk;

  mod iota_public_key {
    use iota_sdk::{
      crypto::{ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey, secp256r1::Secp256r1PrivateKey},
      types::PublicKey,
    };

    use super::*;

    #[test]
    fn can_convert_from_ed25519_public_key_to_jwk() {
      let public_key = PublicKey::Ed25519(Ed25519PrivateKey::random().public_key());
      let result = public_key.to_jwk();

      assert!(result.is_ok());
    }

    #[test]
    fn can_convert_from_secp256r1_public_key_to_jwk() {
      let public_key = PublicKey::Secp256r1(Secp256r1PrivateKey::random().public_key());
      let result = public_key.to_jwk();

      assert!(result.is_ok());
    }

    #[test]
    fn can_convert_from_secp256k1_public_key_to_jwk() {
      let public_key = PublicKey::Secp256k1(Secp256k1PrivateKey::random().public_key());
      let result = public_key.to_jwk();

      assert!(result.is_ok());
    }
  }

  #[test]
  fn can_convert_from_ed25519_keypair_to_jwk() {
    let sk = Ed25519PrivateKey::random();
    let result = sk.to_jwk();

    assert!(result.is_ok());
  }
}
