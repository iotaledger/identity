// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

use crate::error::Error;
use crate::jwk::Jwk;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::KeyPair;
use iota_interaction::types::crypto::PublicKey;

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

impl ToJwk for Ed25519KeyPair {
  type Error = Infallible;

  fn to_jwk(&self) -> Result<Jwk, Self::Error> {
    Ok(ed25519::encode_jwk(self.copy()))
  }
}

#[cfg(test)]
mod tests {
  use super::ToJwk;

  use fastcrypto::traits::KeyPair as _;

  mod iota_public_key {
    use super::*;

    use iota_interaction::types::crypto::IotaKeyPair;

    #[test]
    fn can_convert_from_ed25519_public_key_to_jwk() {
      let public_key =
        IotaKeyPair::Ed25519(fastcrypto::ed25519::Ed25519KeyPair::generate(&mut rand::thread_rng())).public();
      let result = public_key.to_jwk();

      assert!(result.is_ok());
    }

    #[test]
    fn can_convert_from_secp256r1_public_key_to_jwk() {
      let public_key = IotaKeyPair::Secp256r1(fastcrypto::secp256r1::Secp256r1KeyPair::generate(
        &mut rand::thread_rng(),
      ))
      .public();
      let result = public_key.to_jwk();

      assert!(result.is_ok());
    }

    #[test]
    fn can_convert_from_secp256k1_public_key_to_jwk() {
      let public_key = IotaKeyPair::Secp256k1(fastcrypto::secp256k1::Secp256k1KeyPair::generate(
        &mut rand::thread_rng(),
      ))
      .public();
      let result = public_key.to_jwk();

      assert!(result.is_ok());
    }
  }

  #[test]
  fn can_convert_from_ed25519_keypair_to_jwk() {
    let keypair = fastcrypto::ed25519::Ed25519KeyPair::generate(&mut rand::thread_rng());
    let result = keypair.to_jwk();

    assert!(result.is_ok());
  }
}
