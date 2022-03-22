// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::signatures::ed25519;

use crate::crypto::PrivateKey;
use crate::crypto::PublicKey;
use crate::error::Result;

/// Reconstructs an Ed25519 private key from a byte array.
pub(crate) fn ed25519_private_try_from_bytes(bytes: &[u8]) -> Result<ed25519::SecretKey> {
  let private_key_bytes: [u8; ed25519::SECRET_KEY_LENGTH] = bytes
    .try_into()
    .map_err(|_| crate::Error::InvalidKeyLength(bytes.len(), ed25519::SECRET_KEY_LENGTH))?;
  Ok(ed25519::SecretKey::from_bytes(private_key_bytes))
}

/// Reconstructs an Ed25519 public key from a byte array.
pub(crate) fn ed25519_public_try_from_bytes(bytes: &[u8]) -> Result<ed25519::PublicKey> {
  let public_key_bytes: [u8; ed25519::PUBLIC_KEY_LENGTH] = bytes
    .try_into()
    .map_err(|_| crate::Error::InvalidKeyLength(bytes.len(), ed25519::PUBLIC_KEY_LENGTH))?;
  ed25519::PublicKey::try_from_bytes(public_key_bytes).map_err(Into::into)
}

/// Generates a new pair of public/private Ed25519 keys.
///
/// Note that the private key is a 32-byte seed in compliance with [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032#section-3.2).
/// Other implementations often use another format. See [this blog post](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/) for further explanation.
// TODO: move or remove
pub(crate) fn generate_ed25519_keypair() -> Result<(PublicKey, PrivateKey)> {
  let secret: ed25519::SecretKey = ed25519::SecretKey::generate()?;
  let public: ed25519::PublicKey = secret.public_key();

  let private: PrivateKey = secret.to_bytes().to_vec().into();
  let public: PublicKey = public.to_bytes().to_vec().into();

  Ok((public, private))
}

/// Generates a list of public/private Ed25519 keys.
///
/// See [`generate_ed25519_keypair`].
// TODO: remove
pub(crate) fn generate_ed25519_keypairs(count: usize) -> Result<Vec<(PublicKey, PrivateKey)>> {
  (0..count).map(|_| generate_ed25519_keypair()).collect()
}

#[cfg(test)]
mod tests {
  use super::generate_ed25519_keypair;

  #[test]
  fn generate_ed25519_keypair_has_expected_length() {
    let (public_key, private_key) = generate_ed25519_keypair().unwrap();
    assert_eq!(
      private_key.as_ref().len(),
      crypto::signatures::ed25519::SECRET_KEY_LENGTH
    );
    assert_eq!(public_key.as_ref().len(), private_key.as_ref().len());
  }
}
