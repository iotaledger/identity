// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use anyhow::Context as _;
use async_trait::async_trait;
use fastcrypto::hash::Blake2b256;
use fastcrypto::traits::ToFromBytes;
use identity_iota_interaction::shared_crypto::intent::Intent;
use identity_iota_interaction::types::crypto::PublicKey;
use identity_iota_interaction::types::crypto::Signature;
use identity_iota_interaction::types::crypto::SignatureScheme as IotaSignatureScheme;
use identity_iota_interaction::types::transaction::TransactionData;
use identity_iota_interaction::IotaKeySignature;
use identity_iota_interaction::OptionalSync;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParams;
use identity_verification::jwk::JwkParamsEc;
use identity_verification::jwu;
use secret_storage::Error as SecretStorageError;
use secret_storage::Signer;

use crate::JwkStorage;
use crate::KeyId;
use crate::KeyIdStorage;
use crate::KeyStorageErrorKind;
use crate::Storage;

/// Signer that offers signing capabilities for `Signer` trait from `secret_storage`.
/// `Storage` is used to sign.
pub struct StorageSigner<'a, K, I> {
  key_id: KeyId,
  public_key: Jwk,
  storage: &'a Storage<K, I>,
}

impl<K, I> Clone for StorageSigner<'_, K, I> {
  fn clone(&self) -> Self {
    StorageSigner {
      key_id: self.key_id.clone(),
      public_key: self.public_key.clone(),
      storage: self.storage,
    }
  }
}

impl<'a, K, I> StorageSigner<'a, K, I> {
  /// Creates new `StorageSigner` with reference to a `Storage` instance.
  pub fn new(storage: &'a Storage<K, I>, key_id: KeyId, public_key: Jwk) -> Self {
    Self {
      key_id,
      public_key,
      storage,
    }
  }

  /// Returns a reference to the [`KeyId`] of the key used by this [`Signer`].
  pub fn key_id(&self) -> &KeyId {
    &self.key_id
  }

  /// Returns this [`Signer`]'s public key as [`Jwk`].
  pub fn public_key(&self) -> &Jwk {
    &self.public_key
  }

  /// Returns a reference to this [`Signer`]'s [`Storage`].
  pub fn storage(&self) -> &Storage<K, I> {
    self.storage
  }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<K, I> Signer<IotaKeySignature> for StorageSigner<'_, K, I>
where
  K: JwkStorage + OptionalSync,
  I: KeyIdStorage + OptionalSync,
{
  type KeyId = KeyId;

  fn key_id(&self) -> KeyId {
    self.key_id.clone()
  }

  async fn public_key(&self) -> Result<PublicKey, SecretStorageError> {
    match self.public_key.params() {
      JwkParams::Okp(params) => {
        if params.crv != "Ed25519" {
          return Err(SecretStorageError::Other(anyhow!(
            "unsupported key type {}",
            params.crv
          )));
        }

        jwu::decode_b64(&params.x)
          .context("failed to base64 decode key")
          .and_then(|pk_bytes| {
            PublicKey::try_from_bytes(IotaSignatureScheme::ED25519, &pk_bytes).map_err(|e| anyhow!("{e}"))
          })
          .map_err(SecretStorageError::Other)
      }
      JwkParams::Ec(JwkParamsEc { crv, x, y, .. }) => {
        let pk_bytes = {
          let mut decoded_x_bytes = jwu::decode_b64(x)
            .map_err(|e| SecretStorageError::Other(anyhow!("failed to decode b64 x parameter: {e}")))?;
          let mut decoded_y_bytes = jwu::decode_b64(y)
            .map_err(|e| SecretStorageError::Other(anyhow!("failed to decode b64 y parameter: {e}")))?;
          decoded_x_bytes.append(&mut decoded_y_bytes);

          decoded_x_bytes
        };

        if self.public_key.alg() == Some("ES256") || crv == "P-256" {
          PublicKey::try_from_bytes(IotaSignatureScheme::Secp256r1, &pk_bytes)
            .map_err(|e| SecretStorageError::Other(anyhow!("not a secp256r1 key: {e}")))
        } else if self.public_key.alg() == Some("ES256K") || crv == "K-256" {
          PublicKey::try_from_bytes(IotaSignatureScheme::Secp256k1, &pk_bytes)
            .map_err(|e| SecretStorageError::Other(anyhow!("not a secp256k1 key: {e}")))
        } else {
          Err(SecretStorageError::Other(anyhow!("invalid EC key")))
        }
      }
      _ => Err(SecretStorageError::Other(anyhow!("unsupported key"))),
    }
  }
  async fn sign(&self, data: &TransactionData) -> Result<Signature, SecretStorageError> {
    use fastcrypto::hash::HashFunction;

    let tx_data_bcs =
      bcs::to_bytes(data).map_err(|e| SecretStorageError::Other(anyhow!("bcs deserialization failed: {e}")))?;
    let intent_bytes = Intent::iota_transaction().to_bytes();
    let mut hasher = Blake2b256::default();
    hasher.update(intent_bytes);
    hasher.update(&tx_data_bcs);
    let digest = hasher.finalize().digest;

    let signature_bytes = self
      .storage
      .key_storage()
      .sign(&self.key_id, &digest, &self.public_key)
      .await
      .map_err(|e| match e.kind() {
        KeyStorageErrorKind::KeyNotFound => SecretStorageError::KeyNotFound(e.to_string()),
        KeyStorageErrorKind::RetryableIOFailure => SecretStorageError::StoreDisconnected(e.to_string()),
        _ => SecretStorageError::Other(anyhow::anyhow!(e)),
      })?;

    let public_key = Signer::public_key(self).await?;

    let iota_signature_bytes = [[public_key.flag()].as_slice(), &signature_bytes, public_key.as_ref()].concat();

    Signature::from_bytes(&iota_signature_bytes)
      .map_err(|e| SecretStorageError::Other(anyhow!("failed to create valid IOTA signature: {e}")))
  }
}
