// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use async_trait::async_trait;
use fastcrypto::hash::Blake2b256;
use fastcrypto::traits::ToFromBytes;

use identity_did::CoreDID;
use identity_document::document::CoreDocument;
use identity_verification::jwk::FromJwk as _;
use identity_verification::jwk::Jwk;
use identity_verification::MethodData;

use iota_interaction::types::crypto::PublicKey;
use iota_interaction::types::crypto::Signature;
use iota_sdk_types::crypto::Intent;

use iota_interaction::types::transaction::TransactionData;
use iota_interaction::IotaKeySignature;
use iota_interaction::OptionalSync;
use secret_storage::Error as SecretStorageError;
use secret_storage::Signer;

use crate::JwkStorage;
use crate::KeyId;
use crate::KeyIdStorage;
use crate::KeyIdStorageErrorKind;
use crate::KeyStorageErrorKind;
use crate::MethodDigest;
use crate::MethodDigestConstructionError;
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
  pub fn public_key_jwk(&self) -> &Jwk {
    &self.public_key
  }

  /// Returns a reference to this [`Signer`]'s [`Storage`].
  pub fn storage(&self) -> &Storage<K, I> {
    self.storage
  }
}

/// Error type that may be returned by [StorageSigner::new_from_vm_fragment].
#[derive(Debug, thiserror::Error)]
#[error("failed to create signer for '{did}#{fragment}'")]
#[non_exhaustive]
pub struct StorageSignerFromVmError {
  /// The [DID](CoreDID) of the given [document](CoreDocument).
  pub did: CoreDID,
  /// The verification method fragment.
  pub fragment: Box<str>,
  /// Specific type of failure for this error.
  pub kind: StorageSignerFromVmErrorKind,
}

/// Types of failure for [StorageSignerFromVmError].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageSignerFromVmErrorKind {
  /// The given DID Document doesn't contain a VM identified by the given fragment.
  #[error("verification method not found")]
  VmNotFound,
  /// Storage doesn't contain VM's private key.
  #[error("corresponding private key not found in storage")]
  KeyNotFound,
  /// Unknown storage-related error.
  #[error(transparent)]
  StorageError(#[from] Box<dyn std::error::Error + Send + Sync>),
  /// Failed to construct VM's digest.
  #[error(transparent)]
  MethodDigestConstruction(#[from] MethodDigestConstructionError),
  /// The type of the resolved verification method is not supported.
  #[error("unsupported verification method type '{0}'")]
  UnsupportedVmType(Box<str>),
}

impl<'a, K, I> StorageSigner<'a, K, I>
where
  K: JwkStorage + OptionalSync,
  I: KeyIdStorage + OptionalSync,
{
  /// Creates a new [StorageSigner] from a given DID Document and a verification method fragment.
  /// ## Notes
  /// At this time, this function only supports "JsonWebKey2020"-based verification methods.
  pub async fn new_from_vm_fragment<D>(
    storage: &'a Storage<K, I>,
    document: &D,
    fragment: &str,
  ) -> Result<Self, StorageSignerFromVmError>
  where
    D: AsRef<CoreDocument>,
  {
    use StorageSignerFromVmError as Error;
    use StorageSignerFromVmErrorKind as ErrorKind;

    let document = document.as_ref();
    let make_err = |kind| Error {
      did: document.id().clone(),
      fragment: fragment.into(),
      kind,
    };

    // Resolve the given VM from the given DID and fragment.
    let vm = document
      .resolve_method(fragment, None)
      .ok_or_else(|| make_err(ErrorKind::VmNotFound))?;
    // Ensure the resolved VM has a supported type - AKA its embedded public key can be converted to a JWK.
    let MethodData::PublicKeyJwk(jwk) = vm.data() else {
      return Err(make_err(ErrorKind::UnsupportedVmType(vm.type_().as_str().into())));
    };

    // Find the corresponding private key in storage.
    let method_digest = MethodDigest::new(vm).map_err(|e| make_err(e.into()))?;
    let key_id = storage
      .key_id_storage
      .get_key_id(&method_digest)
      .await
      .map_err(|e| match e.kind() {
        KeyIdStorageErrorKind::KeyIdNotFound => make_err(ErrorKind::KeyNotFound),
        _ => make_err(ErrorKind::StorageError(e.into())),
      })?;

    Ok(Self::new(storage, key_id, jwk.clone()))
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
    PublicKey::from_jwk(&self.public_key)
      .map_err(|e| SecretStorageError::Other(anyhow!("failed to convert public key: {e}")))
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

#[cfg(feature = "sd-jwt-signer")]
mod sd_jwt_signer_integration {
  use crate::KeyStorageError;

  use super::*;
  use identity_verification::jwu::encode_b64;
  use identity_verification::jwu::encode_b64_json;
  use sd_jwt::JsonObject;
  use sd_jwt::JwsSigner;

  #[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
  #[cfg_attr(feature = "send-sync-storage", async_trait)]
  impl<K, I> JwsSigner for StorageSigner<'_, K, I>
  where
    K: JwkStorage + OptionalSync,
    I: OptionalSync,
  {
    type Error = KeyStorageError;
    async fn sign(&self, header: &JsonObject, payload: &JsonObject) -> Result<Vec<u8>, Self::Error> {
      let header_json = encode_b64_json(header)
        .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::SerializationError).with_source(e))?;
      let payload_json = encode_b64_json(payload)
        .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::SerializationError).with_source(e))?;

      let mut signing_input = format!("{header_json}.{payload_json}");

      let signature_bytes = self
        .storage
        .key_storage()
        .sign(&self.key_id, signing_input.as_bytes(), &self.public_key)
        .await?;

      signing_input.push('.');
      signing_input.push_str(&encode_b64(signature_bytes));

      Ok(signing_input.into_bytes())
    }
  }
}
