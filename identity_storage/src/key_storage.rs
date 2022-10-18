// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use async_trait::async_trait;
use identity_core::crypto::PublicKey;

use crate::KeyAlias;
use crate::MethodType1;
use crate::Signature;
use crate::StorageResult;

#[cfg(not(feature = "send-sync-storage"))]
mod storage_sub_trait {
  pub trait StorageSendSyncMaybe {}
  impl<S: super::KeyStorage> StorageSendSyncMaybe for S {}
}

#[cfg(feature = "send-sync-storage")]
mod storage_sub_trait {
  pub trait StorageSendSyncMaybe: Send + Sync {}
  impl<S: Send + Sync + super::KeyStorage> StorageSendSyncMaybe for S {}
}

// TODO: Make sealed.
pub trait SealedAbstractKeyType {}

impl<T> SealedAbstractKeyType for T
where
  T: TryFrom<MethodType1> + Send + Sync + 'static,
  <T as TryFrom<MethodType1>>::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
// TODO: Copy docs from legacy `Storage` interface.
pub trait KeyStorage: storage_sub_trait::StorageSendSyncMaybe {
  type KeyType: SealedAbstractKeyType;
  type SigningAlgorithm: Send + Sync + 'static;

  async fn generate(&self, key_type: Self::KeyType) -> StorageResult<KeyAlias>;
  // async fn import(key_type: KeyType, private_key: PrivateKey) -> StorageResult<KeyAlias>;
  async fn public(&self, private_key: &KeyAlias) -> StorageResult<PublicKey>;
  // async fn delete(private_key: &KeyAlias) -> StorageResult<bool>;
  async fn sign<SIG: Send + Into<Self::SigningAlgorithm>>(
    &self,
    private_key: &KeyAlias,
    signing_algorithm: SIG,
    data: Vec<u8>,
  ) -> StorageResult<Signature>;
  // async fn encrypt(
  //   plaintext: Vec<u8>,
  //   associated_data: Vec<u8>,
  //   encryption_algorithm: &EncryptionAlgorithm,
  //   cek_algorithm: &CekAlgorithm,
  //   public_key: PublicKey,
  // ) -> StorageResult<EncryptedData>;
  // async fn decrypt(
  //   private_key: &KeyAlias,
  //   data: EncryptedData,
  //   encryption_algorithm: &EncryptionAlgorithm,
  //   cek_algorithm: &CekAlgorithm,
  // ) -> Vec<u8>;
  // async fn flush(&self) -> StorageResult<()>;
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<T> KeyStorage for Arc<T>
where
  T: KeyStorage,
  T::KeyType: Send,
{
  type KeyType = T::KeyType;
  type SigningAlgorithm = T::SigningAlgorithm;

  async fn generate(&self, key_type: Self::KeyType) -> StorageResult<KeyAlias> {
    T::generate(self, key_type).await
  }

  async fn public(&self, private_key: &KeyAlias) -> StorageResult<PublicKey> {
    T::public(self, private_key).await
  }

  async fn sign<SIG: Send + Into<Self::SigningAlgorithm>>(
    &self,
    private_key: &KeyAlias,
    signing_algorithm: SIG,
    data: Vec<u8>,
  ) -> StorageResult<Signature> {
    T::sign(self, private_key, signing_algorithm, data).await
  }
}
