// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use identity_verification::jwu::encode_b64;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::KeytoolStorage;

use crate::KeyId;

use super::KeyIdStorage;
use super::KeyIdStorageError;
use super::KeyIdStorageErrorKind;
use super::KeyIdStorageResult;
use super::MethodDigest;

const IDENTITY_VERIFICATION_METHOD_PREFIX: &str = "identity__";

#[cfg_attr(feature = "send-sync-storage", async_trait)]
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
impl KeyIdStorage for KeytoolStorage {
  async fn insert_key_id(&self, method_digest: MethodDigest, key_id: KeyId) -> KeyIdStorageResult<()> {
    let current_alias = key_id_to_alias(self, &key_id)?;
    let new_alias = encode_method_digest(&method_digest);

    self
      .update_alias(&current_alias, Some(&new_alias))
      .map_err(|e| KeyIdStorageError::new(KeyIdStorageErrorKind::RetryableIOFailure).with_source(e))
  }

  async fn get_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<KeyId> {
    let alias = encode_method_digest(method_digest);
    let pk = self
      .get_key_by_alias(&alias)
      .map_err(|e| KeyIdStorageError::new(KeyIdStorageErrorKind::RetryableIOFailure).with_source(e))?
      .ok_or(KeyIdStorageErrorKind::KeyIdNotFound)?;
    let address = IotaAddress::from(&pk);

    Ok(KeyId::new(address.to_string()))
  }

  async fn delete_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<()> {
    let alias = encode_method_digest(method_digest);
    self
      .update_alias(&alias, None)
      .map_err(|e| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(e))
  }
}

fn key_id_to_alias(keytool: &KeytoolStorage, key_id: &KeyId) -> KeyIdStorageResult<String> {
  let address = key_id.as_str().parse().map_err(|e| {
    KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified)
      .with_source(e)
      .with_custom_message("invalid key id. Key id must be an IOTA address")
  })?;
  let (_, alias) = keytool
    .get_key(address)
    .map_err(|e| KeyIdStorageError::new(KeyIdStorageErrorKind::RetryableIOFailure).with_source(e))?
    .ok_or(KeyIdStorageErrorKind::KeyIdNotFound)?;

  Ok(alias)
}

fn encode_method_digest(method_digest: &MethodDigest) -> String {
  let b64_method_digest = encode_b64(method_digest.pack());
  format!("{IDENTITY_VERIFICATION_METHOD_PREFIX}{b64_method_digest}")
}
