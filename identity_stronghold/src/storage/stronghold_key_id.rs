// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::utils::IDENTITY_CLIENT_PATH;
use crate::StrongholdStorage;
use async_trait::async_trait;
use identity_storage::key_id_storage::KeyIdStorage;
use identity_storage::key_id_storage::KeyIdStorageResult;
use identity_storage::key_id_storage::MethodDigest;
use identity_storage::key_storage::KeyId;
use identity_storage::KeyIdStorageError;
use identity_storage::KeyIdStorageErrorKind;
use iota_stronghold::Client;
use iota_stronghold::ClientError;
use iota_stronghold::Stronghold;
use tokio::sync::MutexGuard;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyIdStorage for StrongholdStorage {
  async fn insert_key_id(&self, method_digest: MethodDigest, key_id: KeyId) -> KeyIdStorageResult<()> {
    let stronghold = self.get_stronghold().await;
    let client = get_client(&stronghold)?;
    let store = client.store();
    let method_digest_pack = method_digest.pack();
    let key_exists = store
      .contains_key(method_digest_pack.as_ref())
      .map_err(|err| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err))?;

    if key_exists {
      return Err(KeyIdStorageError::new(KeyIdStorageErrorKind::KeyIdAlreadyExists));
    }
    let key_id: String = key_id.into();
    client
      .store()
      .insert(method_digest_pack, key_id.into(), None)
      .map_err(|err| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err))?;
    persist_changes(self, stronghold).await?;
    Ok(())
  }

  async fn get_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<KeyId> {
    let stronghold = self.get_stronghold().await;
    let store = get_client(&stronghold)?.store();
    let method_digest_pack: Vec<u8> = method_digest.pack();
    let key_id_bytes: Vec<u8> = store
      .get(method_digest_pack.as_ref())
      .map_err(|err| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err))?
      .ok_or(KeyIdStorageError::new(KeyIdStorageErrorKind::KeyIdNotFound))?;

    let key_id: KeyId = KeyId::new(
      String::from_utf8(key_id_bytes)
        .map_err(|err| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err))?,
    );
    Ok(key_id)
  }

  async fn delete_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<()> {
    let stronghold = self.get_stronghold().await;
    let store = get_client(&stronghold)?.store();
    let key: Vec<u8> = method_digest.pack();

    let _ = store
      .delete(key.as_ref())
      .map_err(|err| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err))?
      .ok_or(KeyIdStorageError::new(KeyIdStorageErrorKind::KeyIdNotFound))?;

    persist_changes(self, stronghold).await?;
    Ok(())
  }
}

fn get_client(stronghold: &Stronghold) -> KeyIdStorageResult<Client> {
  let client = stronghold.get_client(IDENTITY_CLIENT_PATH);
  match client {
    Ok(client) => Ok(client),
    Err(ClientError::ClientDataNotPresent) => load_or_create_client(stronghold),
    Err(err) => Err(KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err)),
  }
}

fn load_or_create_client(stronghold: &Stronghold) -> KeyIdStorageResult<Client> {
  match stronghold.load_client(IDENTITY_CLIENT_PATH) {
    Ok(client) => Ok(client),
    Err(ClientError::ClientDataNotPresent) => stronghold
      .create_client(IDENTITY_CLIENT_PATH)
      .map_err(|err| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err)),
    Err(err) => Err(KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err)),
  }
}

async fn persist_changes(
  secret_manager: &StrongholdStorage,
  stronghold: MutexGuard<'_, Stronghold>,
) -> KeyIdStorageResult<()> {
  stronghold.write_client(IDENTITY_CLIENT_PATH).map_err(|err| {
    KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified)
      .with_custom_message("stronghold write client error")
      .with_source(err)
  })?;
  // Must be dropped since `write_stronghold_snapshot` requires the stronghold instance.
  drop(stronghold);
  match secret_manager.as_secret_manager() {
    iota_sdk::client::secret::SecretManager::Stronghold(stronghold_manager) => {
      stronghold_manager
        .write_stronghold_snapshot(None)
        .await
        .map_err(|err| {
          KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified)
            .with_custom_message("writing to stronghold snapshot failed")
            .with_source(err)
        })?;
    }
    _ => {
      return Err(
        KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified)
          .with_custom_message("secret manager is not of type stronghold"),
      )
    }
  };

  Ok(())
}
