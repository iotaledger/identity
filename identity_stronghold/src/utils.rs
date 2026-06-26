// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_storage::KeyId;
use identity_storage::KeyStorageError;
use identity_storage::KeyStorageErrorKind;
use identity_storage::KeyStorageResult;
use identity_verification::jws::JwsAlgorithm;
use iota_sdk::client::secret::SecretManager;
use iota_stronghold::Client;
use iota_stronghold::ClientError;
use iota_stronghold::Stronghold;
use rand::distributions::DistString as _;
use tokio::sync::MutexGuard;

use crate::stronghold_key_type::StrongholdKeyType;

pub static IDENTITY_VAULT_PATH: &str = "iota_identity_vault";
pub static IDENTITY_CLIENT_PATH: &[u8] = b"iota_identity_client";

/// Generate a random alphanumeric string of len 32.
pub fn random_key_id() -> KeyId {
  KeyId::new(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32))
}

/// Check that the key type can be used with the algorithm.
pub fn check_key_alg_compatibility(key_type: StrongholdKeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()> {
  match (key_type, alg) {
    (StrongholdKeyType::Ed25519, JwsAlgorithm::EdDSA) => Ok(()),
    (key_type, alg) => Err(
      KeyStorageError::new(identity_storage::KeyStorageErrorKind::KeyAlgorithmMismatch)
        .with_custom_message(format!("cannot use key type `{key_type}` with algorithm `{alg}`")),
    ),
  }
}

pub fn get_client(stronghold: &Stronghold) -> KeyStorageResult<Client> {
  let client = stronghold.get_client(IDENTITY_CLIENT_PATH);
  match client {
    Ok(client) => Ok(client),
    Err(ClientError::ClientDataNotPresent) => load_or_create_client(stronghold),
    Err(err) => Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
  }
}

fn load_or_create_client(stronghold: &Stronghold) -> KeyStorageResult<Client> {
  match stronghold.load_client(IDENTITY_CLIENT_PATH) {
    Ok(client) => Ok(client),
    Err(ClientError::ClientDataNotPresent) => stronghold
      .create_client(IDENTITY_CLIENT_PATH)
      .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
    Err(err) => Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
  }
}

pub async fn persist_changes(
  secret_manager: &SecretManager,
  stronghold: MutexGuard<'_, Stronghold>,
) -> KeyStorageResult<()> {
  stronghold.write_client(IDENTITY_CLIENT_PATH).map_err(|err| {
    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
      .with_custom_message("stronghold write client error")
      .with_source(err)
  })?;
  // Must be dropped since `write_stronghold_snapshot` needs to acquire the stronghold lock.
  drop(stronghold);

  match secret_manager {
    iota_sdk::client::secret::SecretManager::Stronghold(stronghold_manager) => {
      stronghold_manager
        .write_stronghold_snapshot(None)
        .await
        .map_err(|err| {
          KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("writing to stronghold snapshot failed")
            .with_source(err)
        })?;
    }
    _ => {
      return Err(
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
          .with_custom_message("secret manager is not of type stronghold"),
      )
    }
  };
  Ok(())
}
