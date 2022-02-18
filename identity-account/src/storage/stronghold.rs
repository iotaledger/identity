// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::keys::slip10::Chain;
use futures::executor;

use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_core::crypto::PrivateKey;
use identity_core::crypto::PublicKey;
use identity_did::did::DID;
use identity_did::verification::MethodType;
use identity_iota::did::IotaDID;
use iota_stronghold::Location;
use iota_stronghold::SLIP10DeriveInput;
use std::convert::TryFrom;
use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::error::Result;
use crate::identity::ChainState;
use crate::identity::IdentityState;
use crate::storage::Storage;
use crate::stronghold::default_hint;
use crate::stronghold::Snapshot;
use crate::stronghold::Store;
use crate::stronghold::Vault;
use crate::types::Generation;
use crate::types::KeyLocation;
use crate::types::Signature;
use crate::utils::derive_encryption_key;
use crate::utils::EncryptionKey;

#[derive(Debug)]
pub struct Stronghold {
  snapshot: Arc<Snapshot>,
  dropsave: bool,
}

impl Stronghold {
  pub async fn new<'a, T, U>(snapshot: &T, password: U, dropsave: Option<bool>) -> Result<Self>
  where
    T: AsRef<Path> + ?Sized,
    U: Into<Option<&'a str>>,
  {
    let snapshot: Snapshot = Snapshot::new(snapshot);

    if let Some(password) = password.into() {
      snapshot.load(derive_encryption_key(password)).await?;
    }

    Ok(Self {
      snapshot: Arc::new(snapshot),
      dropsave: dropsave.unwrap_or(true),
    })
  }

  fn store(&self, name: &str) -> Store<'_> {
    self.snapshot.store(name, &[])
  }

  fn vault(&self, id: &IotaDID) -> Vault<'_> {
    self.snapshot.vault(&fmt_did(id), &[])
  }

  /// Returns whether save-on-drop is enabled.
  pub fn dropsave(&self) -> bool {
    self.dropsave
  }

  /// Set whether to save the storage changes on drop.
  /// Default: true
  pub fn set_dropsave(&mut self, value: bool) {
    self.dropsave = value;
  }
}

#[async_trait::async_trait]
impl Storage for Stronghold {
  async fn set_password(&self, password: EncryptionKey) -> Result<()> {
    self.snapshot.set_password(password).await
  }

  async fn flush_changes(&self) -> Result<()> {
    self.snapshot.save().await
  }

  async fn key_new(&self, did: &IotaDID, location: &KeyLocation) -> Result<PublicKey> {
    let vault: Vault<'_> = self.vault(did);

    let public: PublicKey = match location.method() {
      MethodType::Ed25519VerificationKey2018 => generate_ed25519(&vault, location).await?,
      MethodType::MerkleKeyCollection2021 => todo!("[Stronghold::key_new] Handle MerkleKeyCollection2021"),
    };

    Ok(public)
  }

  async fn key_insert(&self, did: &IotaDID, location: &KeyLocation, private_key: PrivateKey) -> Result<PublicKey> {
    let vault = self.vault(did);

    vault
      .insert(location_skey(location), private_key.as_ref(), default_hint(), &[])
      .await?;

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => retrieve_ed25519(&vault, location).await,
      MethodType::MerkleKeyCollection2021 => todo!("[Stronghold::key_insert] Handle MerkleKeyCollection2021"),
    }
  }

  async fn key_get(&self, did: &IotaDID, location: &KeyLocation) -> Result<PublicKey> {
    let vault: Vault<'_> = self.vault(did);

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => retrieve_ed25519(&vault, location).await,
      MethodType::MerkleKeyCollection2021 => todo!("[Stronghold::key_get] Handle MerkleKeyCollection2021"),
    }
  }

  async fn key_del(&self, did: &IotaDID, location: &KeyLocation) -> Result<()> {
    let vault: Vault<'_> = self.vault(did);

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => {
        vault.delete(location_seed(location), false).await?;
        vault.delete(location_skey(location), false).await?;

        // TODO: Garbage Collection (?)
      }
      MethodType::MerkleKeyCollection2021 => todo!("[Stronghold::key_del] Handle MerkleKeyCollection2021"),
    }

    Ok(())
  }

  async fn key_sign(&self, did: &IotaDID, location: &KeyLocation, data: Vec<u8>) -> Result<Signature> {
    let vault: Vault<'_> = self.vault(did);

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => sign_ed25519(&vault, data, location).await,
      MethodType::MerkleKeyCollection2021 => todo!("[Stronghold::key_sign] Handle MerkleKeyCollection2021"),
    }
  }

  async fn key_exists(&self, did: &IotaDID, location: &KeyLocation) -> Result<bool> {
    let vault: Vault<'_> = self.vault(did);

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => vault.exists(location_skey(location)).await,
      MethodType::MerkleKeyCollection2021 => todo!("[Stronghold::key_exists] Handle MerkleKeyCollection2021"),
    }
  }

  async fn chain_state(&self, did: &IotaDID) -> Result<Option<ChainState>> {
    // Load the chain-specific store
    let store: Store<'_> = self.store(&fmt_did(did));

    let data: Vec<u8> = store.get(location_chain_state()).await?;

    if data.is_empty() {
      return Ok(None);
    }

    Ok(Some(ChainState::from_json_slice(&data)?))
  }

  async fn set_chain_state(&self, did: &IotaDID, chain_state: &ChainState) -> Result<()> {
    // Load the chain-specific store
    let store: Store<'_> = self.store(&fmt_did(did));

    let json: Vec<u8> = chain_state.to_json_vec()?;

    store.set(location_chain_state(), json, None).await?;

    Ok(())
  }

  async fn state(&self, did: &IotaDID) -> Result<Option<IdentityState>> {
    // Load the chain-specific store
    let store: Store<'_> = self.store(&fmt_did(did));

    // Read the state from the stronghold snapshot
    let data: Vec<u8> = store.get(location_state()).await?;

    // No state data found
    if data.is_empty() {
      return Ok(None);
    }

    // Deserialize and return
    Ok(Some(IdentityState::from_json_slice(&data)?))
  }

  async fn set_state(&self, did: &IotaDID, state: &IdentityState) -> Result<()> {
    // Load the chain-specific store
    let store: Store<'_> = self.store(&fmt_did(did));

    // Serialize the state
    let json: Vec<u8> = state.to_json_vec()?;

    // Write the state to the stronghold snapshot
    store.set(location_state(), json, None).await?;

    Ok(())
  }

  async fn purge(&self, _did: &IotaDID) -> Result<()> {
    // TODO: Will be re-implemented later with the key location refactor
    todo!("stronghold purge not implemented");
  }

  async fn published_generation(&self, did: &IotaDID) -> Result<Option<Generation>> {
    let store: Store<'_> = self.store(&fmt_did(did));

    let bytes = store.get(location_published_generation()).await?;

    if bytes.is_empty() {
      return Ok(None);
    }

    let le_bytes: [u8; 4] = <[u8; 4]>::try_from(bytes.as_ref()).map_err(|_| {
      io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
          "expected to read 4 bytes as the published generation, found {} instead",
          bytes.len()
        ),
      )
    })?;

    let gen = Generation::from_u32(u32::from_le_bytes(le_bytes));

    Ok(Some(gen))
  }

  async fn set_published_generation(&self, did: &IotaDID, index: Generation) -> Result<()> {
    let store: Store<'_> = self.store(&fmt_did(did));

    store
      .set(location_published_generation(), index.to_u32().to_le_bytes(), None)
      .await?;

    Ok(())
  }
}

impl Drop for Stronghold {
  fn drop(&mut self) {
    if self.dropsave {
      let _ = executor::block_on(self.flush_changes());
    }
  }
}

async fn generate_ed25519(vault: &Vault<'_>, location: &KeyLocation) -> Result<PublicKey> {
  // Generate a SLIP10 seed as the private key
  vault
    .slip10_generate(location_seed(location), default_hint(), None)
    .await?;

  let chain: Chain = Chain::from_u32_hardened(vec![0, 0, 0]);
  let seed: SLIP10DeriveInput = SLIP10DeriveInput::Seed(location_seed(location));

  // Use the SLIP10 seed to derive a child key
  vault
    .slip10_derive(chain, seed, location_skey(location), default_hint())
    .await?;

  // Retrieve the public key of the derived child key
  retrieve_ed25519(vault, location).await
}

async fn retrieve_ed25519(vault: &Vault<'_>, location: &KeyLocation) -> Result<PublicKey> {
  vault
    .ed25519_public_key(location_skey(location))
    .await
    .map(|public| public.to_vec().into())
}

async fn sign_ed25519(vault: &Vault<'_>, payload: Vec<u8>, location: &KeyLocation) -> Result<Signature> {
  let public_key: PublicKey = retrieve_ed25519(vault, location).await?;
  let signature: [u8; 64] = vault.ed25519_sign(payload, location_skey(location)).await?;

  Ok(Signature::new(public_key, signature.into()))
}

fn location_chain_state() -> Location {
  Location::generic("$chain_state", Vec::new())
}

fn location_state() -> Location {
  Location::generic("$state", Vec::new())
}

fn location_seed(location: &KeyLocation) -> Location {
  Location::generic(fmt_key("$seed", location), Vec::new())
}

fn location_skey(location: &KeyLocation) -> Location {
  Location::generic(fmt_key("$skey", location), Vec::new())
}

fn location_published_generation() -> Location {
  Location::generic("$published_generation", Vec::new())
}

fn fmt_key(prefix: &str, location: &KeyLocation) -> Vec<u8> {
  format!("{}:{}:{}", prefix, location.generation(), location.fragment_name()).into_bytes()
}

fn fmt_did(did: &IotaDID) -> String {
  format!("$identity:{}", did.authority())
}
