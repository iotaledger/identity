// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Formatter;
use core::fmt::Result as FmtResult;
use crypto::signatures::ed25519;
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use identity_core::crypto::Ed25519;
use identity_core::crypto::KeyPair;
use identity_core::crypto::KeyType;
use identity_core::crypto::PrivateKey;
use identity_core::crypto::PublicKey;
use identity_core::crypto::Sign;
use identity_did::verification::MethodType;
use identity_iota::did::IotaDID;
use std::convert::TryFrom;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;
use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::error::Error;
use crate::error::Result;
use crate::identity::ChainState;
use crate::identity::DIDLease;
use crate::identity::IdentityState;
use crate::storage::Storage;
use crate::types::Generation;
use crate::types::KeyLocation;
use crate::types::Signature;
use crate::utils::EncryptionKey;
use crate::utils::Shared;

type MemVault = HashMap<KeyLocation, KeyPair>;

type ChainStates = HashMap<IotaDID, ChainState>;
type States = HashMap<IotaDID, IdentityState>;
type Vaults = HashMap<IotaDID, MemVault>;
type PublishedGenerations = HashMap<IotaDID, Generation>;

pub struct MemStore {
  expand: bool,
  published_generations: Shared<PublishedGenerations>,
  did_leases: Mutex<HashMap<IotaDID, DIDLease>>,
  chain_states: Shared<ChainStates>,
  states: Shared<States>,
  vaults: Shared<Vaults>,
}

impl MemStore {
  pub fn new() -> Self {
    Self {
      expand: false,
      published_generations: Shared::new(HashMap::new()),
      did_leases: Mutex::new(HashMap::new()),
      chain_states: Shared::new(HashMap::new()),
      states: Shared::new(HashMap::new()),
      vaults: Shared::new(HashMap::new()),
    }
  }

  pub fn expand(&self) -> bool {
    self.expand
  }

  pub fn set_expand(&mut self, value: bool) {
    self.expand = value;
  }

  pub fn vaults(&self) -> Result<Vaults> {
    self.vaults.read().map(|data| data.clone())
  }
}

#[async_trait::async_trait]
impl Storage for MemStore {
  async fn set_password(&self, _password: EncryptionKey) -> Result<()> {
    Ok(())
  }

  async fn flush_changes(&self) -> Result<()> {
    Ok(())
  }

  async fn lease_did(&self, did: &IotaDID) -> Result<DIDLease> {
    let mut hmap = self.did_leases.lock().await;

    match hmap.entry(did.clone()) {
      Entry::Occupied(entry) => {
        if entry.get().load() {
          Err(Error::IdentityInUse)
        } else {
          entry.get().store(true);
          Ok(entry.get().clone())
        }
      }
      Entry::Vacant(entry) => {
        let did_lease = DIDLease::new();
        entry.insert(did_lease.clone());
        Ok(did_lease)
      }
    }
  }

  async fn key_new(&self, did: &IotaDID, location: &KeyLocation) -> Result<PublicKey> {
    let mut vaults: RwLockWriteGuard<'_, _> = self.vaults.write()?;
    let vault: &mut MemVault = vaults.entry(did.clone()).or_default();

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => {
        let keypair: KeyPair = KeyPair::new_ed25519()?;
        let public: PublicKey = keypair.public().clone();

        vault.insert(location.clone(), keypair);

        Ok(public)
      }
      MethodType::MerkleKeyCollection2021 => {
        todo!("[MemStore::key_new] Handle MerkleKeyCollection2021")
      }
    }
  }

  async fn key_insert(&self, did: &IotaDID, location: &KeyLocation, private_key: PrivateKey) -> Result<PublicKey> {
    let mut vaults: RwLockWriteGuard<'_, _> = self.vaults.write()?;
    let vault: &mut MemVault = vaults.entry(did.clone()).or_default();

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => {
        let mut private_key_bytes: [u8; 32] = <[u8; 32]>::try_from(private_key.as_ref())
          .map_err(|err| Error::InvalidPrivateKey(format!("expected a slice of 32 bytes - {}", err)))?;

        let secret: ed25519::SecretKey = ed25519::SecretKey::from_bytes(private_key_bytes);
        private_key_bytes.zeroize();

        let public: ed25519::PublicKey = secret.public_key();

        let public_key: PublicKey = public.to_bytes().to_vec().into();

        let keypair: KeyPair = KeyPair::from((KeyType::Ed25519, public_key.clone(), private_key));

        vault.insert(location.clone(), keypair);

        Ok(public_key)
      }
      MethodType::MerkleKeyCollection2021 => {
        todo!("[MemStore::key_insert] Handle MerkleKeyCollection2021")
      }
    }
  }

  async fn key_exists(&self, did: &IotaDID, location: &KeyLocation) -> Result<bool> {
    let vaults: RwLockReadGuard<'_, _> = self.vaults.read()?;

    if let Some(vault) = vaults.get(did) {
      return Ok(vault.contains_key(location));
    }

    Ok(false)
  }

  async fn key_get(&self, did: &IotaDID, location: &KeyLocation) -> Result<PublicKey> {
    let vaults: RwLockReadGuard<'_, _> = self.vaults.read()?;
    let vault: &MemVault = vaults.get(did).ok_or(Error::KeyVaultNotFound)?;
    let keypair: &KeyPair = vault.get(location).ok_or(Error::KeyNotFound)?;

    Ok(keypair.public().clone())
  }

  async fn key_del(&self, did: &IotaDID, location: &KeyLocation) -> Result<()> {
    let mut vaults: RwLockWriteGuard<'_, _> = self.vaults.write()?;
    let vault: &mut MemVault = vaults.get_mut(did).ok_or(Error::KeyVaultNotFound)?;

    vault.remove(location);

    Ok(())
  }

  async fn key_sign(&self, did: &IotaDID, location: &KeyLocation, data: Vec<u8>) -> Result<Signature> {
    let vaults: RwLockReadGuard<'_, _> = self.vaults.read()?;
    let vault: &MemVault = vaults.get(did).ok_or(Error::KeyVaultNotFound)?;
    let keypair: &KeyPair = vault.get(location).ok_or(Error::KeyNotFound)?;

    match location.method() {
      MethodType::Ed25519VerificationKey2018 => {
        assert_eq!(keypair.type_(), KeyType::Ed25519);

        let public: PublicKey = keypair.public().clone();
        let signature: [u8; 64] = Ed25519::sign(&data, keypair.private())?;
        let signature: Signature = Signature::new(public, signature.to_vec());

        Ok(signature)
      }
      MethodType::MerkleKeyCollection2021 => {
        todo!("[MemStore::key_sign] Handle MerkleKeyCollection2021")
      }
    }
  }

  async fn chain_state(&self, did: &IotaDID) -> Result<Option<ChainState>> {
    self.chain_states.read().map(|states| states.get(did).cloned())
  }

  async fn set_chain_state(&self, did: &IotaDID, chain_state: &ChainState) -> Result<()> {
    self.chain_states.write()?.insert(did.clone(), chain_state.clone());

    Ok(())
  }

  async fn state(&self, did: &IotaDID) -> Result<Option<IdentityState>> {
    self.states.read().map(|states| states.get(did).cloned())
  }

  async fn set_state(&self, did: &IotaDID, state: &IdentityState) -> Result<()> {
    self.states.write()?.insert(did.clone(), state.clone());

    Ok(())
  }

  async fn purge(&self, did: &IotaDID) -> Result<()> {
    let _ = self.states.write()?.remove(did);
    let _ = self.vaults.write()?.remove(did);
    let _ = self.chain_states.write()?.remove(did);

    Ok(())
  }

  async fn published_generation(&self, did: &IotaDID) -> Result<Option<Generation>> {
    Ok(self.published_generations.read()?.get(did).copied())
  }

  async fn set_published_generation(&self, did: &IotaDID, index: Generation) -> Result<()> {
    self.published_generations.write()?.insert(did.clone(), index);
    Ok(())
  }
}

impl Debug for MemStore {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    if self.expand {
      f.debug_struct("MemStore")
        .field("chain_states", &self.chain_states)
        .field("states", &self.states)
        .field("vaults", &self.vaults)
        .finish()
    } else {
      f.write_str("MemStore")
    }
  }
}

impl Default for MemStore {
  fn default() -> Self {
    Self::new()
  }
}
