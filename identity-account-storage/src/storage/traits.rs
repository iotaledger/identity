// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;

use async_trait::async_trait;

use identity_core::crypto::PrivateKey;
use identity_core::crypto::PublicKey;
use identity_iota_core::did::IotaDID;

use crate::error::Result;
use crate::identity::ChainState;
use crate::identity::IdentityState;
use crate::types::KeyLocation;
use crate::types::Signature;
use crate::utils::EncryptionKey;

macro_rules! storage_trait {
  ($( $x:ident ),*) => {
    /// An interface for Identity Account storage implementations.
    ///
    /// See [MemStore][crate::storage::MemStore] for a test/example implementation.
    #[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
    #[cfg_attr(feature = "send-sync-storage", async_trait)]
    pub trait Storage: $($x + )* Debug + 'static {
      /// Sets the account password.
      async fn set_password(&self, password: EncryptionKey) -> Result<()>;

      /// Write any unsaved changes to disk.
      async fn flush_changes(&self) -> Result<()>;

      /// Creates a new keypair at the specified `location` and returns its `PublicKey`.
      async fn key_new(&self, did: &IotaDID, location: &KeyLocation) -> Result<PublicKey>;

      /// Inserts a private key at the specified `location` and returns its `PublicKey`.
      async fn key_insert(&self, did: &IotaDID, location: &KeyLocation, private_key: PrivateKey) -> Result<PublicKey>;

      /// Retrieves the public key at the specified `location`.
      async fn key_get(&self, did: &IotaDID, location: &KeyLocation) -> Result<PublicKey>;

      /// Deletes the keypair specified by `location`.
      async fn key_del(&self, did: &IotaDID, location: &KeyLocation) -> Result<()>;

      /// Signs `data` with the private key at the specified `location`.
      async fn key_sign(&self, did: &IotaDID, location: &KeyLocation, data: Vec<u8>) -> Result<Signature>;

      /// Returns `true` if a keypair exists at the specified `location`.
      async fn key_exists(&self, did: &IotaDID, location: &KeyLocation) -> Result<bool>;

      /// Returns the chain state of the identity specified by `did`.
      async fn chain_state(&self, did: &IotaDID) -> Result<Option<ChainState>>;

      /// Set the chain state of the identity specified by `did`.
      async fn set_chain_state(&self, did: &IotaDID, chain_state: &ChainState) -> Result<()>;

      /// Returns the state of the identity specified by `did`.
      async fn state(&self, did: &IotaDID) -> Result<Option<IdentityState>>;

      /// Sets a new state for the identity specified by `did`.
      async fn set_state(&self, did: &IotaDID, state: &IdentityState) -> Result<()>;

      /// Removes the keys and any state for the identity specified by `did`.
      async fn purge(&self, did: &IotaDID) -> Result<()>;
    }
  };
}

#[cfg(not(feature = "send-sync-storage"))]
storage_trait!();

#[cfg(feature = "send-sync-storage")]
storage_trait!(Send, Sync);
