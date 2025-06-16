// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use crate::key_storage::KeyId;
use crate::key_storage::KeyType;
use async_trait::async_trait;
use identity_verification::jose::jws::JwsAlgorithm;
use identity_verification::jwk::PostQuantumJwk;

use super::jwk_gen_output::JwkGenOutput;
use super::JwkStorage;
use super::KeyStorageResult;

/// Extension to the JwkStorage to handle post-quantum keys.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait JwkStoragePQ: JwkStorage {
  /// Generates a JWK representing a PQ key.
  async fn generate_pq_key(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput>;

  /// Sign the provided `data` using a PQ algorithm, ctx is optional for the ctx paramter of the algorithm ML-DSA.
  async fn pq_sign(&self, key_id: &KeyId, data: &[u8], public_key: &PostQuantumJwk, ctx: Option<&[u8]>) -> KeyStorageResult<Vec<u8>>;
}