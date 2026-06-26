// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use identity_verification::jwk::Jwk;
use jsonprooftoken::jpa::algs::ProofAlgorithm;

use crate::JwkGenOutput;
use crate::JwkStorage;
use crate::KeyId;
use crate::KeyStorageResult;
use crate::KeyType;
use crate::ProofUpdateCtx;

/// Extension to the JwkStorage to handle BBS+ keys
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait JwkStorageBbsPlusExt: JwkStorage {
  /// Generates a JWK representing a BBS+ signature
  async fn generate_bbs(&self, key_type: KeyType, alg: ProofAlgorithm) -> KeyStorageResult<JwkGenOutput>;

  /// Sign the provided `data` and `header` using the private key identified by `key_id` according to the requirements
  /// of the corresponding `public_key` (see [`Jwk::alg`](Jwk::alg()) etc.).
  async fn sign_bbs(
    &self,
    key_id: &KeyId,
    data: &[Vec<u8>],
    header: &[u8],
    public_key: &Jwk,
  ) -> KeyStorageResult<Vec<u8>>;

  /// Update proof functionality for timeframe revocation mechanism
  async fn update_signature(
    &self,
    key_id: &KeyId,
    public_key: &Jwk,
    signature: &[u8],
    ctx: ProofUpdateCtx,
  ) -> KeyStorageResult<Vec<u8>>;
}
