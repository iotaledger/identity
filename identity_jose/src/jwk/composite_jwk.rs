// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::jwk::{PostQuantumJwk, TraditionalJwk};
use crate::error::Error;

/// Algorithms used to generate hybrid signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub enum CompositeAlgId {
  /// DER encoded value in hex = 060B6086480186FA6B5008013E
  #[serde(rename = "id-MLDSA44-Ed25519")]
  IdMldsa44Ed25519,
  /// DER encoded value in hex = 060B6086480186FA6B50080147
  #[serde(rename = "id-MLDSA65-Ed25519")]
  IdMldsa65Ed25519,
}

impl CompositeAlgId {
  /// Returns the JWS algorithm as a `str` slice.
  pub const fn name(self) -> &'static str {
    match self {
      Self::IdMldsa44Ed25519 => "id-MLDSA44-Ed25519",
      Self::IdMldsa65Ed25519 => "id-MLDSA65-Ed25519",
    }
  }

  /// Returns the CompositeAlgId domain as a byte slice
  pub const fn domain(self) -> &'static [u8] {
    match self {
      Self::IdMldsa44Ed25519 => &[0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x3E],
      Self::IdMldsa65Ed25519 => &[0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x47],
    }
  }
}

/// Represent a combination of a traditional public key and a post-quantum public key both in Jwk format.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompositeJwk {
  alg_id: CompositeAlgId,
  traditional_public_key: TraditionalJwk,
  pq_public_key: PostQuantumJwk,
}

impl CompositeJwk {
  /// Create a new CompositePublicKey structure.
  pub fn new(alg_id: CompositeAlgId, traditional_public_key: TraditionalJwk, pq_public_key: PostQuantumJwk) -> Result<Self, Error>  {
    Ok(Self {
      alg_id,
      traditional_public_key: traditional_pk.to_public().unwrap(),
      pq_public_key: pq_pk.to_public().unwrap(),
    })

  }
  /// Get the `algId` value.
  pub fn alg_id(&self) -> CompositeAlgId {
    self.alg_id
  }
  /// Get the post-quantum public key in Jwk format.
  pub fn pq_public_key(&self) -> &PostQuantumJwk {
    &self.pq_public_key
  }
  /// Get the traditional public key in Jwk format.
  pub fn traditional_public_key(&self) -> &TraditionalJwk {
    &self.traditional_public_key
  }
}

impl FromStr for CompositeAlgId {
  type Err = crate::error::Error;

  fn from_str(string: &str) -> std::result::Result<Self, Self::Err> {
    match string {
      "id-MLDSA44-Ed25519" => Ok(Self::IdMldsa44Ed25519),
      "id-MLDSA65-Ed25519" => Ok(Self::IdMldsa65Ed25519),
      &_ => Err(crate::error::Error::JwsAlgorithmParsingError),
    }
  }
}
