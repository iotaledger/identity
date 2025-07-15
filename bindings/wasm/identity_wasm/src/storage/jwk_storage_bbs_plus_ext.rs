// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::error::Result as WasmResult;
use crate::error::WasmResult as _;
use crate::jose::WasmJwk;
use crate::jpt::WasmProofAlgorithm;

use super::WasmJwkGenOutput;
use super::WasmJwkStorage;
use super::WasmProofUpdateCtx;

use identity_iota::storage::bls::encode_bls_jwk;
use identity_iota::storage::bls::expand_bls_jwk;
use identity_iota::storage::bls::generate_bbs_keypair;
use identity_iota::storage::bls::sign_bbs;
use identity_iota::storage::bls::update_bbs_signature;
use identity_iota::storage::JwkGenOutput;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::JwkStorageBbsPlusExt;
use identity_iota::storage::KeyId;
use identity_iota::storage::KeyStorageError;
use identity_iota::storage::KeyStorageErrorKind;
use identity_iota::storage::KeyStorageResult;
use identity_iota::storage::KeyType;
use identity_iota::storage::ProofUpdateCtx;
use identity_iota::verification::jwk::Jwk;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_class = JwkStorage)]
impl WasmJwkStorage {
  #[wasm_bindgen(js_name = generateBBS)]
  /// Generates a new BBS+ keypair.
  pub async fn _generate_bbs(&self, alg: WasmProofAlgorithm) -> WasmResult<WasmJwkGenOutput> {
    self
      .generate_bbs(KeyType::from_static_str("BLS12381"), alg.into())
      .await
      .map(WasmJwkGenOutput::from)
      .wasm_result()
  }

  #[wasm_bindgen(js_name = signBBS)]
  pub async fn _sign_bbs(
    &self,
    key_id: String,
    data: Vec<js_sys::Uint8Array>,
    public_key: WasmJwk,
    header: Option<Vec<u8>>,
  ) -> WasmResult<js_sys::Uint8Array> {
    let key_id = KeyId::new(key_id);
    let data = data.into_iter().map(|arr| arr.to_vec()).collect::<Vec<_>>();
    let header = header.unwrap_or_default();
    self
      .sign_bbs(&key_id, &data, header.as_slice(), &public_key.into())
      .await
      .map(|v| js_sys::Uint8Array::from(v.as_slice()))
      .wasm_result()
  }

  #[wasm_bindgen(js_name = updateBBSSignature)]
  pub async fn _update_signature(
    &self,
    key_id: String,
    public_key: &WasmJwk,
    signature: Vec<u8>,
    ctx: WasmProofUpdateCtx,
  ) -> WasmResult<js_sys::Uint8Array> {
    let key_id = KeyId::new(key_id);
    self
      .update_signature(&key_id, &public_key.0, &signature, ctx.into())
      .await
      .map(|sig| js_sys::Uint8Array::from(sig.as_slice()))
      .wasm_result()
  }
}

#[async_trait::async_trait(?Send)]
impl JwkStorageBbsPlusExt for WasmJwkStorage {
  async fn generate_bbs(&self, _key_type: KeyType, alg: ProofAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    let (sk, pk) = generate_bbs_keypair(alg)?;

    let (jwk, public_jwk) = encode_bls_jwk(&sk, &pk, alg);
    let kid = <Self as JwkStorage>::insert(self, jwk).await?;

    Ok(JwkGenOutput::new(kid, public_jwk))
  }
  async fn sign_bbs(
    &self,
    key_id: &KeyId,
    data: &[Vec<u8>],
    header: &[u8],
    public_key: &Jwk,
  ) -> KeyStorageResult<Vec<u8>> {
    let Some(private_jwk) = WasmJwkStorage::_get_key(self, key_id.as_str()).map(Jwk::from) else {
      return Err(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound));
    };
    // Extract the required alg from the given public key
    let alg = public_key
      .alg()
      .ok_or(KeyStorageErrorKind::UnsupportedProofAlgorithm)
      .and_then(|alg_str| {
        ProofAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedProofAlgorithm)
      })?;

    let (sk, pk) = expand_bls_jwk(&private_jwk)?;
    sign_bbs(alg, data, &sk.expect("jwk was private"), &pk, header)
  }
  async fn update_signature(
    &self,
    key_id: &KeyId,
    public_key: &Jwk,
    signature: &[u8],
    ctx: ProofUpdateCtx,
  ) -> KeyStorageResult<Vec<u8>> {
    // Extract the required alg from the given public key
    let alg = public_key
      .alg()
      .ok_or(KeyStorageErrorKind::UnsupportedProofAlgorithm)
      .and_then(|alg_str| {
        ProofAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedProofAlgorithm)
      })?;

    let Some(private_jwk) = WasmJwkStorage::_get_key(self, key_id.as_str()).map(Jwk::from) else {
      return Err(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound));
    };
    let sk = expand_bls_jwk(&private_jwk)?.0.expect("jwk is private");
    update_bbs_signature(alg, signature, &sk, &ctx)
  }
}
