// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use jsonprooftoken::jpa::algs::PresentationProofAlgorithm;
use jsonprooftoken::jwp::header::PresentationProtectedHeader;
use wasm_bindgen::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[wasm_bindgen(js_name = PresentationProofAlgorithm)]
#[allow(non_camel_case_types)]
pub enum WasmPresentationProofAlgorithm {
  BBS,
  BBS_SHAKE256,
  SU_ES256,
  SU_ES384,
  SU_ES512,
  MAC_H256,
  MAC_H384,
  MAC_H512,
  MAC_K25519,
  MAC_K448,
  MAC_H256K,
}

impl From<WasmPresentationProofAlgorithm> for PresentationProofAlgorithm {
  fn from(value: WasmPresentationProofAlgorithm) -> Self {
    match value {
      WasmPresentationProofAlgorithm::BBS => PresentationProofAlgorithm::BBS,
      WasmPresentationProofAlgorithm::BBS_SHAKE256 => PresentationProofAlgorithm::BBS_SHAKE256,
      WasmPresentationProofAlgorithm::SU_ES256 => PresentationProofAlgorithm::SU_ES256,
      WasmPresentationProofAlgorithm::SU_ES384 => PresentationProofAlgorithm::SU_ES384,
      WasmPresentationProofAlgorithm::SU_ES512 => PresentationProofAlgorithm::SU_ES512,
      WasmPresentationProofAlgorithm::MAC_H256 => PresentationProofAlgorithm::MAC_H256,
      WasmPresentationProofAlgorithm::MAC_H384 => PresentationProofAlgorithm::MAC_H384,
      WasmPresentationProofAlgorithm::MAC_H512 => PresentationProofAlgorithm::MAC_H512,
      WasmPresentationProofAlgorithm::MAC_K25519 => PresentationProofAlgorithm::MAC_K25519,
      WasmPresentationProofAlgorithm::MAC_K448 => PresentationProofAlgorithm::MAC_K448,
      WasmPresentationProofAlgorithm::MAC_H256K => PresentationProofAlgorithm::MAC_H256K,
    }
  }
}

impl From<PresentationProofAlgorithm> for WasmPresentationProofAlgorithm {
  fn from(value: PresentationProofAlgorithm) -> Self {
    match value {
      PresentationProofAlgorithm::BBS => WasmPresentationProofAlgorithm::BBS,
      PresentationProofAlgorithm::BBS_SHAKE256 => WasmPresentationProofAlgorithm::BBS_SHAKE256,
      PresentationProofAlgorithm::SU_ES256 => WasmPresentationProofAlgorithm::SU_ES256,
      PresentationProofAlgorithm::SU_ES384 => WasmPresentationProofAlgorithm::SU_ES384,
      PresentationProofAlgorithm::SU_ES512 => WasmPresentationProofAlgorithm::SU_ES512,
      PresentationProofAlgorithm::MAC_H256 => WasmPresentationProofAlgorithm::MAC_H256,
      PresentationProofAlgorithm::MAC_H384 => WasmPresentationProofAlgorithm::MAC_H384,
      PresentationProofAlgorithm::MAC_H512 => WasmPresentationProofAlgorithm::MAC_H512,
      PresentationProofAlgorithm::MAC_K25519 => WasmPresentationProofAlgorithm::MAC_K25519,
      PresentationProofAlgorithm::MAC_K448 => WasmPresentationProofAlgorithm::MAC_K448,
      PresentationProofAlgorithm::MAC_H256K => WasmPresentationProofAlgorithm::MAC_H256K,
    }
  }
}

#[wasm_bindgen(js_name = PresentationProtectedHeader, inspectable, getter_with_clone)]
pub struct WasmPresentationProtectedHeader {
  pub alg: WasmPresentationProofAlgorithm,
  /// ID for the key used for the JWP.
  pub kid: Option<String>,
  /// Who have received the JPT.
  pub aud: Option<String>,
  /// For replay attacks.
  pub nonce: Option<String>,
}

impl From<WasmPresentationProtectedHeader> for PresentationProtectedHeader {
  fn from(value: WasmPresentationProtectedHeader) -> Self {
    let WasmPresentationProtectedHeader { alg, kid, aud, nonce } = value;
    let mut protected_header = PresentationProtectedHeader::new(alg.into());
    protected_header.set_kid(kid);
    protected_header.set_aud(aud);
    protected_header.set_nonce(nonce);
    protected_header
  }
}

impl From<PresentationProtectedHeader> for WasmPresentationProtectedHeader {
  fn from(value: PresentationProtectedHeader) -> Self {
    let alg = value.alg().into();
    let kid = value.kid().cloned();
    let aud = value.aud().cloned();
    let nonce = value.nonce().cloned();

    WasmPresentationProtectedHeader { alg, kid, aud, nonce }
  }
}
