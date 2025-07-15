// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::storage::ProofUpdateCtx;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = ProofUpdateCtx, inspectable, getter_with_clone)]
pub struct WasmProofUpdateCtx {
  /// Old `startValidityTimeframe` value
  pub old_start_validity_timeframe: Vec<u8>,
  /// New `startValidityTimeframe` value to be signed
  pub new_start_validity_timeframe: Vec<u8>,
  /// Old `endValidityTimeframe` value
  pub old_end_validity_timeframe: Vec<u8>,
  /// New `endValidityTimeframe` value to be signed
  pub new_end_validity_timeframe: Vec<u8>,
  /// Index of `startValidityTimeframe` claim inside the array of Claims
  pub index_start_validity_timeframe: usize,
  /// Index of `endValidityTimeframe` claim inside the array of Claims
  pub index_end_validity_timeframe: usize,
  /// Number of signed messages, number of payloads in a JWP
  pub number_of_signed_messages: usize,
}

impl From<ProofUpdateCtx> for WasmProofUpdateCtx {
  fn from(value: ProofUpdateCtx) -> Self {
    let ProofUpdateCtx {
      old_start_validity_timeframe,
      new_start_validity_timeframe,
      old_end_validity_timeframe,
      new_end_validity_timeframe,
      index_start_validity_timeframe,
      index_end_validity_timeframe,
      number_of_signed_messages,
    } = value;
    Self {
      old_start_validity_timeframe,
      new_start_validity_timeframe,
      old_end_validity_timeframe,
      new_end_validity_timeframe,
      index_start_validity_timeframe,
      index_end_validity_timeframe,
      number_of_signed_messages,
    }
  }
}

impl From<WasmProofUpdateCtx> for ProofUpdateCtx {
  fn from(value: WasmProofUpdateCtx) -> Self {
    let WasmProofUpdateCtx {
      old_start_validity_timeframe,
      new_start_validity_timeframe,
      old_end_validity_timeframe,
      new_end_validity_timeframe,
      index_start_validity_timeframe,
      index_end_validity_timeframe,
      number_of_signed_messages,
    } = value;
    Self {
      old_start_validity_timeframe,
      new_start_validity_timeframe,
      old_end_validity_timeframe,
      new_end_validity_timeframe,
      index_start_validity_timeframe,
      index_end_validity_timeframe,
      number_of_signed_messages,
    }
  }
}
