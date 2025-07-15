// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::WasmTimestamp;
use crate::credential::options::WasmStatusCheck;
use crate::credential::WasmCredential;
use crate::credential::WasmJpt;
use crate::did::WasmCoreDID;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::JptPresentationValidatorUtils;
use wasm_bindgen::prelude::*;

/// Utility functions for verifying JPT presentations.
#[wasm_bindgen(js_name = JptPresentationValidatorUtils)]
pub struct WasmJptPresentationValidatorUtils;

#[wasm_bindgen(js_class = JptPresentationValidatorUtils)]
impl WasmJptPresentationValidatorUtils {
  /// Utility for extracting the issuer field of a credential in JPT representation as DID.
  /// # Errors
  /// If the JPT decoding fails or the issuer field is not a valid DID.
  #[wasm_bindgen(js_name = "extractIssuerFromPresentedJpt")]
  pub fn extract_issuer_from_presented_jpt(presentation: &WasmJpt) -> Result<WasmCoreDID> {
    JptPresentationValidatorUtils::extract_issuer_from_presented_jpt(&presentation.0)
      .wasm_result()
      .map(WasmCoreDID)
  }

  /// Check timeframe interval in credentialStatus with `RevocationTimeframeStatus`.
  #[wasm_bindgen(js_name = "checkTimeframesWithValidityTimeframe2024")]
  pub fn check_timeframes_with_validity_timeframe_2024(
    credential: &WasmCredential,
    validity_timeframe: Option<WasmTimestamp>,
    status_check: WasmStatusCheck,
  ) -> Result<()> {
    JptPresentationValidatorUtils::check_timeframes_with_validity_timeframe_2024(
      &credential.0,
      validity_timeframe.map(|t| t.0),
      status_check.into(),
    )
    .wasm_result()
  }
}
