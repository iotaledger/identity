// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ImportedDocumentLock;
use crate::common::WasmTimestamp;
use crate::credential::options::WasmStatusCheck;
use crate::credential::WasmCredential;
use crate::credential::WasmJpt;
use crate::did::IToCoreDocument;
use crate::did::WasmCoreDID;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::core::Object;
use identity_iota::credential::JptCredentialValidatorUtils;
use identity_iota::did::CoreDID;
use wasm_bindgen::prelude::*;

/// Utility functions for validating JPT credentials.
#[wasm_bindgen(js_name = JptCredentialValidatorUtils)]
#[derive(Default)]
pub struct WasmJptCredentialValidatorUtils;

#[wasm_bindgen(js_class = JptCredentialValidatorUtils)]
impl WasmJptCredentialValidatorUtils {
  #[wasm_bindgen(constructor)]
  pub fn new() -> WasmJptCredentialValidatorUtils {
    WasmJptCredentialValidatorUtils
  }

  /// Utility for extracting the issuer field of a {@link Credential} as a DID.
  /// # Errors
  /// Fails if the issuer field is not a valid DID.
  #[wasm_bindgen(js_name = "extractIssuer")]
  pub fn extract_issuer(credential: &WasmCredential) -> Result<WasmCoreDID> {
    JptCredentialValidatorUtils::extract_issuer::<CoreDID, Object>(&credential.0)
      .wasm_result()
      .map(WasmCoreDID::from)
  }
  /// Utility for extracting the issuer field of a credential in JPT representation as DID.
  /// # Errors
  /// If the JPT decoding fails or the issuer field is not a valid DID.
  #[wasm_bindgen(js_name = "extractIssuerFromIssuedJpt")]
  pub fn extract_issuer_from_issued_jpt(credential: &WasmJpt) -> Result<WasmCoreDID> {
    JptCredentialValidatorUtils::extract_issuer_from_issued_jpt::<CoreDID>(&credential.0)
      .wasm_result()
      .map(WasmCoreDID::from)
  }

  #[wasm_bindgen(js_name = "checkTimeframesWithValidityTimeframe2024")]
  pub fn check_timeframes_with_validity_timeframe_2024(
    credential: &WasmCredential,
    validity_timeframe: Option<WasmTimestamp>,
    status_check: WasmStatusCheck,
  ) -> Result<()> {
    JptCredentialValidatorUtils::check_timeframes_with_validity_timeframe_2024(
      &credential.0,
      validity_timeframe.map(|t| t.0),
      status_check.into(),
    )
    .wasm_result()
  }

  /// Checks whether the credential status has been revoked.
  ///
  /// Only supports `RevocationTimeframe2024`.
  #[wasm_bindgen(js_name = "checkRevocationWithValidityTimeframe2024")]
  pub fn check_revocation_with_validity_timeframe_2024(
    credential: &WasmCredential,
    issuer: &IToCoreDocument,
    status_check: WasmStatusCheck,
  ) -> Result<()> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock.try_read()?;
    JptCredentialValidatorUtils::check_revocation_with_validity_timeframe_2024(
      &credential.0,
      &issuer_guard,
      status_check.into(),
    )
    .wasm_result()
  }

  /// Checks whether the credential status has been revoked or the timeframe interval is INVALID
  ///
  /// Only supports `RevocationTimeframe2024`.
  #[wasm_bindgen(js_name = "checkTimeframesAndRevocationWithValidityTimeframe2024")]
  pub fn check_timeframes_and_revocation_with_validity_timeframe_2024(
    credential: &WasmCredential,
    issuer: &IToCoreDocument,
    validity_timeframe: Option<WasmTimestamp>,
    status_check: WasmStatusCheck,
  ) -> Result<()> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock.try_read()?;
    JptCredentialValidatorUtils::check_timeframes_and_revocation_with_validity_timeframe_2024(
      &credential.0,
      &issuer_guard,
      validity_timeframe.map(|t| t.0),
      status_check.into(),
    )
    .wasm_result()
  }
}
