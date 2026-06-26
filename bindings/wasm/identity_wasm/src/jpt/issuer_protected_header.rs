// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::jpt::WasmProofAlgorithm;
use jsonprooftoken::jwp::header::IssuerProtectedHeader;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = IssuerProtectedHeader, getter_with_clone, inspectable)]
pub struct WasmIssuerProtectedHeader {
  /// JWP type (JPT).
  pub typ: Option<String>,
  /// Algorithm used for the JWP.
  pub alg: WasmProofAlgorithm,
  /// ID for the key used for the JWP.
  pub kid: Option<String>,
  /// Not handled for now. Will be used in the future to resolve external claims
  pub cid: Option<String>,
  /// Claims.
  claims: Vec<String>,
}

#[wasm_bindgen(js_class = IssuerProtectedHeader)]
impl WasmIssuerProtectedHeader {
  #[wasm_bindgen]
  pub fn claims(&self) -> Vec<String> {
    self.claims.clone()
  }
}

impl From<WasmIssuerProtectedHeader> for IssuerProtectedHeader {
  fn from(value: WasmIssuerProtectedHeader) -> Self {
    let WasmIssuerProtectedHeader { typ, alg, kid, cid, .. } = value;
    let mut header = IssuerProtectedHeader::new(alg.into());
    header.set_typ(typ);
    header.set_kid(kid);
    header.set_cid(cid);

    header
  }
}

impl From<IssuerProtectedHeader> for WasmIssuerProtectedHeader {
  fn from(value: IssuerProtectedHeader) -> Self {
    WasmIssuerProtectedHeader {
      typ: value.typ().cloned(),
      alg: value.alg().into(),
      kid: value.kid().cloned(),
      cid: value.cid().cloned(),
      claims: value.claims().map(|claims| claims.clone().0).unwrap_or_default(),
    }
  }
}
