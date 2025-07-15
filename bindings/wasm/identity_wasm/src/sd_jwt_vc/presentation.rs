// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::sd_jwt_vc::SdJwtVcPresentationBuilder;
use wasm_bindgen::prelude::wasm_bindgen;

use super::sd_jwt_v2::WasmDisclosure;
use super::sd_jwt_v2::WasmHasher;
use super::sd_jwt_v2::WasmKeyBindingJwt;
use super::WasmSdJwtVc;
use crate::error::Result;
use crate::error::WasmResult;

#[wasm_bindgen(js_name = SdJwtVcPresentationBuilder)]
pub struct WasmSdJwtVcPresentationBuilder(pub(crate) SdJwtVcPresentationBuilder);

#[wasm_bindgen(js_class = SdJwtVcPresentationBuilder)]
impl WasmSdJwtVcPresentationBuilder {
  /// Prepares a new presentation from a given {@link SdJwtVc}.
  #[wasm_bindgen(constructor)]
  pub fn new(token: WasmSdJwtVc, hasher: &WasmHasher) -> Result<Self> {
    SdJwtVcPresentationBuilder::new(token.0, hasher).map(Self).wasm_result()
  }

  #[wasm_bindgen]
  pub fn conceal(self, path: &str) -> Result<Self> {
    self.0.conceal(path).map(Self).wasm_result()
  }

  #[wasm_bindgen(js_name = attachKeyBindingJwt)]
  pub fn attach_key_binding_jwt(self, kb_jwt: WasmKeyBindingJwt) -> Self {
    Self(self.0.attach_key_binding_jwt(kb_jwt.0))
  }

  #[wasm_bindgen]
  pub fn finish(self) -> Result<PresentationResult> {
    self
      .0
      .finish()
      .map(|(token, disclosures)| PresentationResult {
        sd_jwt_vc: WasmSdJwtVc(token),
        disclosures: disclosures.into_iter().map(WasmDisclosure::from).collect(),
      })
      .wasm_result()
  }
}

#[wasm_bindgen(js_name = SdJwtVcPresentationResult, getter_with_clone)]
pub struct PresentationResult {
  #[wasm_bindgen(js_name = sdJwtVc)]
  pub sd_jwt_vc: WasmSdJwtVc,
  pub disclosures: Vec<WasmDisclosure>,
}
