// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::sd_jwt_vc::SdJwtVcPresentationBuilder;
use wasm_bindgen::prelude::wasm_bindgen;

use super::WasmSdJwtVc;
use crate::error::Result;
use crate::error::WasmResult;
use crate::sd_jwt::WasmDisclosure;
use crate::sd_jwt::WasmHasher;

#[wasm_bindgen(js_name = SdJwtVcPresentationBuilder)]
pub struct WasmSdJwtVcPresentationBuilder(pub(crate) SdJwtVcPresentationBuilder);

#[wasm_bindgen(js_class = SdJwtVcPresentationBuilder)]
impl WasmSdJwtVcPresentationBuilder {
  /// Prepares a new presentation from a given {@link SdJwtVc}.
  #[wasm_bindgen(constructor)]
  pub fn new(token: WasmSdJwtVc, hasher: &WasmHasher) -> Result<Self> {
    SdJwtVcPresentationBuilder::new(token.0, hasher).map(Self).wasm_result()
  }

  pub fn conceal(self, path: &str) -> Result<Self> {
    self.0.conceal(path).map(Self).wasm_result()
  }

  pub fn conceal_all(self) -> Self {
    Self(self.0.conceal_all())
  }

  pub fn disclose(self, path: &str) -> Result<Self> {
    self.0.disclose(path).map(Self).wasm_result()
  }

  pub fn finish(self) -> PresentationResult {
    let (token, disclosures) = self.0.finish();

    PresentationResult {
      sd_jwt_vc: WasmSdJwtVc(token),
      disclosures: disclosures.into_iter().map(WasmDisclosure::from).collect(),
    }
  }
}

#[wasm_bindgen(js_name = SdJwtVcPresentationResult, getter_with_clone)]
pub struct PresentationResult {
  #[wasm_bindgen(js_name = sdJwtVc)]
  pub sd_jwt_vc: WasmSdJwtVc,
  pub disclosures: Vec<WasmDisclosure>,
}
