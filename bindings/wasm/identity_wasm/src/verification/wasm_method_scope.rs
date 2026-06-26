// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::MethodScope;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
  // Workaround for lack of Option<&Type>/&Option<Type> support.
  #[wasm_bindgen(typescript_type = "MethodScope")]
  pub type RefMethodScope;

  #[wasm_bindgen(typescript_type = "MethodScope | undefined")]
  pub type OptionMethodScope;
}

/// Supported verification method types.
#[wasm_bindgen(js_name = MethodScope, inspectable)]
pub struct WasmMethodScope(pub(crate) MethodScope);

#[wasm_bindgen(js_class = MethodScope)]
impl WasmMethodScope {
  #[wasm_bindgen(js_name = VerificationMethod)]
  pub fn verification_method() -> WasmMethodScope {
    Self(MethodScope::VerificationMethod)
  }

  #[wasm_bindgen(js_name = Authentication)]
  pub fn authentication() -> WasmMethodScope {
    Self(MethodScope::authentication())
  }

  #[wasm_bindgen(js_name = AssertionMethod)]
  pub fn assertion_method() -> WasmMethodScope {
    Self(MethodScope::assertion_method())
  }

  #[wasm_bindgen(js_name = KeyAgreement)]
  pub fn key_agreement() -> WasmMethodScope {
    Self(MethodScope::key_agreement())
  }

  #[wasm_bindgen(js_name = CapabilityDelegation)]
  pub fn capability_delegation() -> WasmMethodScope {
    Self(MethodScope::capability_delegation())
  }

  #[wasm_bindgen(js_name = CapabilityInvocation)]
  pub fn capability_invocation() -> WasmMethodScope {
    Self(MethodScope::capability_invocation())
  }

  /// Returns the {@link MethodScope} as a string.
  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> String {
    self.0.to_string()
  }
}

impl_wasm_json!(WasmMethodScope, MethodScope);
impl_wasm_clone!(WasmMethodScope, MethodScope);
