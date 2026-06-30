// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::did::WasmDIDUrl;
use crate::error::Result;
use crate::error::WasmResult;
use crate::verification::WasmVerificationMethod;
use identity_iota::verification::MethodRef;
use wasm_bindgen::prelude::*;

/// A reference held inside a verification relationship: either an embedded
/// {@link VerificationMethod}, an absolute DID URL (`"refer"`), or a relative
/// DID URL resolved against the document DID (`"relativeRefer"`).
#[wasm_bindgen(js_name = MethodRef, inspectable)]
pub struct WasmMethodRef(pub(crate) MethodRef);

#[wasm_bindgen(js_class = MethodRef)]
impl WasmMethodRef {
  /// Returns the variant: `"embedded"`, `"refer"`, or `"relativeRefer"`.
  #[wasm_bindgen(getter, js_name = type)]
  pub fn kind(&self) -> String {
    match &self.0 {
      MethodRef::Embed(_) => "embedded",
      MethodRef::Refer(_) => "refer",
      MethodRef::RelativeRefer(_) => "relativeRefer",
    }
    .to_owned()
  }

  /// Returns the embedded {@link VerificationMethod}, or `undefined` for references.
  #[wasm_bindgen(js_name = asVerificationMethod)]
  pub fn as_verification_method(&self) -> Option<WasmVerificationMethod> {
    if let MethodRef::Embed(method) = &self.0 {
      Some(WasmVerificationMethod(method.clone()))
    } else {
      None
    }
  }

  /// Returns the resolved absolute {@link DIDUrl} for `"refer"` and `"relativeRefer"`,
  /// or `undefined` for embedded methods.
  ///
  /// Note: for `"relativeRefer"` this is the *resolved* URL (e.g. `did:example:123#key-1`).
  /// Use {@link MethodRef#toString} to obtain the original relative string (e.g. `"#key-1"`).
  #[wasm_bindgen(js_name = asDIDUrl)]
  pub fn as_did_url(&self) -> Option<WasmDIDUrl> {
    match &self.0 {
      MethodRef::Refer(did_url) | MethodRef::RelativeRefer(did_url) => Some(WasmDIDUrl(did_url.clone())),
      MethodRef::Embed(_) => None,
    }
  }

  /// Serializes as the document JSON representation:
  /// - `"embedded"` → the full verification method object
  /// - `"refer"` → the absolute DID URL string
  /// - `"relativeRefer"` → the relative reference string (e.g. `"#key-1"`)
  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<JsValue> {
    JsValue::from_serde(&self.0).wasm_result()
  }

  /// Returns the string form consistent with the document JSON:
  /// the relative string for `"relativeRefer"`, the full DID URL string for all others.
  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> String {
    match &self.0 {
      MethodRef::Embed(method) => method.id().to_string(),
      MethodRef::Refer(did_url) => did_url.to_string(),
      MethodRef::RelativeRefer(did_url) => did_url.url().to_string(),
    }
  }
}

impl_wasm_clone!(WasmMethodRef, MethodRef);
