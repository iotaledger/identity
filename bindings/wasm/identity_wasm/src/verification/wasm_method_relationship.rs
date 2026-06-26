// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::MethodRelationship;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = MethodRelationship)]
#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum WasmMethodRelationship {
  Authentication = 0,
  AssertionMethod = 1,
  KeyAgreement = 2,
  CapabilityDelegation = 3,
  CapabilityInvocation = 4,
}

impl From<WasmMethodRelationship> for MethodRelationship {
  fn from(relationship: WasmMethodRelationship) -> Self {
    match relationship {
      WasmMethodRelationship::Authentication => MethodRelationship::Authentication,
      WasmMethodRelationship::AssertionMethod => MethodRelationship::AssertionMethod,
      WasmMethodRelationship::KeyAgreement => MethodRelationship::KeyAgreement,
      WasmMethodRelationship::CapabilityDelegation => MethodRelationship::CapabilityDelegation,
      WasmMethodRelationship::CapabilityInvocation => MethodRelationship::CapabilityInvocation,
    }
  }
}
