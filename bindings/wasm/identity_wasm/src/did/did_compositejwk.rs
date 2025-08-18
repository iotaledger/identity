// Copyright 2020-2025 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_iota::did::DIDCompositeJwk;
use identity_iota::did::DID as _;
use wasm_bindgen::prelude::*;

use super::wasm_core_did::get_core_did_clone;
use super::IToCoreDID;
use super::WasmCoreDID;
use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmCompositeJwk;

/// `did:compositejwk` DID.
#[wasm_bindgen(js_name = DIDCompositeJwk)]
pub struct WasmDIDCompositeJwk(pub(crate) DIDCompositeJwk);

#[wasm_bindgen(js_class = DIDCompositeJwk)]
impl WasmDIDCompositeJwk {
  #[wasm_bindgen(constructor)]
  /// Creates a new {@link DIDCompositeJwk} from a {@link CoreDID}.
  ///
  /// ### Errors
  /// Throws an error if the given did is not a valid `did:compositejwk` DID.
  pub fn new(did: IToCoreDID) -> Result<WasmDIDCompositeJwk> {
    let did = get_core_did_clone(&did).0;
    DIDCompositeJwk::try_from(did).wasm_result().map(Self)
  }
  /// Parses a {@link DIDCompositeJwk} from the given `input`.
  ///
  /// ### Errors
  ///
  /// Throws an error if the input is not a valid {@link DIDCompositeJwk}.
  #[wasm_bindgen]
  pub fn parse(input: &str) -> Result<WasmDIDCompositeJwk> {
    DIDCompositeJwk::parse(input).wasm_result().map(Self)
  }

  /// Returns the JSON WEB KEY (JWK) encoded inside this `did:jwk`.
  #[wasm_bindgen(js_name = compositeJwk)]
  pub fn composite_jwk(&self) -> WasmCompositeJwk {
    self.0.composite_jwk().into()
  }

  // ===========================================================================
  // DID trait
  // ===========================================================================

  /// Returns the {@link CoreDID} scheme.
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "did"`
  /// - `"did:iota:smr:12345678" -> "did"`
  #[wasm_bindgen]
  pub fn scheme(&self) -> String {
    self.0.scheme().to_owned()
  }

  /// Returns the {@link CoreDID} authority: the method name and method-id.
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "example:12345678"`
  /// - `"did:iota:smr:12345678" -> "iota:smr:12345678"`
  #[wasm_bindgen]
  pub fn authority(&self) -> String {
    self.0.authority().to_owned()
  }

  /// Returns the {@link CoreDID} method name.
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "example"`
  /// - `"did:iota:smr:12345678" -> "iota"`
  #[wasm_bindgen]
  pub fn method(&self) -> String {
    self.0.method().to_owned()
  }

  /// Returns the {@link CoreDID} method-specific ID.
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "12345678"`
  /// - `"did:iota:smr:12345678" -> "smr:12345678"`
  #[wasm_bindgen(js_name = methodId)]
  pub fn method_id(&self) -> String {
    self.0.method_id().to_owned()
  }

  /// Returns the {@link CoreDID} as a string.
  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> String {
    self.0.to_string()
  }

  // Only intended to be called internally.
  #[wasm_bindgen(js_name = toCoreDid, skip_typescript)]
  pub fn to_core_did(&self) -> WasmCoreDID {
    WasmCoreDID(self.0.clone().into())
  }
}

impl_wasm_json!(WasmDIDCompositeJwk, DIDCompositeJwk);
impl_wasm_clone!(WasmDIDCompositeJwk, DIDCompositeJwk);
