// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::did::WasmCoreDID;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::did::DIDUrl;
use wasm_bindgen::prelude::*;

/// A method agnostic DID Url.
#[wasm_bindgen(js_name = DIDUrl, inspectable)]
pub struct WasmDIDUrl(pub(crate) DIDUrl);

#[wasm_bindgen(js_class = DIDUrl)]
impl WasmDIDUrl {
  /// Parses a {@link DIDUrl} from the input string.
  #[wasm_bindgen]
  pub fn parse(input: &str) -> Result<WasmDIDUrl> {
    DIDUrl::parse(input).map(WasmDIDUrl).wasm_result()
  }

  /// Return a copy of the {@link CoreDID} section of the {@link DIDUrl}.
  #[wasm_bindgen]
  pub fn did(&self) -> WasmCoreDID {
    WasmCoreDID::from(self.0.did().clone())
  }

  /// Return a copy of the relative DID Url as a string, including only the path, query, and fragment.
  #[wasm_bindgen(js_name = urlStr)]
  pub fn url_str(&self) -> String {
    self.0.url().to_string()
  }

  /// Returns a copy of the {@link DIDUrl} method fragment, if any. Excludes the leading '#'.
  #[wasm_bindgen]
  pub fn fragment(&self) -> Option<String> {
    self.0.fragment().map(str::to_owned)
  }

  /// Sets the `fragment` component of the {@link DIDUrl}.
  #[wasm_bindgen(js_name = setFragment)]
  pub fn set_fragment(&mut self, value: Option<String>) -> Result<()> {
    self.0.set_fragment(value.as_deref()).wasm_result()
  }

  /// Returns a copy of the {@link DIDUrl} path.
  #[wasm_bindgen]
  pub fn path(&self) -> Option<String> {
    self.0.path().map(str::to_owned)
  }

  /// Sets the `path` component of the {@link DIDUrl}.
  #[wasm_bindgen(js_name = setPath)]
  pub fn set_path(&mut self, value: Option<String>) -> Result<()> {
    self.0.set_path(value.as_deref()).wasm_result()
  }

  /// Returns a copy of the {@link DIDUrl} method query, if any. Excludes the leading '?'.
  #[wasm_bindgen]
  pub fn query(&self) -> Option<String> {
    self.0.query().map(str::to_owned)
  }

  /// Sets the `query` component of the {@link DIDUrl}.
  #[wasm_bindgen(js_name = setQuery)]
  pub fn set_query(&mut self, value: Option<String>) -> Result<()> {
    self.0.set_query(value.as_deref()).wasm_result()
  }

  /// Append a string representing a path, query, and/or fragment, returning a new {@link DIDUrl}.
  ///
  /// Must begin with a valid delimiter character: '/', '?', '#'. Overwrites the existing URL
  /// segment and any following segments in order of path, query, then fragment.
  ///
  /// I.e.
  /// - joining a path will clear the query and fragment.
  /// - joining a query will clear the fragment.
  /// - joining a fragment will only overwrite the fragment.
  #[wasm_bindgen]
  pub fn join(&self, segment: &str) -> Result<WasmDIDUrl> {
    self.0.join(segment).map(WasmDIDUrl::from).wasm_result()
  }

  /// Returns the {@link DIDUrl} as a string.
  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> String {
    self.0.to_string()
  }
}

impl_wasm_json!(WasmDIDUrl, DIDUrl);
impl_wasm_clone!(WasmDIDUrl, DIDUrl);

impl From<DIDUrl> for WasmDIDUrl {
  fn from(did_url: DIDUrl) -> Self {
    Self(did_url)
  }
}

impl From<WasmDIDUrl> for DIDUrl {
  fn from(wasm_did_url: WasmDIDUrl) -> Self {
    wasm_did_url.0
  }
}
