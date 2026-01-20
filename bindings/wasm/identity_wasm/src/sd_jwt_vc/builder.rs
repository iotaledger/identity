// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::StringOrUrl;
use identity_iota::core::Url;
use identity_iota::credential::sd_jwt_vc::SdJwtVcBuilder;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::common::WasmTimestamp;
use crate::credential::WasmCredential;
use crate::error::Result;
use crate::error::WasmResult;
use crate::sd_jwt_vc::WasmSdJwtVc;

use super::WasmStatus;
use crate::sd_jwt::WasmHasher;
use crate::sd_jwt::WasmJwsSigner;
use crate::sd_jwt::WasmRequiredKeyBinding;

#[wasm_bindgen(js_name = SdJwtVcBuilder)]
pub struct WasmSdJwtVcBuilder(pub(crate) SdJwtVcBuilder<WasmHasher>);

#[wasm_bindgen(js_class = SdJwtVcBuilder)]
impl WasmSdJwtVcBuilder {
  /// Creates a new {@link SdJwtVcBuilder} using `object` JSON representation and a given
  /// hasher `hasher`.
  #[wasm_bindgen(constructor)]
  pub fn new(object: js_sys::Object, hasher: WasmHasher) -> Result<Self> {
    let object = serde_wasm_bindgen::from_value::<serde_json::Value>(object.into()).wasm_result()?;
    SdJwtVcBuilder::new_with_hasher(object, hasher).map(Self).wasm_result()
  }

  /// Creates a new [`SdJwtVcBuilder`] starting from a {@link Credential} that is converted to a JWT claim set.
  #[wasm_bindgen(js_name = fromCredential)]
  pub fn new_from_credential(credential: WasmCredential, hasher: WasmHasher) -> Result<Self> {
    SdJwtVcBuilder::new_from_credential(credential.0, hasher)
      .map(Self)
      .wasm_result()
  }

  /// Substitutes a value with the digest of its disclosure.
  ///
  /// ## Notes
  /// - `path` indicates the pointer to the value that will be concealed using the syntax of [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
  #[wasm_bindgen(js_name = makeConcealable)]
  pub fn make_concealable(self, path: &str) -> Result<Self> {
    self.0.make_concealable(path).map(Self).wasm_result()
  }

  /// Sets a single JWT header by its key and value.
  pub fn header(self, key: String, value: JsValue) -> Result<Self> {
    let json_value: serde_json::Value = serde_wasm_bindgen::from_value(value).wasm_result()?;
    Ok(Self(self.0.header(key, json_value)))
  }

  /// Sets the JWT header.
  /// ## Notes
  /// - if {@link SdJwtVcBuilder.header} is not called, the default header is used: ```json { "typ": "sd-jwt", "alg":
  ///   "<algorithm used in SdJwtBuilder.finish>" } ```
  /// - `alg` is always replaced with the value passed to {@link SdJwtVcBuilder.finish}.
  pub fn headers(self, headers: js_sys::Object) -> Self {
    let header = serde_wasm_bindgen::from_value(headers.into()).expect("JS object is a valid JSON object");
    Self(self.0.headers(header))
  }

  /// Adds a decoy digest to the specified path.
  ///
  /// `path` indicates the pointer to the value that will be concealed using the syntax of
  /// [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
  ///
  /// Use `path` = "" to add decoys to the top level.
  #[wasm_bindgen(js_name = addDecoys)]
  pub fn add_decoys(self, path: &str, number_of_decoys: usize) -> Result<Self> {
    self.0.add_decoys(path, number_of_decoys).map(Self).wasm_result()
  }

  /// Require a proof of possession of a given key from the holder.
  ///
  /// This operation adds a JWT confirmation (`cnf`) claim as specified in
  /// [RFC8300](https://www.rfc-editor.org/rfc/rfc7800.html#section-3).
  #[wasm_bindgen(js_name = requireKeyBinding)]
  pub fn require_key_binding(self, key_bind: WasmRequiredKeyBinding) -> Result<Self> {
    let key_bind = serde_wasm_bindgen::from_value(key_bind.into()).wasm_result()?;
    Ok(Self(self.0.require_key_binding(key_bind)))
  }

  /// Inserts an `iss` claim. See {@link SdJwtVcClaim.iss}.
  #[wasm_bindgen]
  pub fn iss(self, issuer: &str) -> Result<Self> {
    let url = Url::parse(issuer).wasm_result()?;
    Ok(Self(self.0.iss(url)))
  }

  /// Inserts a `nbf` claim. See {@link SdJwtVcClaims.nbf}.
  #[wasm_bindgen]
  pub fn nbf(self, nbf: WasmTimestamp) -> Self {
    Self(self.0.nbf(nbf.0))
  }

  /// Inserts a `exp` claim. See {@link SdJwtVcClaims.exp}.
  #[wasm_bindgen]
  pub fn exp(self, exp: WasmTimestamp) -> Self {
    Self(self.0.exp(exp.0))
  }

  /// Inserts a `iat` claim. See {@link SdJwtVcClaims.iat}.
  #[wasm_bindgen]
  pub fn iat(self, iat: WasmTimestamp) -> Self {
    Self(self.0.iat(iat.0))
  }

  /// Inserts a `vct` claim. See {@link SdJwtVcClaims.vct}.
  #[wasm_bindgen]
  pub fn vct(self, vct: &str) -> Self {
    let vct = StringOrUrl::parse(vct).unwrap();
    Self(self.0.vct(vct))
  }

  /// Inserts a `sub` claim. See {@link SdJwtVcClaims.sub}.
  #[allow(clippy::should_implement_trait)]
  #[wasm_bindgen]
  pub fn sub(self, sub: &str) -> Self {
    let sub = StringOrUrl::parse(sub).unwrap();
    Self(self.0.sub(sub))
  }

  /// Inserts a `status` claim. See {@link SdJwtVcClaims.status}.
  #[wasm_bindgen]
  pub fn status(self, status: WasmStatus) -> Result<Self> {
    let status = serde_wasm_bindgen::from_value(status.into()).wasm_result()?;
    Ok(Self(self.0.status(status)))
  }

  /// Creates an {@link SdJwtVc} with the provided data.
  #[wasm_bindgen]
  pub async fn finish(self, signer: &WasmJwsSigner, alg: &str) -> Result<WasmSdJwtVc> {
    self.0.finish(signer, alg).await.map(WasmSdJwtVc).wasm_result()
  }
}
