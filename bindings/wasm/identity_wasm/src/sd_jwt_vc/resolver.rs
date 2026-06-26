// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use async_trait::async_trait;
use identity_iota::core::Url;
use identity_iota::credential::sd_jwt_vc::resolver::Error as ErrorR;
use identity_iota::credential::sd_jwt_vc::Resolver;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const I_RESOLVER: &str = r#"
interface IResolver<I, T> {
  resolve: (input: I) => Promise<T>;
}
"#;

#[wasm_bindgen]
extern "C" {
  // Resolver<Url, Vec<u8>>
  #[wasm_bindgen(typescript_type = "IResolver<string, Uint8Array>")]
  pub type ResolverStringToUint8Array;

  #[wasm_bindgen(structural, method, catch)]
  pub async fn resolve(this: &ResolverStringToUint8Array, input: &str) -> Result<Uint8Array, js_sys::Error>;

  // Resolver<Url, serde_json::Value>
  #[wasm_bindgen(typescript_type = "IResolver<string, any>")]
  pub type ResolverUrlToValue;

  #[wasm_bindgen(structural, method, catch)]
  pub async fn resolve(this: &ResolverUrlToValue, input: &str) -> Result<JsValue, js_sys::Error>;
}

#[async_trait(?Send)]
impl<I> Resolver<I, Vec<u8>> for ResolverStringToUint8Array
where
  I: AsRef<str> + Sync,
{
  async fn resolve(&self, input: &I) -> Result<Vec<u8>, ErrorR> {
    self
      .resolve(input.as_ref())
      .await
      .map(|arr| arr.to_vec())
      .map_err(|e| ErrorR::Generic(anyhow::anyhow!("{}", e.to_string())))
  }
}

#[async_trait(?Send)]
impl<I> Resolver<I, serde_json::Value> for ResolverStringToUint8Array
where
  I: AsRef<str> + Sync,
{
  async fn resolve(&self, input: &I) -> Result<serde_json::Value, ErrorR> {
    self
      .resolve(input.as_ref())
      .await
      .map(|arr| arr.to_vec())
      .map_err(|e| ErrorR::Generic(anyhow::anyhow!("{}", e.to_string())))
      .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| ErrorR::ParsingFailure(e.into())))
  }
}

#[async_trait(?Send)]
impl Resolver<Url, serde_json::Value> for ResolverUrlToValue {
  async fn resolve(&self, input: &Url) -> Result<serde_json::Value, ErrorR> {
    self
      .resolve(input.as_str())
      .await
      .map(|js_value| serde_wasm_bindgen::from_value(js_value).expect("JS value is a JSON value"))
      .map_err(|e| ErrorR::Generic(anyhow!("{}", e.to_string())))
  }
}
