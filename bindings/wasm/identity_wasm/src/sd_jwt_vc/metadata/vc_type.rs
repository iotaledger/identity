// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::sd_jwt_vc::metadata::TypeMetadata;
use serde::Serialize;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::impl_wasm_json;
use crate::sd_jwt_vc::resolver::ResolverUrlToValue;

#[wasm_bindgen(typescript_custom_section)]
const I_TYPE_METADATA: &str = r#"
type SchemaByUri = { schema_uri: string, "schema_uri#integrity"?: string };
type SchemaByObject = { schema: unknown, "schema#integrity"?: string };
type NoSchema = {};
type TypeSchema = SchemaByUri | SchemaByObject | NoSchema;

type TypeMetadataHelper = {
  name?: string;
  description?: string;
  extends?: string;
  "extends#integrity"?: string;
  display?: unknown[];
  claims?: ClaimMetadata[];
} & TypeSchema;
"#;

#[wasm_bindgen]
extern "C" {
  pub type TypeMetadataHelper;
}

#[derive(Serialize, Clone)]
#[serde(transparent)]
#[wasm_bindgen(js_name = TypeMetadata)]
pub struct WasmTypeMetadata(pub(crate) TypeMetadata);

impl_wasm_json!(WasmTypeMetadata, TypeMetadata);

#[wasm_bindgen(js_class = TypeMetadata)]
impl WasmTypeMetadata {
  #[wasm_bindgen(constructor)]
  pub fn new(helper: TypeMetadataHelper) -> Result<Self> {
    serde_wasm_bindgen::from_value(helper.into()).map(Self).wasm_result()
  }

  #[wasm_bindgen(js_name = intoInner)]
  pub fn into_inner(&self) -> Result<TypeMetadataHelper> {
    serde_wasm_bindgen::to_value(&self.0)
      .wasm_result()
      .and_then(JsCast::dyn_into)
  }

  /// Uses this {@link TypeMetadata} to validate JSON object `credential`. This method fails
  /// if the schema is referenced instead of embedded.
  /// Use {@link TypeMetadata.validate_credential_with_resolver} for such cases.
  /// ## Notes
  /// This method ignores type extensions.
  #[wasm_bindgen(js_name = validateCredential)]
  pub fn validate_credential(&self, credential: JsValue) -> Result<()> {
    let credential = serde_wasm_bindgen::from_value(credential).wasm_result()?;
    self.0.validate_credential(&credential).wasm_result()
  }

  /// Similar to {@link TypeMetadata.validate_credential}, but accepts a {@link Resolver}
  /// {@link Url} -> {@link any} that is used to resolve any reference to either
  /// another type or JSON schema.
  #[wasm_bindgen(js_name = validateCredentialWithResolver)]
  pub async fn validate_credential_with_resolver(
    &self,
    credential: JsValue,
    resolver: &ResolverUrlToValue,
  ) -> Result<()> {
    let credential = serde_wasm_bindgen::from_value(credential).wasm_result()?;
    self
      .0
      .validate_credential_with_resolver(&credential, resolver)
      .await
      .wasm_result()
  }
}
