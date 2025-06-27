// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::RecordStringAny;
use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::impl_wasm_clone;
use product_common::impl_wasm_json;

use identity_iota::core::Url;
use identity_iota::storage::JwsSignatureOptions;
use wasm_bindgen::prelude::*;

/// Options for creating a JSON Web Signature.
#[wasm_bindgen(js_name = JwsSignatureOptions, inspectable)]
pub struct WasmJwsSignatureOptions(pub(crate) JwsSignatureOptions);

#[wasm_bindgen(js_class = JwsSignatureOptions)]
impl WasmJwsSignatureOptions {
  #[wasm_bindgen(constructor)]
  pub fn new(options: Option<IJwsSignatureOptions>) -> Result<WasmJwsSignatureOptions> {
    if let Some(options) = options {
      let options: JwsSignatureOptions = options.into_serde().wasm_result()?;
      Ok(WasmJwsSignatureOptions(options))
    } else {
      Ok(WasmJwsSignatureOptions(Default::default()))
    }
  }

  /// Replace the value of the `attachJwk` field.
  #[wasm_bindgen(js_name = setAttachJwk)]
  pub fn set_attach_jwk(&mut self, value: bool) {
    self.0.attach_jwk = value;
  }

  /// Replace the value of the `b64` field.
  #[wasm_bindgen(js_name = setB64)]
  pub fn set_b64(&mut self, value: bool) {
    self.0.b64 = Some(value);
  }

  /// Replace the value of the `typ` field.
  #[wasm_bindgen(js_name = setTyp)]
  pub fn set_typ(&mut self, value: String) {
    self.0.typ = Some(value);
  }

  /// Replace the value of the `cty` field.
  #[wasm_bindgen(js_name = setCty)]
  pub fn set_cty(&mut self, value: String) {
    self.0.cty = Some(value);
  }

  /// Replace the value of the `url` field.
  #[wasm_bindgen(js_name = serUrl)]
  pub fn set_url(&mut self, value: String) -> Result<()> {
    self.0.url = Some(Url::parse(value).wasm_result()?);
    Ok(())
  }

  /// Replace the value of the `nonce` field.
  #[wasm_bindgen(js_name = setNonce)]
  pub fn set_nonce(&mut self, value: String) {
    self.0.nonce = Some(value);
  }

  /// Replace the value of the `kid` field.
  #[wasm_bindgen(js_name = setKid)]
  pub fn set_kid(&mut self, value: String) {
    self.0.kid = Some(value);
  }

  /// Replace the value of the `detached_payload` field.
  #[wasm_bindgen(js_name = setDetachedPayload)]
  pub fn set_detached_payload(&mut self, value: bool) {
    self.0.detached_payload = value;
  }

  /// Add additional header parameters.
  #[wasm_bindgen(js_name = setCustomHeaderParameters)]
  pub fn set_custom_header_parameters(&mut self, value: RecordStringAny) -> Result<()> {
    self.0.custom_header_parameters = Some(value.into_serde().wasm_result()?);
    Ok(())
  }
}

impl_wasm_json!(WasmJwsSignatureOptions, JwsSignatureOptions);
impl_wasm_clone!(WasmJwsSignatureOptions, JwsSignatureOptions);

/// Duck-typed interface to allow creating {@link JwsSignatureOptions} easily.
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJwsSignatureOptions")]
  pub type IJwsSignatureOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JWS_SIGNATURE_OPTIONS: &'static str = r#"
/** Holds options to create {@link JwsSignatureOptions}. */
interface IJwsSignatureOptions {
    /** Whether to attach the public key in the corresponding method
     * to the JWS header.
     * 
     * Default: false
     */
    readonly attachJwk?: boolean;

    /** Whether to Base64url encode the payload or not.
     *
     * [More Info](https://tools.ietf.org/html/rfc7797#section-3)
     */
    readonly b64?: boolean;

    /** The Type value to be placed in the protected header.
     * 
     * [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.9)
     */
    readonly typ?: string;

    /** Content Type to be placed in the protected header.
     * 
     * [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.10)
     */
    readonly cty?: string;

    /** The URL to be placed in the protected header.
     * 
     * [More Info](https://tools.ietf.org/html/rfc8555#section-6.4.1)
     */
    readonly url?: string;

    /** The nonce to be placed in the protected header.
     * 
     * [More Info](https://tools.ietf.org/html/rfc8555#section-6.5.2)
     */
    readonly nonce?: string;

    /** The kid to set in the protected header.
     * If unset, the kid of the JWK with which the JWS is produced is used.
     * 
     * [More Info](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4)
     */
    readonly kid?: string;

    /**   /// Whether the payload should be detached from the JWS.
     * 
     * [More Info](https://www.rfc-editor.org/rfc/rfc7515#appendix-F).
     */
    readonly detachedPayload?: boolean

    /**
     * Additional header parameters.
     */
    readonly customHeaderParameters?: Record<string, any>;
}"#;
