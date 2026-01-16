// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::sd_jwt_vc::Error;
use identity_iota::sd_jwt_payload::SdJwt;
use identity_iota::sd_jwt_payload::SdJwtPresentationBuilder;
use identity_iota::sd_jwt_payload::Sha256Hasher;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::error::WasmResult;

use super::WasmDisclosure;
use super::WasmHasher;
use super::WasmKeyBindingJwt;
use super::WasmRequiredKeyBinding;

#[wasm_bindgen(typescript_custom_section)]
const I_SD_JWT_CLAIMS: &str = r#"
interface SdJwtClaims {
  _sd: string[];
  _sd_alg?: string;
  cnf?: RequiredKeyBinding;
  [properties: string]: unknown;
}
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "SdJwtClaims")]
  pub type WasmSdJwtClaims;
}

/// Representation of an [SD-JWT](https://www.rfc-editor.org/rfc/rfc9901.html#name-sd-jwt-and-sd-jwtkb-data-fo)
/// of the format `<Issuer-signed JWT>~<D.1>~<D.2>~...~<D.N>~<optional KB-JWT>`.
#[derive(Clone)]
#[wasm_bindgen(js_name = SdJwt)]
pub struct WasmSdJwt(pub(crate) SdJwt);

#[wasm_bindgen(js_class = SdJwt)]
impl WasmSdJwt {
  /// Attempts to parse a semantically valid {@link SdJwt} from the given string.
  pub fn parse(s: &str) -> Result<WasmSdJwt> {
    SdJwt::parse(s).map(Self).map_err(Error::from).wasm_result()
  }

  /// Returns the JWT headers of this SD-JWT token.
  #[wasm_bindgen(unchecked_return_type = "object")]
  pub fn headers(&self) -> JsValue {
    serde_wasm_bindgen::to_value(self.0.headers()).unwrap()
  }

  /// Returns the raw SD-JWT claims object.
  pub fn claims(&self) -> Result<WasmSdJwtClaims> {
    serde_wasm_bindgen::to_value(self.0.claims())
      .wasm_result()
      .map(JsCast::unchecked_into)
  }

  /// Returns a list of disclosure strings.
  pub fn disclosures(&self) -> Vec<String> {
    self.0.disclosures().iter().map(ToString::to_string).collect()
  }

  /// Returns the issuer's key binding requirements for this token, if any.
  #[wasm_bindgen(js_name = "requiredKeyBind")]
  pub fn required_key_bind(&self) -> Option<WasmRequiredKeyBinding> {
    self.0.required_key_bind().map(|required_kb| {
      serde_wasm_bindgen::to_value(required_kb)
        .expect("RequiredKeyBinding can be turned into a JS value")
        .unchecked_into()
    })
  }

  /// Returns the JSON object obtained by replacing all disclosures into their
  /// corresponding JWT concealable claims.
  #[wasm_bindgen(js_name = "intoDisclosedObject")]
  pub fn into_disclosed_object(self) -> Result<JsValue> {
    self
      .0
      .into_disclosed_object(&Sha256Hasher)
      .map_err(Error::from)
      .map(|obj| serde_wasm_bindgen::to_value(&obj).expect("obj can be turned into a JS value"))
      .wasm_result()
  }

  /// Attaches a {@link KeyBindingJwt} to this {@link SdJwt} token.
  /// ## Notes
  /// This method does *not* validate the given {@link KeyBindingJwt} in any way.
  #[wasm_bindgen(js_name = attachKeyBindingJwt)]
  pub fn attach_key_binding_jwt(&mut self, kb_jwt: WasmKeyBindingJwt) {
    self.0.attach_key_binding_jwt(kb_jwt.0);
  }

  /// Returns the string representation for this SD-JWT token.
  pub fn presentation(&self) -> String {
    self.0.presentation()
  }

  #[wasm_bindgen(js_name = "toJSON")]
  pub fn to_json(&self) -> JsValue {
    JsValue::from_str(&self.presentation())
  }

  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = "toString")]
  pub fn to_string(&self) -> JsValue {
    JsValue::from_str(&self.presentation())
  }
}

/// A class that enables users to conceal or disclose disclosable claims
/// within an {@link SdJwt}.
#[wasm_bindgen(js_name = SdJwtPresentationBuilder)]
pub struct WasmSdJwtPresentationBuilder(pub(crate) SdJwtPresentationBuilder);

#[wasm_bindgen(js_class = SdJwtPresentationBuilder)]
impl WasmSdJwtPresentationBuilder {
  #[wasm_bindgen(constructor)]
  pub fn new(sd_jwt: WasmSdJwt, hasher: &WasmHasher) -> Result<Self> {
    SdJwtPresentationBuilder::new(sd_jwt.0, hasher).map(Self).wasm_result()
  }

  /// Removes the disclosure for the property at `path`, concealing it.
  ///
  /// ## Notes
  /// - When concealing a claim more than one disclosure may be removed: the disclosure for the claim itself and the
  ///   disclosures for any concealable sub-claim.
  pub fn conceal(self, path: &str) -> Result<Self> {
    self.0.conceal(path).map(Self).wasm_result()
  }

  /// Removes all disclosures from this SD-JWT, resulting in a token that,
  /// when presented, will have *all* selectively-disclosable properties
  /// omitted.
  pub fn conceal_all(self) -> Self {
    Self(self.0.conceal_all())
  }

  /// Discloses a value that was previously concealed.
  /// # Notes
  /// - This method may disclose multiple values, if the given path references a disclosable value stored within another
  ///   disclosable value. That is, {@link SdJwtPresentationBuilder.disclose} will unconceal the selectively disclosable
  ///   value at `path` together with *all* its parents that are disclosable values themselves.
  /// - By default *all* disclosable claims are disclosed, therefore this method can only be used to *undo* any
  ///   concealment operations previously performed by either {@link SdJwtPresentationBuilder.conceal} or {@link
  ///   SdJwtPresentationBuilder.conceal_all}.
  pub fn disclose(self, path: &str) -> Result<Self> {
    self.0.disclose(path).map(Self).wasm_result()
  }

  /// Returns the resulting {@link SdJwt} together with all omitted disclosures.
  #[wasm_bindgen]
  pub fn finish(self) -> SdJwtPresentationResult {
    let (sd_jwt, disclosures) = self.0.finish();
    SdJwtPresentationResult {
      sd_jwt: WasmSdJwt(sd_jwt),
      disclosures: disclosures.into_iter().map(WasmDisclosure::from).collect(),
    }
  }
}

#[wasm_bindgen(inspectable, getter_with_clone)]
pub struct SdJwtPresentationResult {
  #[wasm_bindgen(js_name = sdJwt)]
  pub sd_jwt: WasmSdJwt,
  pub disclosures: Vec<WasmDisclosure>,
}
