// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::jose::jwk::Jwk;
use identity_iota::verification::jose::jwk::JwkOperation;
use identity_iota::verification::jose::jwk::JwkParams;
use identity_iota::verification::jose::jwk::JwkUse;
use wasm_bindgen::prelude::*;

use crate::common::ArrayString;
use crate::error::WasmResult;
use crate::jose::ArrayJwkOperation;
use crate::jose::IJwkParams;
use crate::jose::WasmJwkParamsAkp;
use crate::jose::WasmJwkParamsEc;
use crate::jose::WasmJwkParamsOct;
use crate::jose::WasmJwkParamsOkp;
use crate::jose::WasmJwkParamsRsa;
use crate::jose::WasmJwkType;
use crate::jose::WasmJwkUse;
use crate::jose::WasmJwsAlgorithm;
use core::ops::Deref;

/// JSON Web Key.
///
/// [More Info](https://tools.ietf.org/html/rfc7517#section-4)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[wasm_bindgen(js_name = Jwk)]
pub struct WasmJwk(pub(crate) Jwk);

#[wasm_bindgen(js_class = Jwk)]
impl WasmJwk {
  #[wasm_bindgen(constructor)]
  pub fn new(jwk: IJwkParams) -> Self {
    let jwk: Jwk = jwk.into_serde().unwrap();
    Self(jwk)
  }

  /// Returns the value for the key type parameter (kty).
  #[wasm_bindgen]
  pub fn kty(&self) -> WasmJwkType {
    // WARNING: this does not validate the return type. Check carefully.
    JsValue::from(self.0.kty().name().to_owned()).unchecked_into()
  }

  /// Returns the value for the use property (use).
  #[wasm_bindgen(js_name = use)]
  pub fn use_(&self) -> Option<WasmJwkUse> {
    self
      .0
      .use_()
      .as_ref()
      .map(JwkUse::name)
      .map(JsValue::from)
      // WARNING: this does not validate the return type. Check carefully.
      .map(JsValue::unchecked_into)
  }

  // Returns the value for the key operations parameter (key_ops).
  #[wasm_bindgen(js_name = keyOps)]
  pub fn key_ops(&self) -> ArrayJwkOperation {
    self
      .0
      .key_ops()
      .unwrap_or_default()
      .iter()
      .map(JwkOperation::name)
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      // WARNING: this does not validate the return type. Check carefully.
      .unchecked_into::<ArrayJwkOperation>()
  }

  /// Returns the value for the algorithm property (alg).
  #[wasm_bindgen]
  pub fn alg(&self) -> Option<WasmJwsAlgorithm> {
    self
      .0
      .alg()
      .map(JsValue::from)
      // WARNING: this does not validate the return type. Check carefully.
      .map(JsValue::unchecked_into)
  }

  /// Returns the value of the key ID property (kid).
  #[wasm_bindgen]
  pub fn kid(&self) -> Option<String> {
    self.0.kid().map(ToOwned::to_owned)
  }

  /// Sets a value for the key ID property (kid).
  #[wasm_bindgen(js_name = setKid)]
  pub fn set_kid(&mut self, kid: String) {
    self.0.set_kid(kid);
  }

  /// Returns the value of the X.509 URL property (x5u).
  #[wasm_bindgen]
  pub fn x5u(&self) -> Option<String> {
    self
      .0
      .x5u()
      .map(Deref::deref)
      .map(AsRef::<str>::as_ref)
      .map(ToOwned::to_owned)
  }

  /// Returns the value of the X.509 certificate chain property (x5c).
  #[wasm_bindgen]
  pub fn x5c(&self) -> ArrayString {
    self
      .0
      .x5c()
      .unwrap_or_default()
      .iter()
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// Returns the value of the X.509 certificate SHA-1 thumbprint property (x5t).
  #[wasm_bindgen]
  pub fn x5t(&self) -> Option<String> {
    self.0.x5t().map(AsRef::<str>::as_ref).map(ToOwned::to_owned)
  }

  /// Returns the value of the X.509 certificate SHA-256 thumbprint property (x5t#S256).
  #[wasm_bindgen]
  pub fn x5t256(&self) -> Option<String> {
    self.0.x5t_s256().map(AsRef::<str>::as_ref).map(ToOwned::to_owned)
  }

  /// If this JWK is of kty EC, returns those parameters.
  #[wasm_bindgen(js_name = paramsEc)]
  pub fn params_ec(&self) -> crate::error::Result<Option<WasmJwkParamsEc>> {
    if let JwkParams::Ec(params_ec) = self.0.params() {
      // WARNING: this does not validate the return type. Check carefully.
      Ok(Some(
        serde_wasm_bindgen::to_value(params_ec).wasm_result()?.unchecked_into(),
      ))
    } else {
      Ok(None)
    }
  }

  /// If this JWK is of kty OKP, returns those parameters.
  #[wasm_bindgen(js_name = paramsOkp)]
  pub fn params_okp(&self) -> crate::error::Result<Option<WasmJwkParamsOkp>> {
    if let JwkParams::Okp(params_okp) = self.0.params() {
      // WARNING: this does not validate the return type. Check carefully.
      Ok(Some(
        serde_wasm_bindgen::to_value(params_okp).wasm_result()?.unchecked_into(),
      ))
    } else {
      Ok(None)
    }
  }

  /// If this JWK is of kty OCT, returns those parameters.
  #[wasm_bindgen(js_name = paramsOct)]
  pub fn params_oct(&self) -> crate::error::Result<Option<WasmJwkParamsOct>> {
    if let JwkParams::Oct(params_oct) = self.0.params() {
      // WARNING: this does not validate the return type. Check carefully.
      Ok(Some(
        serde_wasm_bindgen::to_value(params_oct).wasm_result()?.unchecked_into(),
      ))
    } else {
      Ok(None)
    }
  }

  /// If this JWK is of kty RSA, returns those parameters.
  #[wasm_bindgen(js_name = paramsRsa)]
  pub fn params_rsa(&self) -> crate::error::Result<Option<WasmJwkParamsRsa>> {
    if let JwkParams::Rsa(params_rsa) = self.0.params() {
      // WARNING: this does not validate the return type. Check carefully.
      Ok(Some(
        serde_wasm_bindgen::to_value(params_rsa).wasm_result()?.unchecked_into(),
      ))
    } else {
      Ok(None)
    }
  }

  /// If this JWK is of kty AKP, returns those parameters.
  #[wasm_bindgen(js_name = paramsAkp)]
  pub fn params_akp(&self) -> crate::error::Result<Option<WasmJwkParamsAkp>> {
    if let JwkParams::Akp(params_akp) = self.0.params() {
      // WARNING: this does not validate the return type. Check carefully.
      Ok(Some(
        serde_wasm_bindgen::to_value(params_akp).wasm_result()?.unchecked_into(),
      ))
    } else {
      Ok(None)
    }
  }

  /// Creates a Thumbprint of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638).
  ///
  /// `SHA2-256` is used as the hash function *H*.
  ///
  /// The thumbprint is returned as a base64url-encoded string.
  #[wasm_bindgen(js_name = thumbprintSha256B64)]
  pub fn thumbprint_sha256_b64(&self) -> String {
    self.0.thumbprint_sha256_b64()
  }

  /// Returns a clone of the {@link Jwk} with _all_ private key components unset.
  /// Nothing is returned when `kty = oct` as this key type is not considered public by this library.
  #[wasm_bindgen(js_name = toPublic)]
  pub fn to_public(&self) -> Option<WasmJwk> {
    self.0.to_public().map(WasmJwk)
  }

  /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
  #[wasm_bindgen(js_name = isPublic)]
  pub fn is_public(&self) -> bool {
    self.0.is_public()
  }

  /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
  #[wasm_bindgen(js_name = isPrivate)]
  pub fn is_private(&self) -> bool {
    self.0.is_private()
  }
}

impl From<WasmJwk> for Jwk {
  fn from(value: WasmJwk) -> Self {
    value.0
  }
}

impl From<Jwk> for WasmJwk {
  fn from(value: Jwk) -> Self {
    WasmJwk(value)
  }
}

impl_wasm_json!(WasmJwk, Jwk);
impl_wasm_clone!(WasmJwk, Jwk);

#[wasm_bindgen(typescript_custom_section)]
const I_JWK: &'static str = r#"
type IJwkParams = IJwkEc | IJwkRsa | IJwkOkp | IJwkOct | IJwkAkp
/** A JSON Web Key with EC params. */
export interface IJwkEc extends IJwk, JwkParamsEc {
  kty: JwkType.Ec
}
/** A JSON Web Key with RSA params. */
export interface IJwkRsa extends IJwk, JwkParamsRsa {
  kty: JwkType.Rsa
}
/** A JSON Web Key with OKP params. */
export interface IJwkOkp extends IJwk, JwkParamsOkp {
  kty: JwkType.Okp
}
/** A JSON Web Key with OCT params. */
export interface IJwkOct extends IJwk, JwkParamsOct {
  kty: JwkType.Oct
}
/** A JSON Web Key with AKP params. */
export interface IJwkAkp extends IJwk, JwkParamsAkp {
  kty: JwkType.Akp
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const I_JWK: &'static str = r#"
/** A JSON Web Key. */
export interface IJwk {
  /** Key Type.

  Identifies the cryptographic algorithm family used with the key.
  
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.1) */
  kty: JwkType
  /** Public Key Use.
  
  Identifies the intended use of the public key.
  
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.2) */
  use?: JwkUse
  /** Key Operations.
 
  Identifies the operation(s) for which the key is intended to be used.
 
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.3) */
  key_ops?: JwkOperation[]
  /** Algorithm.
 
  Identifies the algorithm intended for use with the key.
 
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.4) */
  alg?: JwsAlgorithm
  /** Key ID.
 
  Used to match a specific key among a set of keys within a JWK Set.
 
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.5) */
  kid?: string
  /** X.509 URL.
 
  A URI that refers to a resource for an X.509 public key certificate or
  certificate chain.
  
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.6) */
  x5u?: string
  /** X.509 Certificate Chain.
 
  Contains a chain of one or more PKIX certificates.
 
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.7) */
  x5c?: string[]
  /** X.509 Certificate SHA-1 Thumbprint.

  A base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509
  certificate.

  [More Info](https://tools.ietf.org/html/rfc7517#section-4.8) */
  x5t?: string
  /** X.509 Certificate SHA-256 Thumbprint.
 
  A base64url-encoded SHA-256 thumbprint of the DER encoding of an X.509
  certificate.
 
  [More Info](https://tools.ietf.org/html/rfc7517#section-4.9) */
  'x5t#S256'?: string
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const IJWK_PARAMS_EC: &str = r#"
/** Parameters for Elliptic Curve Keys.
 * 
 * [More Info](https://tools.ietf.org/html/rfc7518#section-6.2) */
interface JwkParamsEc {
  /** Identifies the cryptographic curve used with the key.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.1.1) */
  crv: string
  /** The `x` coordinate for the Elliptic Curve point as a base64url-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.1.2) */
  x: string
  /** The `y` coordinate for the Elliptic Curve point as a base64url-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.1.3) */
  y: string
  /** The Elliptic Curve private key as a base64url-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.2.1) */
  d?: string
}"#;

#[wasm_bindgen(typescript_custom_section)]
const IJWK_PARAMS_OKP: &str = r#"
/** Parameters for Octet Key Pairs.
 * 
 * [More Info](https://tools.ietf.org/html/rfc8037#section-2) */
interface JwkParamsOkp {
  /** The subtype of the key pair.
   * 
   * [More Info](https://tools.ietf.org/html/rfc8037#section-2) */
  crv: string
  /** The public key as a base64url-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc8037#section-2) */
  x: string
  /** The private key as a base64url-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc8037#section-2) */
  d?: string
}"#;

#[wasm_bindgen(typescript_custom_section)]
const IJWK_PARAMS_RSA: &str = r#"
/** Parameters for RSA Keys.
 * 
 * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3) */
interface JwkParamsRsa {
  /** The modulus value for the RSA public key as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.1.1) */
  n: string,
  /** The exponent value for the RSA public key as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.1.2) */
  e: string,
  /** The private exponent value for the RSA private key as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.1) */
  d?: string,
  /** The first prime factor as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.2) */
  p?: string,
  /** The second prime factor as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.3) */
  q?: string,
  /** The Chinese Remainder Theorem (CRT) exponent of the first factor as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.4)  */
  dp?: string,
  /** The CRT exponent of the second factor as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.5) */
  dq?: string,
  /** The CRT coefficient of the second factor as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.6) */
  qi?: string,
  /** An array of information about any third and subsequent primes, should they exist.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7) */
  oth?: JwkParamsRsaPrime[],
}

/** Parameters for RSA Primes
 * 
 * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7) */
interface JwkParamsRsaPrime {
  /** The value of a subsequent prime factor as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7.1)  */
  r: string,
  /** The CRT exponent of the corresponding prime factor as a base64urlUInt-encoded value. 
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7.2) */
  d: string,
  /** The CRT coefficient of the corresponding prime factor as a base64urlUInt-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7.3) */
  t: string,
}"#;

#[wasm_bindgen(typescript_custom_section)]
const IJWK_PARAMS_OKP: &str = r#"
/** Parameters for Symmetric Keys.
 * 
 * [More Info](https://tools.ietf.org/html/rfc7518#section-6.4) */
interface JwkParamsOct {
  /** The symmetric key as a base64url-encoded value.
   * 
   * [More Info](https://tools.ietf.org/html/rfc7518#section-6.4.1) */
  k: string
}"#;

#[wasm_bindgen(typescript_custom_section)]
const IJWK_PARAMS_AKP: &str = r#"
/** Parameters for Algorithm Key Pair (AKP).
 * 
 * [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-06#name-algorithm-key-pair-type) */
interface JwkParamsAkp {
  pub: string,
  priv?: string
}"#;
