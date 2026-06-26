// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_ecdsa_verifier::EcDSAJwsVerifier;
use identity_eddsa_verifier::Ed25519Verifier;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::jws::JwsVerifier;
use identity_iota::verification::jws::VerificationInput;
use wasm_bindgen::prelude::*;

use crate::error::WasmResult;
use crate::jose::WasmJwk;
use crate::jose::WasmJwsAlgorithm;

/// Verify a JWS signature secured with the `EdDSA` algorithm and curve `Ed25519`.
///
/// This function is useful when one is composing a `IJwsVerifier` that delegates
/// `EdDSA` verification with curve `Ed25519` to this function.
///
/// # Warning
///
/// This function does not check whether `alg = EdDSA` in the protected header. Callers are expected to assert this
/// prior to calling the function.
#[wasm_bindgen(js_name = verifyEd25519)]
#[allow(non_snake_case)]
pub fn verify_ed25519(
  alg: WasmJwsAlgorithm,
  signingInput: &[u8],
  decodedSignature: &[u8],
  publicKey: &WasmJwk,
) -> Result<(), JsValue> {
  let alg: JwsAlgorithm = JwsAlgorithm::try_from(alg)?;
  let input: VerificationInput = VerificationInput {
    alg,
    signing_input: Box::from(signingInput),
    decoded_signature: Box::from(decodedSignature),
  };
  Ed25519Verifier::verify(input, &publicKey.0).wasm_result()
}

/// An implementor of `IJwsVerifier` that can handle the
/// `EdDSA` algorithm.
#[wasm_bindgen(js_name = EdDSAJwsVerifier)]
pub struct WasmEdDSAJwsVerifier();

#[wasm_bindgen(js_class = EdDSAJwsVerifier)]
#[allow(clippy::new_without_default)]
impl WasmEdDSAJwsVerifier {
  /// Constructs an EdDSAJwsVerifier.
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
    Self()
  }

  /// Verify a JWS signature secured with the `EdDSA` algorithm.
  /// Only the `Ed25519` curve is supported for now.
  ///
  /// This function is useful when one is building an `IJwsVerifier` that extends the default provided by
  /// the IOTA Identity Framework.
  ///
  /// # Warning
  ///
  /// This function does not check whether `alg = EdDSA` in the protected header. Callers are expected to assert this
  /// prior to calling the function.
  #[wasm_bindgen]
  #[allow(non_snake_case)]
  pub fn verify(
    &self,
    alg: WasmJwsAlgorithm,
    signingInput: &[u8],
    decodedSignature: &[u8],
    publicKey: &WasmJwk,
  ) -> Result<(), JsValue> {
    let alg: JwsAlgorithm = JwsAlgorithm::try_from(alg)?;
    let input: VerificationInput = VerificationInput {
      alg,
      signing_input: signingInput.into(),
      decoded_signature: decodedSignature.into(),
    };
    EdDSAJwsVerifier::default().verify(input, &publicKey.0).wasm_result()
  }
}

/// An implementor of `IJwsVerifier` that can handle the
/// `EcDSA` algorithm.
#[wasm_bindgen(js_name = EcDSAJwsVerifier)]
pub struct WasmEcDSAJwsVerifier();

#[wasm_bindgen(js_class = EcDSAJwsVerifier)]
#[allow(clippy::new_without_default)]
impl WasmEcDSAJwsVerifier {
  /// Constructs an EcDSAJwsVerifier.
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
    Self()
  }

  /// Verify a JWS signature secured with the `EcDSA` algorithm.
  /// Only the `ES256` and `ES256K` curves are supported for now.
  ///
  /// # Warning
  ///
  /// This function does not check the `alg` property in the protected header. Callers are expected to assert this
  /// prior to calling the function.
  #[wasm_bindgen]
  #[allow(non_snake_case)]
  pub fn verify(
    &self,
    alg: WasmJwsAlgorithm,
    signingInput: &[u8],
    decodedSignature: &[u8],
    publicKey: &WasmJwk,
  ) -> Result<(), JsValue> {
    let alg: JwsAlgorithm = JwsAlgorithm::try_from(alg)?;
    let input: VerificationInput = VerificationInput {
      alg,
      signing_input: signingInput.into(),
      decoded_signature: decodedSignature.into(),
    };
    EcDSAJwsVerifier::default().verify(input, &publicKey.0).wasm_result()
  }
}
