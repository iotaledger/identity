// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::decoded_jwt_presentation::WasmDecodedJwtPresentation;
use super::options::WasmJwtPresentationValidationOptions;
use crate::common::ImportedDocumentLock;
use crate::credential::WasmJwt;
use crate::credential::WasmPresentation;
use crate::did::IToCoreDocument;
use crate::did::WasmCoreDID;
use crate::error::Result;
use crate::error::WasmResult;
use crate::verification::IJwsVerifier;
use crate::verification::WasmJwsVerifier;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::did::CoreDID;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = JwtPresentationValidator, inspectable)]
pub struct WasmJwtPresentationValidator(JwtPresentationValidator<WasmJwsVerifier>);

#[wasm_bindgen(js_class = JwtPresentationValidator)]
impl WasmJwtPresentationValidator {
  /// Creates a new {@link JwtPresentationValidator}. If a `signatureVerifier` is provided it will be used when
  /// verifying decoded JWS signatures, otherwise a default verifier capable of handling the `EdDSA`, `ES256`, `ES256K`
  /// algorithms will be used.
  #[wasm_bindgen(constructor)]
  #[allow(non_snake_case)]
  pub fn new(signatureVerifier: Option<IJwsVerifier>) -> WasmJwtPresentationValidator {
    let signature_verifier = WasmJwsVerifier::new(signatureVerifier);
    WasmJwtPresentationValidator(JwtPresentationValidator::with_signature_verifier(signature_verifier))
  }

  /// Validates a {@link Presentation} encoded as a {@link Jwt}.
  ///
  /// The following properties are validated according to `options`:
  /// - the JWT can be decoded into a semantically valid presentation.
  /// - the expiration and issuance date contained in the JWT claims.
  /// - the holder's signature.
  ///
  /// Validation is done with respect to the properties set in `options`.
  ///
  /// # Warning
  ///
  /// * This method does NOT validate the constituent credentials and therefore also not the relationship between the
  /// credentials' subjects and the presentation holder. This can be done with {@link JwtCredentialValidationOptions}.
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the presentation can
  /// be trusted. This section contains more information on additional checks that should be carried out before and
  /// after calling this method.
  ///
  /// ## The state of the supplied DID Documents.
  ///
  /// The caller must ensure that the DID Documents in `holder` are up-to-date.
  ///
  /// # Errors
  ///
  /// An error is returned whenever a validated condition is not satisfied or when decoding fails.
  #[wasm_bindgen]
  #[allow(non_snake_case)]
  pub fn validate(
    &self,
    presentationJwt: &WasmJwt,
    holder: &IToCoreDocument,
    validation_options: &WasmJwtPresentationValidationOptions,
  ) -> Result<WasmDecodedJwtPresentation> {
    let holder_lock = ImportedDocumentLock::from(holder);
    let holder_guard = holder_lock.try_read()?;

    self
      .0
      .validate(&presentationJwt.0, &holder_guard, &validation_options.0)
      .map(WasmDecodedJwtPresentation::from)
      .wasm_result()
  }

  /// Validates the semantic structure of the {@link Presentation}.
  #[wasm_bindgen(js_name = checkStructure)]
  pub fn check_structure(presentation: &WasmPresentation) -> Result<()> {
    JwtPresentationValidatorUtils::check_structure(&presentation.0).wasm_result()?;
    Ok(())
  }

  /// Attempt to extract the holder of the presentation.
  ///
  /// # Errors:
  /// * If deserialization/decoding of the presentation fails.
  /// * If the holder can't be parsed as DIDs.
  #[wasm_bindgen(js_name = extractHolder)]
  pub fn extract_holder(presentation: &WasmJwt) -> Result<WasmCoreDID> {
    let holder = JwtPresentationValidatorUtils::extract_holder::<CoreDID>(&presentation.0).wasm_result()?;
    Ok(WasmCoreDID(holder))
  }
}
