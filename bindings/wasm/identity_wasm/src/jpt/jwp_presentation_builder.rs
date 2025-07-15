// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::WasmJwpIssued;
use super::WasmPresentationProtectedHeader;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::SelectiveDisclosurePresentation;
use wasm_bindgen::prelude::*;

/// Used to construct a JwpPresentedBuilder and handle the selective disclosure of attributes
/// - @context MUST NOT be blinded
/// - id MUST be blinded
/// - type MUST NOT be blinded
/// - issuer MUST NOT be blinded
/// - issuanceDate MUST be blinded (if Timeframe Revocation mechanism is used)
/// - expirationDate MUST be blinded (if Timeframe Revocation mechanism is used)
/// - credentialSubject (User have to choose which attribute must be blinded)
/// - credentialSchema MUST NOT be blinded
/// - credentialStatus MUST NOT be blinded
/// - refreshService MUST NOT be blinded (probably will be used for Timeslot Revocation mechanism)
/// - termsOfUse NO reason to use it in ZK VC (will be in any case blinded)
/// - evidence (User have to choose which attribute must be blinded)
#[wasm_bindgen(js_name = SelectiveDisclosurePresentation)]
pub struct WasmSelectiveDisclosurePresentation(pub(crate) SelectiveDisclosurePresentation);

impl From<WasmSelectiveDisclosurePresentation> for SelectiveDisclosurePresentation {
  fn from(value: WasmSelectiveDisclosurePresentation) -> Self {
    value.0
  }
}

impl From<SelectiveDisclosurePresentation> for WasmSelectiveDisclosurePresentation {
  fn from(value: SelectiveDisclosurePresentation) -> Self {
    WasmSelectiveDisclosurePresentation(value)
  }
}

#[wasm_bindgen(js_class = SelectiveDisclosurePresentation)]
impl WasmSelectiveDisclosurePresentation {
  /// Initialize a presentation starting from an Issued JWP.
  /// The properties `jti`, `nbf`, `issuanceDate`, `expirationDate` and `termsOfUse` are concealed by default.
  #[wasm_bindgen(constructor)]
  pub fn new(issued_jwp: WasmJwpIssued) -> WasmSelectiveDisclosurePresentation {
    SelectiveDisclosurePresentation::new(&issued_jwp.0).into()
  }

  /// Selectively disclose "credentialSubject" attributes.
  /// # Example
  /// ```
  /// {
  ///     "id": 1234,
  ///     "name": "Alice",
  ///     "mainCourses": ["Object-oriented Programming", "Mathematics"],
  ///     "degree": {
  ///         "type": "BachelorDegree",
  ///         "name": "Bachelor of Science and Arts",
  ///     },
  ///     "GPA": "4.0",
  /// }
  /// ```
  /// If you want to undisclose for example the Mathematics course and the name of the degree:
  /// ```
  /// undisclose_subject("mainCourses[1]");
  /// undisclose_subject("degree.name");
  /// ```
  #[wasm_bindgen(js_name = concealInSubject)]
  pub fn conceal_in_subject(&mut self, path: String) -> Result<()> {
    self.0.conceal_in_subject(&path).wasm_result()
  }

  /// Undiscloses "evidence" attributes.
  #[wasm_bindgen(js_name = concealInEvidence)]
  pub fn conceal_in_evidence(&mut self, path: String) -> Result<()> {
    self.0.conceal_in_evidence(&path).wasm_result()
  }

  /// Sets presentation protected header.
  #[wasm_bindgen(js_name = setPresentationHeader)]
  pub fn set_presentation_header(&mut self, header: WasmPresentationProtectedHeader) {
    self.0.set_presentation_header(header.into())
  }
}
