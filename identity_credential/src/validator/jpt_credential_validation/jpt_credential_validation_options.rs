// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use crate::validator::SubjectHolderRelationship;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_document::verifiable::JwpVerificationOptions;
use serde::Deserialize;
use serde::Serialize;

/// Options to declare validation criteria for [`Credential`](crate::credential::Credential)s.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JptCredentialValidationOptions {
  /// Declares that the credential is **not** considered valid if it expires before this
  /// [`Timestamp`].
  /// Uses the current datetime during validation if not set.
  #[serde(default)]
  pub earliest_expiry_date: Option<Timestamp>,

  /// Declares that the credential is **not** considered valid if it was issued later than this
  /// [`Timestamp`].
  /// Uses the current datetime during validation if not set.
  #[serde(default)]
  pub latest_issuance_date: Option<Timestamp>,

  /// Validation behaviour for [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status).
  ///
  /// Default: [`StatusCheck::Strict`](crate::validator::StatusCheck::Strict).
  #[serde(default)]
  pub status: crate::validator::StatusCheck,

  /// Declares how credential subjects must relate to the presentation holder during validation.
  ///
  /// <https://www.w3.org/TR/vc-data-model/#subject-holder-relationships>
  pub subject_holder_relationship: Option<(Url, SubjectHolderRelationship)>,

  /// Options which affect the verification of the proof on the credential.
  #[serde(default)]
  pub verification_options: JwpVerificationOptions,
}

impl JptCredentialValidationOptions {
  /// Constructor that sets all options to their defaults.
  pub fn new() -> Self {
    Self::default()
  }

  /// Declare that the credential is **not** considered valid if it expires before this [`Timestamp`].
  /// Uses the current datetime during validation if not set.
  pub fn earliest_expiry_date(mut self, timestamp: Timestamp) -> Self {
    self.earliest_expiry_date = Some(timestamp);
    self
  }

  /// Declare that the credential is **not** considered valid if it was issued later than this [`Timestamp`].
  /// Uses the current datetime during validation if not set.
  pub fn latest_issuance_date(mut self, timestamp: Timestamp) -> Self {
    self.latest_issuance_date = Some(timestamp);
    self
  }

  /// Sets the validation behaviour for [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status).
  pub fn status_check(mut self, status_check: crate::validator::StatusCheck) -> Self {
    self.status = status_check;
    self
  }

  /// Declares how credential subjects must relate to the presentation holder during validation.
  ///
  /// <https://www.w3.org/TR/vc-data-model/#subject-holder-relationships>
  pub fn subject_holder_relationship(
    mut self,
    holder: Url,
    subject_holder_relationship: SubjectHolderRelationship,
  ) -> Self {
    self.subject_holder_relationship = Some((holder, subject_holder_relationship));
    self
  }

  /// Set options which affect the verification of the JWP proof.
  pub fn verification_options(mut self, options: JwpVerificationOptions) -> Self {
    self.verification_options = options;
    self
  }
}
