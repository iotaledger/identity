// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt::Display;

use itertools;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
/// An error associated with validating credentials and presentations.
pub enum ValidationError {
  /// Indicates that the expiration date of the credential is not considered valid.
  #[error("the expiration date is in the past or earlier than required")]
  ExpirationDate,
  /// Indicates that the issuance date of the credential is not considered valid.
  #[error("issuance date is in the future or later than required")]
  IssuanceDate,
  /// Indicates that the credential's (resp. presentation's) signature could not be verified using
  /// the issuer's (resp. holder's) DID Document.
  #[error("could not verify the {signer_ctx}'s signature")]
  #[non_exhaustive]
  Signature {
    /// Signature verification error.
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
    /// Specifies whether the error was from the DID Document of a credential issuer
    /// or the presentation holder.
    signer_ctx: SignerContext,
  },

  /// Indicates that the credential's (resp. presentation's) issuer's (resp. holder's) URL could
  /// not be parsed as a valid DID.
  #[error("{signer_ctx} URL is not a valid DID")]
  #[non_exhaustive]
  SignerUrl {
    /// DID parsing error.
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
    /// Specifies whether the error relates to the DID of a credential issuer
    /// or the presentation holder.
    signer_ctx: SignerContext,
  },

  /// Indicates an attempt to verify a signature of a credential (resp. presentation) using a
  /// DID Document not matching the issuer's (resp. holder's) id.
  #[error("the {0}'s id does not match the provided DID Document(s)")]
  #[non_exhaustive]
  DocumentMismatch(SignerContext),

  /// Indicates that the structure of the [Credential](crate::credential::Credential) is not semantically
  /// correct.
  #[error("the credential's structure is not semantically correct")]
  CredentialStructure(#[source] crate::Error),
  /// Indicates that the structure of the [Presentation](crate::presentation::Presentation) is not
  /// semantically correct.
  #[error("the presentation's structure is not semantically correct")]
  PresentationStructure(#[source] crate::Error),
  /// Indicates that the relationship between the presentation holder and one of the credential subjects is not valid.
  #[error("expected holder = subject of the credential")]
  #[non_exhaustive]
  SubjectHolderRelationship,
  /// Indicates that the presentation does not have a holder.
  #[error("the presentation has an empty holder property")]
  MissingPresentationHolder,
  /// Indicates that the credential's status is invalid.
  #[error("invalid credential status")]
  InvalidStatus(#[source] crate::Error),
  /// Indicates that the the credential's service is invalid.
  #[error("invalid service")]
  InvalidService(#[source] identity_did::Error),
  /// Indicates that the credential has been revoked.
  #[error("credential has been revoked")]
  Revoked,
}

/// Specifies whether an error is related to a credential issuer or the presentation holder.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignerContext {
  /// Credential issuer.
  Issuer,
  /// Presentation holder.
  Holder,
}

impl Display for SignerContext {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let context = match *self {
      Self::Issuer => "issuer",
      Self::Holder => "holder",
    };
    write!(f, "{}", context)
  }
}

/// Errors caused by a failure to validate a credential.
#[derive(Debug)]
pub struct CompoundCredentialValidationError {
  /// List of credential validation errors.
  pub validation_errors: Vec<ValidationError>,
}

impl Display for CompoundCredentialValidationError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // intersperse might become available in the standard library soon: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.intersperse
    let detailed_information: String = itertools::intersperse(
      self.validation_errors.iter().map(|err| err.to_string()),
      "; ".to_string(),
    )
    .collect();
    write!(f, "[{}]", detailed_information)
  }
}

impl std::error::Error for CompoundCredentialValidationError {}

#[derive(Debug)]
/// An error caused by a failure to validate a Presentation.
pub struct CompoundPresentationValidationError {
  /// Errors that occurred during validation of individual credentials, mapped by index of their
  /// order in the presentation.
  pub credential_errors: BTreeMap<usize, CompoundCredentialValidationError>,
  /// Errors that occurred during validation of the presentation.
  pub presentation_validation_errors: Vec<ValidationError>,
}

impl Display for CompoundPresentationValidationError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let credential_error_formatter = |(position, reason): (&usize, &CompoundCredentialValidationError)| -> String {
      format!("credential num. {} errors: {}", position, reason.to_string().as_str())
    };

    let error_string_iter = self
      .presentation_validation_errors
      .iter()
      .map(|error| error.to_string())
      .chain(self.credential_errors.iter().map(credential_error_formatter));
    let detailed_information: String = itertools::intersperse(error_string_iter, "; ".to_string()).collect();
    write!(f, "[{}]", detailed_information)
  }
}

impl std::error::Error for CompoundPresentationValidationError {}
