// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This module is basically an adaptation of the old credential::validator::error module.
use std::fmt::Display;

use itertools;

#[cfg(target_arch = "wasm32")]
use product_common::impl_wasm_error_from;
#[cfg(target_arch = "wasm32")]
use product_common::bindings::wasm_error;
#[cfg(target_arch = "wasm32")]
use std::borrow::Cow;

/// An error associated with validating credentials and presentations.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum JwtValidationError {
  /// Indicates that the JWS representation of an issued credential or presentation could not be decoded.
  #[error("could not decode jws")]
  JwsDecodingError(#[source] identity_verification::jose::error::Error),

  /// Indicates error while verifying the JWS of a presentation.
  #[error("could not verify jws")]
  PresentationJwsError(#[source] identity_document::error::Error),

  /// Indicates that a verification method that both matches the DID Url specified by
  /// the `kid` value and contains a public key in the JWK format could not be found.
  #[error("could not find verification material")]
  MethodDataLookupError {
    /// The source of the error if set
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    /// A message providing more context
    message: &'static str,
    /// Specifies whether the error occurred when trying to verify the signature of a presentation holder or
    /// of a credential issuer.
    signer_ctx: SignerContext,
  },

  /// The DID part parsed from the `kid` does not match the identifier of the issuer (resp. holder) property
  /// of the credential (resp. presentation).
  #[error("identifier mismatch")]
  IdentifierMismatch {
    /// The context in which the error occurred.
    signer_ctx: SignerContext,
  },

  /// Indicates that the expiration date of the credential or presentation is not considered valid.
  #[error("the expiration date is in the past or earlier than required")]
  ExpirationDate,
  /// Indicates that the issuance date of the credential or presentation is not considered valid.
  #[error("issuance date is in the future or later than required")]
  IssuanceDate,
  /// Indicates that the credential's (resp. presentation's) signature could not be verified using
  /// the issuer's (resp. holder's) DID Document.
  #[error("could not verify the {signer_ctx}'s signature; {source}")]
  #[non_exhaustive]
  Signature {
    /// Signature verification error.
    source: identity_verification::jose::error::Error,
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
  #[error("service lookup error")]
  #[non_exhaustive]
  ServiceLookupError,
  /// Indicates that the credential has been revoked.
  #[error("credential has been revoked")]
  Revoked,
  /// Indicates that the credential has been suspended.
  #[error("credential has been suspended")]
  Suspended,
  /// Indicates that the credential's timeframe interval is not valid
  #[cfg(feature = "jpt-bbs-plus")]
  #[error("timeframe interval not valid")]
  OutsideTimeframe,
  /// Indicates that the JWP representation of an issued credential or presentation could not be decoded.
  #[cfg(feature = "jpt-bbs-plus")]
  #[error("could not decode jwp")]
  JwpDecodingError(#[source] jsonprooftoken::errors::CustomError),
  /// Indicates that the verification of the JWP has failed
  #[cfg(feature = "jpt-bbs-plus")]
  #[error("could not verify jwp")]
  JwpProofVerificationError(#[source] jsonprooftoken::errors::CustomError),
}

#[cfg(target_arch = "wasm32")]
impl_wasm_error_from!(JwtValidationError);

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
    write!(f, "{context}")
  }
}

/// Errors caused by a failure to validate a [`Credential`](crate::credential::Credential).
#[derive(Debug)]
pub struct CompoundCredentialValidationError {
  /// List of credential validation errors.
  pub validation_errors: Vec<JwtValidationError>,
}

#[cfg(target_arch = "wasm32")]
impl From<CompoundCredentialValidationError> for wasm_error::WasmError<'_> {
  fn from(error: CompoundCredentialValidationError) -> Self {
    Self {
      name: Cow::Borrowed("CompoundCredentialValidationError"),
      message: Cow::Owned(wasm_error::ErrorMessage(&error).to_string()),
    }
  }
}

impl Display for CompoundCredentialValidationError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // intersperse might become available in the standard library soon: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.intersperse
    let detailed_information: String = itertools::intersperse(
      self.validation_errors.iter().map(|err| err.to_string()),
      "; ".to_string(),
    )
    .collect();
    write!(f, "[{detailed_information}]")
  }
}

impl std::error::Error for CompoundCredentialValidationError {}
