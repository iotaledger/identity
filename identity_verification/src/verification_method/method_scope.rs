// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use core::fmt::Display;
use core::str::FromStr;

use identity_core::convert::FmtJson;

use crate::error::Error;
use crate::error::Result;
use crate::verification_method::MethodRelationship;

/// The scope of a [`VerificationMethod`](crate::VerificationMethod).
///
/// Can either refer to a generic method embedded in the verification method field,
/// or to a verification relationship.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[derive(Default)]
pub enum MethodScope {
  /// The scope of generic verification methods.
  #[default]
  VerificationMethod,
  /// The scope of a specific [`MethodRelationship`].
  VerificationRelationship(MethodRelationship),
}

impl MethodScope {
  /// Returns the string representation of the scope.
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::VerificationMethod => "VerificationMethod",
      Self::VerificationRelationship(relationship) => relationship.into(),
    }
  }

  /// The verification relationship scope of [`MethodRelationship::Authentication`].
  pub const fn authentication() -> Self {
    Self::VerificationRelationship(MethodRelationship::Authentication)
  }

  /// The verification relationship scope of [`MethodRelationship::CapabilityDelegation`].
  pub const fn capability_delegation() -> Self {
    Self::VerificationRelationship(MethodRelationship::CapabilityDelegation)
  }

  /// The verification relationship scope of [`MethodRelationship::CapabilityInvocation`].
  pub const fn capability_invocation() -> Self {
    Self::VerificationRelationship(MethodRelationship::CapabilityInvocation)
  }

  /// The verification relationship scope of [`MethodRelationship::AssertionMethod`].
  pub const fn assertion_method() -> Self {
    Self::VerificationRelationship(MethodRelationship::AssertionMethod)
  }

  /// The verification relationship scope of [`MethodRelationship::KeyAgreement`].
  pub const fn key_agreement() -> Self {
    Self::VerificationRelationship(MethodRelationship::KeyAgreement)
  }
}


impl FromStr for MethodScope {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    match string {
      "VerificationMethod" => Ok(Self::VerificationMethod),
      "Authentication" => Ok(Self::VerificationRelationship(MethodRelationship::Authentication)),
      "AssertionMethod" => Ok(Self::VerificationRelationship(MethodRelationship::AssertionMethod)),
      "KeyAgreement" => Ok(Self::VerificationRelationship(MethodRelationship::KeyAgreement)),
      "CapabilityDelegation" => Ok(Self::VerificationRelationship(MethodRelationship::CapabilityDelegation)),
      "CapabilityInvocation" => Ok(Self::VerificationRelationship(MethodRelationship::CapabilityInvocation)),
      _ => Err(Error::UnknownMethodScope),
    }
  }
}

impl From<MethodRelationship> for MethodScope {
  fn from(relationship: MethodRelationship) -> Self {
    Self::VerificationRelationship(relationship)
  }
}

impl Display for MethodScope {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.fmt_json(f)
  }
}
