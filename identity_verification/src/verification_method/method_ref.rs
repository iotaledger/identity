// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Formatter;

use identity_core::common::KeyComparable;
use identity_did::DID;
use serde::Serialize;
use serde::Serializer;

use crate::verification_method::VerificationMethod;
use crate::Error;
use identity_did::CoreDID;
use identity_did::DIDUrl;

/// A reference to a verification method, either a `DID` or embedded `Method`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum MethodRef {
  /// A [`VerificationMethod`] embedded in a verification relationship.
  Embed(VerificationMethod),
  /// A reference to a [`VerificationMethod`] in a verification relationship.
  Refer(DIDUrl),
  /// A relative reference to a [`VerificationMethod`] in current document
  RelativeRefer(DIDUrl),
}

impl MethodRef {
  /// Returns a reference to the `MethodRef` id.
  pub fn id(&self) -> &DIDUrl {
    match self {
      Self::Embed(inner) => inner.id(),
      Self::Refer(inner) => inner,
      Self::RelativeRefer(inner) => inner,
    }
  }

  /// Returns a reference to the [`MethodRef`] controller.
  ///
  /// Always `None` for [`MethodRef::Refer`].
  pub fn controller(&self) -> Option<&CoreDID> {
    match self {
      Self::Embed(inner) => Some(inner.controller()),
      Self::Refer(_) => None,
      Self::RelativeRefer(_) => None,
    }
  }

  /// Returns a `bool` indicating if the `MethodRef` is an embedded `Method`.
  #[inline]
  pub fn is_embedded(&self) -> bool {
    matches!(self, Self::Embed(_))
  }

  /// Returns a `bool` indicating if the `MethodRef` is a `DID` reference.
  #[inline]
  pub fn is_referred(&self) -> bool {
    matches!(self, Self::Refer(_))
  }

  /// Maps the [`MethodRef`] by applying a function `f` to the inner
  /// [`VerificationMethod`] or [`DIDUrl`]. This can be useful for DID methods
  /// where the DID is not known before the document has been published.
  pub fn map<F>(self, f: F) -> MethodRef
  where
    F: FnMut(CoreDID) -> CoreDID,
  {
    match self {
      MethodRef::Embed(method) => MethodRef::Embed(method.map(f)),
      MethodRef::Refer(id) => MethodRef::Refer(id.map(f)),
      MethodRef::RelativeRefer(id) => MethodRef::Refer(id.map(f)),
    }
  }

  /// Fallible version of [`MethodRef::map`].
  pub fn try_map<F, E>(self, f: F) -> Result<MethodRef, E>
  where
    F: FnMut(CoreDID) -> Result<CoreDID, E>,
  {
    Ok(match self {
      MethodRef::Embed(method) => MethodRef::Embed(method.try_map(f)?),
      MethodRef::Refer(id) => MethodRef::Refer(id.try_map(f)?),
      MethodRef::RelativeRefer(id) => MethodRef::Refer(id.try_map(f)?),
    })
  }

  /// Returns the inner `Method` if this is an embedded `MethodRef`.
  ///
  /// Note: Returns `Err(self)` as a failure case.
  ///
  /// # Errors
  ///
  /// Fails if `MethodRef` is not an embedded method.
  pub fn try_into_embedded(self) -> Result<VerificationMethod, Box<Self>> {
    match self {
      Self::Embed(inner) => Ok(inner),
      Self::Refer(_) => Err(self.into()),
      Self::RelativeRefer(_) => Err(self.into()),
    }
  }

  /// Returns the inner `Method` if this is an referenced `MethodRef`.
  ///
  /// Note: Returns `Err(self)` as a failure case.
  ///
  /// # Errors
  ///
  /// Fails if `MethodRef` is not an referenced method.
  pub fn try_into_referenced(self) -> Result<DIDUrl, Box<Self>> {
    match self {
      Self::Embed(_) => Err(self.into()),
      Self::Refer(inner) => Ok(inner),
      Self::RelativeRefer(inner) => Ok(inner),
    }
  }

  /// Try to build instance from [`serde_json::Value`].
  pub fn try_from_value(value: &serde_json::Value, id: &CoreDID) -> Result<MethodRef, Error> {
    let parsed = match value {
      // relative references will be joined with document id
      serde_json::Value::String(string_value) => {
        if !string_value.starts_with("did:") {
          MethodRef::RelativeRefer(id.clone().join(string_value).map_err(Error::DIDUrlConstructionError)?)
        } else {
          serde_json::from_value(value.clone())?
        }
      }
      // otherwise parse as usual
      _ => serde_json::from_value(value.clone())?,
    };

    Ok(parsed)
  }
}

impl Debug for MethodRef {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::Embed(inner) => Debug::fmt(inner, f),
      Self::Refer(inner) => Debug::fmt(inner, f),
      Self::RelativeRefer(inner) => Debug::fmt(inner, f),
    }
  }
}

impl From<VerificationMethod> for MethodRef {
  #[inline]
  fn from(other: VerificationMethod) -> Self {
    Self::Embed(other)
  }
}

impl From<DIDUrl> for MethodRef {
  #[inline]
  fn from(other: DIDUrl) -> Self {
    Self::Refer(other)
  }
}

impl AsRef<DIDUrl> for MethodRef {
  #[inline]
  fn as_ref(&self) -> &DIDUrl {
    self.id()
  }
}

impl KeyComparable for MethodRef {
  type Key = DIDUrl;

  #[inline]
  fn key(&self) -> &Self::Key {
    self.id()
  }
}

impl Serialize for MethodRef {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    match self {
      Self::Embed(value) => value.serialize(serializer),
      Self::Refer(value) => value.serialize(serializer),
      Self::RelativeRefer(value) => serializer.serialize_str(&value.url().to_string()),
    }
  }
}
