// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Formatter;
use core::fmt::Result;

use serde;
use serde::Deserialize;
use serde::Serialize;

use crate::common::Object;
use crate::common::Url;

/// A reference to a JSON-LD context
///
/// [More Info](https://www.w3.org/TR/vc-data-model/#contexts)
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
#[serde(untagged)]
pub enum Context {
  /// A JSON-LD context expressed as a Url.
  Url(Url),
  /// A JSON-LD context expressed as a JSON object.
  Obj(Object),
}

impl Debug for Context {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    match self {
      Self::Url(inner) => Debug::fmt(inner, f),
      Self::Obj(inner) => Debug::fmt(inner, f),
    }
  }
}

impl From<Url> for Context {
  fn from(other: Url) -> Self {
    Self::Url(other)
  }
}

impl From<Object> for Context {
  fn from(other: Object) -> Self {
    Self::Obj(other)
  }
}

impl<T> PartialEq<T> for Context
where
  T: AsRef<str> + ?Sized,
{
  fn eq(&self, other: &T) -> bool {
    match self {
      Self::Url(inner) => inner.as_str() == other.as_ref(),
      Self::Obj(_) => false,
    }
  }
}
