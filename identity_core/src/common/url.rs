// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::ops::Deref;
use core::ops::DerefMut;
use core::str::FromStr;

use serde;
use serde::Deserialize;
use serde::Serialize;

use crate::common::KeyComparable;
use crate::error::Error;
use crate::error::Result;

/// A parsed URL.
#[derive(Clone, Hash, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Url(::url::Url);

impl Url {
  /// Parses an absolute [`Url`] from the given input string.
  pub fn parse(input: impl AsRef<str>) -> Result<Self> {
    ::url::Url::parse(input.as_ref()).map_err(Error::InvalidUrl).map(Self)
  }

  /// Consumes the [`Url`] and returns the value as a `String`.
  pub fn into_string(self) -> String {
    self.0.to_string()
  }

  /// Parses the given input string as a [`Url`], with `self` as the base Url.
  pub fn join(&self, input: impl AsRef<str>) -> Result<Self> {
    self.0.join(input.as_ref()).map_err(Error::InvalidUrl).map(Self)
  }
}

impl Debug for Url {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("Url({})", self.0.as_str()))
  }
}

impl Display for Url {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.0.as_str())
  }
}

impl Deref for Url {
  type Target = ::url::Url;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl DerefMut for Url {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.0
  }
}

impl From<::url::Url> for Url {
  fn from(other: ::url::Url) -> Self {
    Self(other)
  }
}

impl FromStr for Url {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    Self::parse(string)
  }
}

impl<T> PartialEq<T> for Url
where
  T: AsRef<str> + ?Sized,
{
  fn eq(&self, other: &T) -> bool {
    self.as_str() == other.as_ref()
  }
}

impl KeyComparable for Url {
  type Key = Url;

  #[inline]
  fn key(&self) -> &Self::Key {
    self
  }
}

impl AsRef<str> for Url {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

#[cfg(feature = "irl")]
mod irl_integraton {
  use super::Url;

  use iota_caip::iota::IotaResourceLocator as Irl;
  impl From<Irl> for Url {
    fn from(irl: Irl) -> Self {
      Url::parse(irl.as_str()).expect("an IOTA Resource Locator is always a valid URL")
    }
  }
}
