// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::str::FromStr;
use std::hash::Hash;

use did_url_parser::DID as BaseDIDUrl;

use identity_core::common::KeyComparable;

use crate::DIDUrl;
use crate::Error;

pub trait DID:
  Clone
  + PartialEq
  + Eq
  + PartialOrd
  + Ord
  + Hash
  + FromStr
  + TryFrom<CoreDID>
  + Into<String>
  + Into<CoreDID>
  + AsRef<CoreDID>
{
  const SCHEME: &'static str = BaseDIDUrl::SCHEME;

  /// Returns the [`DID`] scheme. See [`DID::SCHEME`].
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "did"`
  /// - `"did:iota:main:12345678" -> "did"`
  fn scheme(&self) -> &'static str {
    self.as_ref().0.scheme()
  }

  /// Returns the [`DID`] authority: the method name and method-id.
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "example:12345678"`
  /// - `"did:iota:main:12345678" -> "iota:main:12345678"`
  fn authority(&self) -> &str {
    self.as_ref().0.authority()
  }

  /// Returns the [`DID`] method name.
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "example"`
  /// - `"did:iota:main:12345678" -> "iota"`
  fn method(&self) -> &str {
    self.as_ref().0.method()
  }

  /// Returns the [`DID`] method-specific ID.
  ///
  /// E.g.
  /// - `"did:example:12345678" -> "12345678"`
  /// - `"did:iota:main:12345678" -> "main:12345678"`
  fn method_id(&self) -> &str {
    self.as_ref().0.method_id()
  }

  /// Returns the serialized [`DID`].
  ///
  /// This is fast since the serialized value is stored in the [`DID`].
  fn as_str(&self) -> &str {
    self.as_ref().0.as_str()
  }

  /// Consumes the [`DID`] and returns its serialization.
  fn into_string(self) -> String {
    self.into()
  }

  /// Constructs a [`DIDUrl`] by attempting to append a string representing a path, query, and/or
  /// fragment to this [`DID`].
  ///
  /// See [`DIDUrl::join`].
  fn join(self, value: impl AsRef<str>) -> Result<DIDUrl, Error> {
    let url = DIDUrl::from(self);
    url.join(value)
  }

  /// Clones the [`DID`] into a [`DIDUrl`] of the same method.
  fn to_url(&self) -> DIDUrl {
    DIDUrl::new(self.clone().into(), None)
  }

  /// Converts the [`DID`] into a [`DIDUrl`] of the same method.
  fn into_url(self) -> DIDUrl {
    DIDUrl::from(self)
  }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
#[serde(into = "BaseDIDUrl", try_from = "BaseDIDUrl")]
/// A wrapper around [`BaseDIDUrl`](BaseDIDUrl).
pub struct CoreDID(BaseDIDUrl);

impl CoreDID {
  /// Parses a [`CoreDID`] from the given `input`.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`DID`].
  pub fn parse(input: impl AsRef<str>) -> Result<Self, Error> {
    let base_did_url = BaseDIDUrl::parse(input)?;
    base_did_url.try_into()
  }

  /// Set the method name of the [`DID`].
  pub fn set_method_name(&mut self, value: impl AsRef<str>) -> Result<(), Error> {
    Self::valid_method_name(value.as_ref())?;
    self.0.set_method(value);
    Ok(())
  }

  /// Validates whether a string is a valid [`DID`] method name.
  pub fn valid_method_name(value: &str) -> Result<(), Error> {
    if !value.chars().all(is_char_method_name) {
      return Err(Error::InvalidMethodName);
    }
    Ok(())
  }

  /// Set the method-specific-id of the [`DID`].
  pub fn set_method_id(&mut self, value: impl AsRef<str>) -> Result<(), Error> {
    Self::valid_method_id(value.as_ref())?;
    self.0.set_method_id(value);
    Ok(())
  }

  /// Validates whether a string is a valid [`DID`] method-id.
  pub fn valid_method_id(value: &str) -> Result<(), Error> {
    // if !value.chars().all(is_char_method_id) {
    //   return Err(Error::InvalidMethodId);
    // }
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
      match c {
        '%' => {
          let digits = chars.clone().take(2).collect::<String>();
          u8::from_str_radix(&digits, 16).map_err(|_| Error::InvalidMethodId)?;
          chars.next();
          chars.next();
        }
        c if is_char_method_id(c) => (),
        _ => return Err(Error::InvalidMethodId),
      }
    }

    Ok(())
  }

  /// Checks if the given `did` is valid according to the base [`DID`] specification.
  pub fn check_validity(did: &BaseDIDUrl) -> Result<(), Error> {
    // Validate basic DID constraints.
    Self::valid_method_name(did.method())?;
    Self::valid_method_id(did.method_id())?;
    if did.scheme() != Self::SCHEME {
      return Err(Error::InvalidScheme);
    }

    // Ensure no DID Url segments are present.
    if !did.path().is_empty() || did.fragment().is_some() || did.query().is_some() {
      return Err(Error::InvalidMethodId);
    }

    Ok(())
  }
}

impl AsRef<CoreDID> for CoreDID {
  fn as_ref(&self) -> &CoreDID {
    self
  }
}

impl From<CoreDID> for BaseDIDUrl {
  fn from(did: CoreDID) -> Self {
    did.0
  }
}

impl TryFrom<BaseDIDUrl> for CoreDID {
  type Error = Error;

  fn try_from(base_did_url: BaseDIDUrl) -> Result<Self, Self::Error> {
    Self::check_validity(&base_did_url)?;
    Ok(Self(base_did_url))
  }
}

impl Debug for CoreDID {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{}", self.as_str()))
  }
}

impl Display for CoreDID {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{}", self.as_str()))
  }
}

impl AsRef<str> for CoreDID {
  fn as_ref(&self) -> &str {
    self.0.as_ref()
  }
}

impl FromStr for CoreDID {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    Self::parse(string)
  }
}

impl TryFrom<&str> for CoreDID {
  type Error = Error;

  fn try_from(other: &str) -> Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl TryFrom<String> for CoreDID {
  type Error = Error;

  fn try_from(other: String) -> Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl From<CoreDID> for String {
  fn from(did: CoreDID) -> Self {
    did.0.into_string()
  }
}

impl PartialEq<str> for CoreDID {
  fn eq(&self, other: &str) -> bool {
    self.as_str() == other
  }
}

impl PartialEq<&'_ str> for CoreDID {
  fn eq(&self, other: &&'_ str) -> bool {
    self == *other
  }
}

impl KeyComparable for CoreDID {
  type Key = CoreDID;

  #[inline]
  fn key(&self) -> &Self::Key {
    self
  }
}

/// Checks whether a character satisfies DID method name constraints:
/// { 0-9 | a-z }
#[inline(always)]
pub(crate) const fn is_char_method_name(ch: char) -> bool {
  matches!(ch, '0'..='9' | 'a'..='z')
}

/// Checks whether a character satisfies DID method-id constraints:
/// { 0-9 | a-z | A-Z | . | - | _ | : }
#[inline(always)]
pub(crate) const fn is_char_method_id(ch: char) -> bool {
  matches!(ch, '0'..='9' | 'a'..='z' | 'A'..='Z' | '.' | '-' | '_' | ':')
}

impl<D> DID for D where
  D: Clone
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Hash
    + FromStr
    + TryFrom<CoreDID>
    + Into<String>
    + Into<CoreDID>
    + AsRef<CoreDID>
{
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_core_did_valid() {
    assert_eq!(
      CoreDID::parse("did:example:123456890").unwrap(),
      "did:example:123456890"
    );
    assert_eq!(
      CoreDID::parse("did:iota:main:123456890").unwrap(),
      "did:iota:main:123456890"
    );
  }

  #[test]
  fn test_core_did_invalid() {
    assert!(CoreDID::parse("").is_err());
    assert!(CoreDID::parse("did:").is_err());
    assert!(CoreDID::parse("dad:example:123456890").is_err());
    assert!(CoreDID::parse("did:example:123456#key-1").is_err());
    assert!(CoreDID::parse("did:example:123456/path/to/something/0").is_err());
    assert!(CoreDID::parse("did:example:123456?key-id=cool-key").is_err());
  }

  proptest::proptest! {
    #[test]
    fn test_fuzz_core_did_valid(s in r"did:[a-z0-9]{1,10}:[a-zA-Z0-9\.\-_:]{1,60}") {
      assert_eq!(CoreDID::parse(&s).unwrap().as_str(), &s);
    }

    #[test]
    fn test_fuzz_core_did_no_panic(s in "\\PC*") {
      assert!(CoreDID::parse(s).is_err());
    }

    #[test]
    fn test_fuzz_set_method_name_no_panic(s in "\\PC*") {
      let mut did = CoreDID::parse("did:example:1234567890").unwrap();
      let _ = did.set_method_id(&s);
    }

    #[test]
    fn test_fuzz_set_method_id_no_panic(s in "\\PC*") {
      let mut did = CoreDID::parse("did:example:1234567890").unwrap();
      let _ = did.set_method_name(&s);
    }
  }
}
