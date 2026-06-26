// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::str::FromStr;
use std::cmp::Ordering;
use std::hash::Hash;
use std::hash::Hasher;

use did_url_parser::DID as BaseDIDUrl;

use identity_core::common::KeyComparable;
use identity_core::common::Url;

use crate::did::is_char_method_id;
use crate::did::CoreDID;
use crate::did::DID;
use crate::Error;

/// A [DID Url]: a [CoreDID] with [RelativeDIDUrl] components.
///
/// E.g. "did:iota:H3C2AVvLMv6gmMNam3uVAjZar3cJCwDwnZn6z3wXmqPV/path?query1=a&query2=b#fragment"
///
/// [DID Url]: https://www.w3.org/TR/did-core/#did-url-syntax
#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct DIDUrl {
  did: CoreDID,
  url: RelativeDIDUrl,
}

/// A [relative DID Url] with the [path], [query], and [fragment] components defined according
/// to [URI syntax](https://datatracker.ietf.org/doc/html/rfc5234).
///
/// E.g.
/// - `"/path?query#fragment"`
/// - `"/path"`
/// - `"?query"`
/// - `"#fragment"`
///
/// [relative DID Url]: https://www.w3.org/TR/did-core/#relative-did-urls
/// [path]: https://www.w3.org/TR/did-core/#path
/// [query]: https://www.w3.org/TR/did-core/#query
/// [fragment]: https://www.w3.org/TR/did-core/#fragment
#[derive(Clone, Default)]
pub struct RelativeDIDUrl {
  // Path including the leading '/'
  path: Option<String>,
  // Query including the leading '?'
  query: Option<String>,
  // Fragment including the leading '#'
  fragment: Option<String>,
}

impl RelativeDIDUrl {
  /// Create an empty [`RelativeDIDUrl`].
  pub fn new() -> Self {
    Self {
      path: None,
      query: None,
      fragment: None,
    }
  }

  /// Returns whether all URL segments are empty.
  pub fn is_empty(&self) -> bool {
    self.path.as_deref().unwrap_or_default().is_empty()
      && self.query.as_deref().unwrap_or_default().is_empty()
      && self.fragment.as_deref().unwrap_or_default().is_empty()
  }

  /// Return the [path](https://www.w3.org/TR/did-core/#path) component,
  /// including the leading '/'.
  ///
  /// E.g. `"/path/sub-path/resource"`
  pub fn path(&self) -> Option<&str> {
    self.path.as_deref()
  }

  /// Attempt to set the [path](https://www.w3.org/TR/did-core/#path) component.
  /// The path must start with a '/'.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::RelativeDIDUrl;
  /// # let mut url = RelativeDIDUrl::new();
  /// url.set_path(Some("/path/sub-path/resource")).unwrap();
  /// assert_eq!(url.path().unwrap(), "/path/sub-path/resource");
  /// assert_eq!(url.to_string(), "/path/sub-path/resource");
  /// ```
  pub fn set_path(&mut self, value: Option<&str>) -> Result<(), Error> {
    self.path = value
      .filter(|s| !s.is_empty())
      .map(|s| {
        if s.starts_with('/') && is_valid_url_segment(s, is_char_path) {
          Ok(s.to_owned())
        } else {
          Err(Error::InvalidPath)
        }
      })
      .transpose()?;
    Ok(())
  }

  /// Return the [path](https://www.w3.org/TR/did-core/#query) component,
  /// excluding the leading '?' delimiter.
  ///
  /// E.g. `"?query1=a&query2=b" -> "query1=a&query2=b"`
  pub fn query(&self) -> Option<&str> {
    self.query.as_deref().and_then(|query| query.strip_prefix('?'))
  }

  /// Attempt to set the [query](https://www.w3.org/TR/did-core/#query) component.
  /// A leading '?' is ignored.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::RelativeDIDUrl;
  /// # let mut url = RelativeDIDUrl::new();
  /// // Set the query with a leading '?'
  /// url.set_query(Some("?query1=a")).unwrap();
  /// assert_eq!(url.query().unwrap(), "query1=a");
  /// assert_eq!(url.to_string(), "?query1=a");
  ///
  /// // Set the query without a leading '?'
  /// url.set_query(Some("query1=a&query2=b")).unwrap();
  /// assert_eq!(url.query().unwrap(), "query1=a&query2=b");
  /// assert_eq!(url.to_string(), "?query1=a&query2=b");
  /// ```
  pub fn set_query(&mut self, value: Option<&str>) -> Result<(), Error> {
    self.query = value
      .filter(|s| !s.is_empty())
      .map(|mut s| {
        // Ignore leading '?' during validation.
        s = s.strip_prefix('?').unwrap_or(s);
        if s.is_empty() || !is_valid_url_segment(s, is_char_query) {
          return Err(Error::InvalidQuery);
        }
        Ok(format!("?{s}"))
      })
      .transpose()?;
    Ok(())
  }

  /// Return an iterator of `(name, value)` pairs in the query string.
  ///
  /// E.g. `"query1=a&query2=b" -> [("query1", "a"), ("query2", "b")]`
  ///
  /// See [form_urlencoded::parse].
  pub fn query_pairs(&self) -> form_urlencoded::Parse<'_> {
    form_urlencoded::parse(self.query().unwrap_or_default().as_bytes())
  }

  /// Return the [fragment](https://www.w3.org/TR/did-core/#fragment) component,
  /// excluding the leading '#' delimiter.
  ///
  /// E.g. `"#fragment" -> "fragment"`
  pub fn fragment(&self) -> Option<&str> {
    self.fragment.as_deref().and_then(|fragment| fragment.strip_prefix('#'))
  }

  /// Attempt to set the [fragment](https://www.w3.org/TR/did-core/#fragment) component.
  /// A leading '#' is ignored.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::RelativeDIDUrl;
  /// # let mut url = RelativeDIDUrl::new();
  /// // Set the fragment with a leading '#'
  /// url.set_fragment(Some("#fragment1")).unwrap();
  /// assert_eq!(url.fragment().unwrap(), "fragment1");
  /// assert_eq!(url.to_string(), "#fragment1");
  ///
  /// // Set the fragment without a leading '#'
  /// url.set_fragment(Some("fragment2")).unwrap();
  /// assert_eq!(url.fragment().unwrap(), "fragment2");
  /// assert_eq!(url.to_string(), "#fragment2");
  /// ```
  pub fn set_fragment(&mut self, value: Option<&str>) -> Result<(), Error> {
    self.fragment = value
      .filter(|s| !s.is_empty())
      .map(|mut s| {
        // Ignore leading '#' during validation.
        s = s.strip_prefix('#').unwrap_or(s);
        if s.is_empty() || !is_valid_url_segment(s, is_char_fragment) {
          return Err(Error::InvalidFragment);
        }
        Ok(format!("#{s}"))
      })
      .transpose()?;
    Ok(())
  }
}

impl Display for RelativeDIDUrl {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!(
      "{}{}{}",
      self.path.as_deref().unwrap_or_default(),
      self.query.as_deref().unwrap_or_default(),
      self.fragment.as_deref().unwrap_or_default()
    ))
  }
}

impl Debug for RelativeDIDUrl {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{self}"))
  }
}

impl PartialEq for RelativeDIDUrl {
  fn eq(&self, other: &Self) -> bool {
    self.path.as_deref().unwrap_or_default() == other.path.as_deref().unwrap_or_default()
      && self.query.as_deref().unwrap_or_default() == other.query.as_deref().unwrap_or_default()
      && self.fragment.as_deref().unwrap_or_default() == other.fragment.as_deref().unwrap_or_default()
  }
}

impl Eq for RelativeDIDUrl {}

impl PartialOrd for RelativeDIDUrl {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for RelativeDIDUrl {
  fn cmp(&self, other: &Self) -> Ordering {
    // Compare path, query, then fragment in that order
    let path_cmp = self
      .path
      .as_deref()
      .unwrap_or_default()
      .cmp(other.path.as_deref().unwrap_or_default());

    if path_cmp == Ordering::Equal {
      let query_cmp = self
        .query
        .as_deref()
        .unwrap_or_default()
        .cmp(other.query.as_deref().unwrap_or_default());

      if query_cmp == Ordering::Equal {
        return self
          .fragment
          .as_deref()
          .unwrap_or_default()
          .cmp(other.fragment.as_deref().unwrap_or_default());
      }

      return query_cmp;
    }

    path_cmp
  }
}

impl Hash for RelativeDIDUrl {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_string().hash(state)
  }
}

impl DIDUrl {
  /// Construct a new [`DIDUrl`] with optional [`RelativeDIDUrl`].
  pub fn new(did: CoreDID, url: Option<RelativeDIDUrl>) -> Self {
    Self {
      did,
      url: url.unwrap_or_default(),
    }
  }

  /// Parse a [`DIDUrl`] from a string.
  pub fn parse(input: impl AsRef<str>) -> Result<Self, Error> {
    let did_url: BaseDIDUrl = BaseDIDUrl::parse(input)?;
    Self::from_base_did_url(did_url)
  }

  fn from_base_did_url(did_url: BaseDIDUrl) -> Result<Self, Error> {
    // Extract relative DID URL
    let url: RelativeDIDUrl = {
      let mut url: RelativeDIDUrl = RelativeDIDUrl::new();
      url.set_path(Some(did_url.path()))?;
      url.set_query(did_url.query())?;
      url.set_fragment(did_url.fragment())?;
      url
    };

    // Extract base DID
    let did: CoreDID = {
      let mut base_did: BaseDIDUrl = did_url;
      base_did.set_path("");
      base_did.set_query(None);
      base_did.set_fragment(None);
      CoreDID::try_from(base_did).map_err(|_| Error::Other("invalid DID"))?
    };

    Ok(Self { did, url })
  }

  /// Returns the [`did`][CoreDID].
  pub fn did(&self) -> &CoreDID {
    &self.did
  }

  /// Returns the [`RelativeDIDUrl`].
  pub fn url(&self) -> &RelativeDIDUrl {
    &self.url
  }

  /// Sets the [`RelativeDIDUrl`].
  pub fn set_url(&mut self, url: RelativeDIDUrl) {
    self.url = url
  }

  /// Returns the [`DIDUrl`] `fragment` component.
  ///
  /// See [`RelativeDIDUrl::fragment`].
  pub fn fragment(&self) -> Option<&str> {
    self.url.fragment()
  }

  /// Sets the `fragment` component of the [`DIDUrl`].
  ///
  /// See [`RelativeDIDUrl::set_fragment`].
  pub fn set_fragment(&mut self, value: Option<&str>) -> Result<(), Error> {
    self.url.set_fragment(value)
  }

  /// Returns the [`DIDUrl`] `path` component.
  ///
  /// See [`RelativeDIDUrl::path`].
  pub fn path(&self) -> Option<&str> {
    self.url.path()
  }

  /// Sets the `path` component of the [`DIDUrl`].
  ///
  /// See [`RelativeDIDUrl::set_path`].
  pub fn set_path(&mut self, value: Option<&str>) -> Result<(), Error> {
    self.url.set_path(value)
  }

  /// Returns the [`DIDUrl`] `query` component.
  ///
  /// See [`RelativeDIDUrl::query`].
  pub fn query(&self) -> Option<&str> {
    self.url.query()
  }

  /// Sets the `query` component of the [`DIDUrl`].
  ///
  /// See [`RelativeDIDUrl::set_query`].
  pub fn set_query(&mut self, value: Option<&str>) -> Result<(), Error> {
    self.url.set_query(value)
  }

  /// Parses the [`DIDUrl`] query and returns an iterator of (key, value) pairs.
  ///
  /// See [`RelativeDIDUrl::query_pairs`].
  pub fn query_pairs(&self) -> form_urlencoded::Parse<'_> {
    self.url.query_pairs()
  }

  /// Append a string representing a `path`, `query`, and/or `fragment`, returning a new [`DIDUrl`].
  ///
  /// Must begin with a valid delimiter character: '/', '?', '#'. Overwrites the existing URL
  /// segment and any following segments in order of path, query, then fragment.
  ///
  /// I.e.
  /// - joining a path will overwrite the path and clear the query and fragment.
  /// - joining a query will overwrite the query and clear the fragment.
  /// - joining a fragment will only overwrite the fragment.
  pub fn join(&self, segment: impl AsRef<str>) -> Result<Self, Error> {
    let segment: &str = segment.as_ref();

    // Accept only a relative path, query, or fragment to reject altering the method id segment.
    if !segment.starts_with('/') && !segment.starts_with('?') && !segment.starts_with('#') {
      return Err(Error::InvalidPath);
    }

    // Parse DID Url.
    let base_did_url: BaseDIDUrl = BaseDIDUrl::parse(self.to_string())?.join(segment)?;
    Self::from_base_did_url(base_did_url)
  }

  /// Maps a [`DIDUrl`] by applying a function to the [`CoreDID`] part of the [`DIDUrl`], the [`RelativeDIDUrl`]
  /// components are left untouched.
  pub fn map<F>(self, f: F) -> DIDUrl
  where
    F: FnOnce(CoreDID) -> CoreDID,
  {
    DIDUrl {
      did: f(self.did),
      url: self.url,
    }
  }

  /// Fallible version of [`DIDUrl::map`].
  pub fn try_map<F, E>(self, f: F) -> Result<DIDUrl, E>
  where
    F: FnOnce(CoreDID) -> Result<CoreDID, E>,
  {
    Ok(DIDUrl {
      did: f(self.did)?,
      url: self.url,
    })
  }
}

impl<D> From<D> for DIDUrl
where
  D: Into<CoreDID>,
{
  fn from(did: D) -> Self {
    Self::new(did.into(), None)
  }
}

impl FromStr for DIDUrl {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    Self::parse(string)
  }
}

impl TryFrom<String> for DIDUrl {
  type Error = Error;

  fn try_from(other: String) -> Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl From<DIDUrl> for String {
  fn from(did_url: DIDUrl) -> Self {
    did_url.to_string()
  }
}

impl From<DIDUrl> for Url {
  fn from(did_url: DIDUrl) -> Self {
    Url::parse(did_url.to_string()).expect("a DIDUrl should be a valid Url")
  }
}

impl AsRef<CoreDID> for DIDUrl {
  fn as_ref(&self) -> &CoreDID {
    &self.did
  }
}

impl AsRef<DIDUrl> for DIDUrl {
  fn as_ref(&self) -> &DIDUrl {
    self
  }
}

impl PartialEq for DIDUrl {
  fn eq(&self, other: &Self) -> bool {
    self.did().eq(other.did()) && self.url() == other.url()
  }
}

impl Eq for DIDUrl {}

impl PartialOrd for DIDUrl {
  #[inline]
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for DIDUrl {
  #[inline]
  fn cmp(&self, other: &Self) -> Ordering {
    match self.did().cmp(other.did()) {
      Ordering::Equal => self.url().cmp(other.url()),
      ord => ord,
    }
  }
}

impl Hash for DIDUrl {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_string().hash(state)
  }
}

impl Debug for DIDUrl {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{self}"))
  }
}

impl Display for DIDUrl {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{}{}", self.did.as_str(), self.url))
  }
}

impl KeyComparable for DIDUrl {
  type Key = Self;

  fn key(&self) -> &Self::Key {
    self
  }
}

/// Checks whether a character satisfies DID Url path constraints.
#[inline(always)]
#[rustfmt::skip]
pub(crate) const fn is_char_path(ch: char) -> bool {
  is_char_method_id(ch) || matches!(ch, '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | '@' | '/')
}

/// Checks whether a character satisfies DID Url query constraints.
#[inline(always)]
pub(crate) const fn is_char_query(ch: char) -> bool {
  is_char_path(ch) || ch == '?'
}

/// Checks whether a character satisfies DID Url fragment constraints.
#[inline(always)]
pub(crate) const fn is_char_fragment(ch: char) -> bool {
  is_char_path(ch) || ch == '?'
}

pub(crate) fn is_valid_percent_encoded_char(s: &str) -> bool {
  let mut chars = s.chars();
  let Some('%') = chars.next() else { return false };
  s.len() >= 3 && chars.take(2).all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn is_valid_url_segment<F>(segment: &str, char_predicate: F) -> bool
where
  F: Fn(char) -> bool,
{
  let mut chars = segment.char_indices();
  while let Some((i, c)) = chars.next() {
    if c == '%' {
      if !is_valid_percent_encoded_char(&segment[i..]) {
        return false;
      }
      // skip the two HEX digits
      chars.next();
      chars.next();
    } else if !char_predicate(c) {
      return false;
    }
  }

  true
}

#[cfg(test)]
mod tests {
  use super::*;

  #[rustfmt::skip]
  #[test]
  fn test_did_url_parse_valid() {
    let did_url = DIDUrl::parse("did:example:1234567890").unwrap();
    assert_eq!(did_url.to_string(), "did:example:1234567890");
    assert!(did_url.url().is_empty());
    assert!(did_url.path().is_none());
    assert!(did_url.query().is_none());
    assert!(did_url.fragment().is_none());

    assert_eq!(DIDUrl::parse("did:example:1234567890/path").unwrap().to_string(), "did:example:1234567890/path");
    assert_eq!(DIDUrl::parse("did:example:1234567890?query").unwrap().to_string(), "did:example:1234567890?query");
    assert_eq!(DIDUrl::parse("did:example:1234567890#fragment").unwrap().to_string(), "did:example:1234567890#fragment");

    assert_eq!(DIDUrl::parse("did:example:1234567890/path?query").unwrap().to_string(), "did:example:1234567890/path?query");
    assert_eq!(DIDUrl::parse("did:example:1234567890/path#fragment").unwrap().to_string(), "did:example:1234567890/path#fragment");
    assert_eq!(DIDUrl::parse("did:example:1234567890?query#fragment").unwrap().to_string(), "did:example:1234567890?query#fragment");

    let did_url = DIDUrl::parse("did:example:1234567890/path?query#fragment").unwrap();
    assert!(!did_url.url().is_empty());
    assert_eq!(did_url.to_string(), "did:example:1234567890/path?query#fragment");
    assert_eq!(did_url.path().unwrap(), "/path");
    assert_eq!(did_url.query().unwrap(), "query");
    assert_eq!(did_url.fragment().unwrap(), "fragment");
  }

  #[rustfmt::skip]
  #[test]
  fn test_join_valid() {
    let did_url = DIDUrl::parse("did:example:1234567890").unwrap();
    assert_eq!(did_url.join("/path").unwrap().to_string(), "did:example:1234567890/path");
    assert_eq!(did_url.join("?query").unwrap().to_string(), "did:example:1234567890?query");
    assert_eq!(did_url.join("#fragment").unwrap().to_string(), "did:example:1234567890#fragment");

    assert_eq!(did_url.join("/path?query").unwrap().to_string(), "did:example:1234567890/path?query");
    assert_eq!(did_url.join("/path#fragment").unwrap().to_string(), "did:example:1234567890/path#fragment");
    assert_eq!(did_url.join("?query#fragment").unwrap().to_string(), "did:example:1234567890?query#fragment");

    let did_url = did_url.join("/path?query#fragment").unwrap();
    assert_eq!(did_url.to_string(), "did:example:1234567890/path?query#fragment");
    assert_eq!(did_url.path().unwrap(), "/path");
    assert_eq!(did_url.query().unwrap(), "query");
    assert_eq!(did_url.fragment().unwrap(), "fragment");
  }

  #[test]
  fn test_did_url_invalid() {
    assert!(DIDUrl::parse("did:example:1234567890/invalid{path}").is_err());
    assert!(DIDUrl::parse("did:example:1234567890?invalid{query}").is_err());
    assert!(DIDUrl::parse("did:example:1234567890#invalid{fragment}").is_err());

    let did_url = DIDUrl::parse("did:example:1234567890").unwrap();
    assert!(did_url.join("noleadingdelimiter").is_err());
    assert!(did_url.join("/invalid{path}").is_err());
    assert!(did_url.join("?invalid{query}").is_err());
    assert!(did_url.join("#invalid{fragment}").is_err());
  }

  #[test]
  fn test_did_url_basic_comparisons() {
    let did_url1 = DIDUrl::parse("did:example:1234567890").unwrap();
    let did_url1_copy = DIDUrl::parse("did:example:1234567890").unwrap();
    assert_eq!(did_url1, did_url1_copy);

    let did_url2 = DIDUrl::parse("did:example:0987654321").unwrap();
    assert_ne!(did_url1, did_url2);
    assert!(did_url1 > did_url2);

    let did_url3 = DIDUrl::parse("did:fxample:1234567890").unwrap();
    assert_ne!(did_url1, did_url3);
    assert!(did_url1 < did_url3);

    let did_url4 = DIDUrl::parse("did:example:1234567890/path").unwrap();
    assert_ne!(did_url1, did_url4);
    assert_ne!(did_url1.url(), did_url4.url());
    assert_eq!(did_url1.did(), did_url4.did());
    assert!(did_url1 < did_url4);

    let did_url5 = DIDUrl::parse("did:example:1234567890/zero").unwrap();
    assert_ne!(did_url4, did_url5);
    assert_ne!(did_url4.url(), did_url5.url());
    assert_eq!(did_url4.did(), did_url5.did());
    assert!(did_url4 < did_url5);
  }

  #[test]
  fn test_path_valid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Simple path.
    assert!(relative_url.set_path(Some("/path")).is_ok());
    assert_eq!(relative_url.path().unwrap(), "/path");
    assert!(relative_url.set_path(Some("/path/sub-path/resource")).is_ok());
    assert_eq!(relative_url.path().unwrap(), "/path/sub-path/resource");

    // Empty path.
    assert!(relative_url.set_path(Some("")).is_ok());
    assert!(relative_url.path().is_none());
    assert!(relative_url.set_path(None).is_ok());
    assert!(relative_url.path().is_none());

    // Percent encoded path.
    assert!(relative_url.set_path(Some("/p%AAth")).is_ok());
    assert_eq!(relative_url.path().unwrap(), "/p%AAth");
  }

  #[rustfmt::skip]
  #[test]
  fn test_path_invalid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Invalid symbols.
    assert!(matches!(relative_url.set_path(Some("/white space")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/white\tspace")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/white\nspace")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path{invalid_brackets}")), Err(Error::InvalidPath)));

    // Missing leading '/'.
    assert!(matches!(relative_url.set_path(Some("path")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("p/")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("p/ath")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("path/")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("path/sub-path/")), Err(Error::InvalidPath)));

    // Reject query delimiter '?'.
    assert!(matches!(relative_url.set_path(Some("?query")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("some?query")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path?")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path?query")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path/query?")), Err(Error::InvalidPath)));

    // Reject fragment delimiter '#'.
    assert!(matches!(relative_url.set_path(Some("#fragment")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("some#fragment")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path#")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path#fragment")), Err(Error::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path/fragment#")), Err(Error::InvalidPath)));
  }

  #[test]
  fn test_query_valid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Empty query.
    assert!(relative_url.set_query(Some("")).is_ok());
    assert!(relative_url.query().is_none());

    // With leading '?'.
    assert!(relative_url.set_query(Some("?query")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "query");
    assert!(relative_url.set_query(Some("?name=value")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value");
    assert!(relative_url.set_query(Some("?name=value&name2=value2")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value&name2=value2");
    assert!(relative_url.set_query(Some("?name=value&name2=value2&3=true")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value&name2=value2&3=true");

    // Without leading '?'.
    assert!(relative_url.set_query(Some("query")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "query");
    assert!(relative_url.set_query(Some("name=value&name2=value2&3=true")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value&name2=value2&3=true");

    // With percent encoded char.
    assert!(relative_url.set_query(Some("qu%EEry")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "qu%EEry");
  }

  #[rustfmt::skip]
  #[test]
  fn test_query_invalid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Delimiter-only.
    assert!(matches!(relative_url.set_query(Some("?")), Err(Error::InvalidQuery)));

    // Invalid symbols.
    assert!(matches!(relative_url.set_query(Some("?white space")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?white\tspace")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?white\nspace")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query{invalid_brackets}")), Err(Error::InvalidQuery)));

    // Reject fragment delimiter '#'.
    assert!(matches!(relative_url.set_query(Some("#fragment")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("some#fragment")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query#fragment")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=a#fragment")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=#fragment")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=frag#ment")), Err(Error::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=fragment#")), Err(Error::InvalidQuery)));
  }

  #[rustfmt::skip]
  #[test]
  fn test_fragment_valid() {
    let mut relative_url = RelativeDIDUrl::new();

    // With leading '#'.
    assert!(relative_url.set_fragment(Some("#fragment")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "fragment");
    assert!(relative_url.set_fragment(Some("#longer_fragment?and/other-delimiters:valid")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "longer_fragment?and/other-delimiters:valid");

    // Without leading '#'.
    assert!(relative_url.set_fragment(Some("fragment")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "fragment");
    assert!(relative_url.set_fragment(Some("longer_fragment?and/other-delimiters:valid")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "longer_fragment?and/other-delimiters:valid");

    // Empty fragment.
    assert!(relative_url.set_fragment(Some("")).is_ok());
    assert!(relative_url.fragment().is_none());
    assert!(relative_url.set_fragment(None).is_ok());
    assert!(relative_url.fragment().is_none());

    // Percent encoded fragment.
    assert!(relative_url.set_fragment(Some("fr%AAgm%EEnt")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "fr%AAgm%EEnt");
  }

  #[rustfmt::skip]
  #[test]
  fn test_fragment_invalid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Delimiter only.
    assert!(matches!(relative_url.set_fragment(Some("#")), Err(Error::InvalidFragment)));

    // Invalid symbols.
    assert!(matches!(relative_url.set_fragment(Some("#white space")), Err(Error::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#white\tspace")), Err(Error::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#white\nspace")), Err(Error::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#fragment{invalid_brackets}")), Err(Error::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#fragment\"other\"")), Err(Error::InvalidFragment)));
  }

  proptest::proptest! {
    #[test]
    fn test_fuzz_join_no_panic(s in "\\PC*") {
      let did_url = DIDUrl::parse("did:example:1234567890").unwrap();
      let _ = did_url.join(s);
    }

    #[test]
    fn test_fuzz_path_no_panic(s in "\\PC*") {
      let mut url = RelativeDIDUrl::new();
      let _ = url.set_path(Some(&s));
    }

    #[test]
    fn test_fuzz_query_no_panic(s in "\\PC*") {
      let mut url = RelativeDIDUrl::new();
      let _ = url.set_query(Some(&s));
    }

    #[test]
    fn test_fuzz_fragment_no_panic(s in "\\PC*") {
      let mut url = RelativeDIDUrl::new();
      let _ = url.set_fragment(Some(&s));
    }
  }
}
