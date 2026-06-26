// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::fmt::Display;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

use super::Url;

/// A type that represents either an arbitrary string or a URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrUrl {
  /// A well-formed URL.
  Url(Url),
  /// An arbitrary UTF-8 string.
  String(String),
}

impl StringOrUrl {
  /// Parses a [`StringOrUrl`] from a string.
  pub fn parse(s: &str) -> Result<Self, Infallible> {
    s.parse()
  }
  /// Returns a [`Url`] reference if `self` is [`StringOrUrl::Url`].
  pub fn as_url(&self) -> Option<&Url> {
    match self {
      Self::Url(url) => Some(url),
      _ => None,
    }
  }

  /// Returns a [`str`] reference if `self` is [`StringOrUrl::String`].
  pub fn as_string(&self) -> Option<&str> {
    match self {
      Self::String(s) => Some(s),
      _ => None,
    }
  }

  /// Returns whether `self` is a [`StringOrUrl::Url`].
  pub fn is_url(&self) -> bool {
    matches!(self, Self::Url(_))
  }

  /// Returns whether `self` is a [`StringOrUrl::String`].
  pub fn is_string(&self) -> bool {
    matches!(self, Self::String(_))
  }
}

impl Default for StringOrUrl {
  fn default() -> Self {
    StringOrUrl::String(String::default())
  }
}

impl Display for StringOrUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Url(url) => write!(f, "{url}"),
      Self::String(s) => write!(f, "{s}"),
    }
  }
}

impl FromStr for StringOrUrl {
  // Cannot fail.
  type Err = Infallible;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(
      s.parse::<Url>()
        .map(Self::Url)
        .unwrap_or_else(|_| Self::String(s.to_string())),
    )
  }
}

impl AsRef<str> for StringOrUrl {
  fn as_ref(&self) -> &str {
    match self {
      Self::String(s) => s,
      Self::Url(url) => url.as_str(),
    }
  }
}

impl From<Url> for StringOrUrl {
  fn from(value: Url) -> Self {
    Self::Url(value)
  }
}

impl From<String> for StringOrUrl {
  fn from(value: String) -> Self {
    Self::String(value)
  }
}

impl From<StringOrUrl> for String {
  fn from(value: StringOrUrl) -> Self {
    match value {
      StringOrUrl::String(s) => s,
      StringOrUrl::Url(url) => url.into_string(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[derive(Debug, Serialize, Deserialize)]
  struct TestData {
    string_or_url: StringOrUrl,
  }

  impl Default for TestData {
    fn default() -> Self {
      Self {
        string_or_url: StringOrUrl::Url(TEST_URL.parse().unwrap()),
      }
    }
  }

  const TEST_URL: &str = "file:///tmp/file.txt";

  #[test]
  fn deserialization_works() {
    let test_data: TestData = serde_json::from_value(serde_json::json!({ "string_or_url": TEST_URL })).unwrap();
    let target_url: Url = TEST_URL.parse().unwrap();
    assert_eq!(test_data.string_or_url.as_url(), Some(&target_url));
  }

  #[test]
  fn serialization_works() {
    assert_eq!(
      serde_json::to_value(TestData::default()).unwrap(),
      serde_json::json!({ "string_or_url": TEST_URL })
    )
  }

  #[test]
  fn parsing_works() {
    assert!(TEST_URL.parse::<StringOrUrl>().unwrap().is_url());
    assert!("I'm a random string :)".parse::<StringOrUrl>().unwrap().is_string());
  }
}
