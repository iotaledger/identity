// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_did::RelativeDIDUrl;
use identity_did::DID;

/// Specifies a DIDUrl or fragment to query a service or method in a DID Document.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct DIDUrlQuery<'query>(Cow<'query, str>);

impl DIDUrlQuery<'_> {
  /// Returns whether this query matches the given DIDUrl.
  pub(crate) fn matches(&self, did_url: &DIDUrl) -> bool {
    // Ensure the DID matches if included in the query.
    if let Some(did_str) = self.did_str() {
      if did_str != did_url.did().as_str() {
        return false;
      }
    }

    // Compare fragments.
    match self.fragment().zip(did_url.fragment()) {
      Some((a, b)) => a == b,
      None => false,
    }
  }

  /// Extract the DID portion of the query if it exists.
  fn did_str(&self) -> Option<&str> {
    let query: &str = self.0.as_ref();
    if !query.starts_with(CoreDID::SCHEME) {
      return None;
    }

    // Find end of DID section.
    // did:example:123/path?service=agent&relativeRef=/credentials#degree
    let mut end_pos: usize = query.len();
    end_pos = end_pos.min(query.find('?').unwrap_or(end_pos));
    end_pos = end_pos.min(query.find('/').unwrap_or(end_pos));
    end_pos = end_pos.min(query.find('#').unwrap_or(end_pos));
    query.get(0..end_pos)
  }

  /// Extract the query fragment if it exists.
  fn fragment(&self) -> Option<&str> {
    let query: &str = self.0.as_ref();
    let fragment_maybe: Option<&str> = if query.starts_with(CoreDID::SCHEME) {
      // Extract the fragment from a full DID-Url-like string.
      query.rfind('#').and_then(|index| query.get(index + 1..))
    } else if let Some(fragment_delimiter_index) = query.rfind('#') {
      // Extract the fragment from a relative DID-Url.
      query.get(fragment_delimiter_index + 1..)
    } else {
      // Assume the entire string is a fragment.
      Some(query)
    };
    fragment_maybe.filter(|fragment| !fragment.is_empty())
  }
}

impl<'query> From<&'query str> for DIDUrlQuery<'query> {
  fn from(other: &'query str) -> Self {
    Self(Cow::Borrowed(other))
  }
}

impl<'query> From<&'query String> for DIDUrlQuery<'query> {
  fn from(other: &'query String) -> Self {
    Self(Cow::Borrowed(&**other))
  }
}

impl<'query> From<&'query DIDUrl> for DIDUrlQuery<'query> {
  fn from(other: &'query DIDUrl) -> Self {
    Self(Cow::Owned(other.to_string()))
  }
}

impl From<DIDUrl> for DIDUrlQuery<'_> {
  fn from(other: DIDUrl) -> Self {
    Self(Cow::Owned(other.to_string()))
  }
}

impl<'query> From<&'query RelativeDIDUrl> for DIDUrlQuery<'query> {
  fn from(other: &'query RelativeDIDUrl) -> Self {
    Self(Cow::Owned(other.to_string()))
  }
}

#[cfg(test)]
mod tests {
  use identity_did::DIDUrl;
  use std::ops::Not;

  use super::*;

  #[test]
  fn test_did_str() {
    assert!(DIDUrlQuery::from("").did_str().is_none());
    assert!(DIDUrlQuery::from("fragment").did_str().is_none());
    assert!(DIDUrlQuery::from("#fragment").did_str().is_none());
    assert!(DIDUrlQuery::from("?query").did_str().is_none());
    assert!(DIDUrlQuery::from("/path").did_str().is_none());
    assert!(DIDUrlQuery::from("/path?query#fragment").did_str().is_none());
    assert!(DIDUrlQuery::from("method:missingscheme123").did_str().is_none());
    assert!(DIDUrlQuery::from("iota:example").did_str().is_none());
    assert_eq!(
      DIDUrlQuery::from("did:iota:example").did_str(),
      Some("did:iota:example")
    );
    assert_eq!(
      DIDUrlQuery::from("did:iota:example#fragment").did_str(),
      Some("did:iota:example")
    );
    assert_eq!(
      DIDUrlQuery::from("did:iota:example?query").did_str(),
      Some("did:iota:example")
    );
    assert_eq!(
      DIDUrlQuery::from("did:iota:example/path").did_str(),
      Some("did:iota:example")
    );
    assert_eq!(
      DIDUrlQuery::from("did:iota:example/path?query#fragment").did_str(),
      Some("did:iota:example")
    );
    assert_eq!(
      DIDUrlQuery::from("did:iota:example/path?query&relativeRef=/#fragment").did_str(),
      Some("did:iota:example")
    );
  }

  #[test]
  fn test_fragment() {
    assert!(DIDUrlQuery::from("").fragment().is_none());
    assert_eq!(DIDUrlQuery::from("fragment").fragment(), Some("fragment"));
    assert_eq!(DIDUrlQuery::from("#fragment").fragment(), Some("fragment"));
    assert_eq!(DIDUrlQuery::from("/path?query#fragment").fragment(), Some("fragment"));
    assert!(DIDUrlQuery::from("did:iota:example").fragment().is_none());
    assert_eq!(
      DIDUrlQuery::from("did:iota:example#fragment").fragment(),
      Some("fragment")
    );
    assert!(DIDUrlQuery::from("did:iota:example?query").fragment().is_none());
    assert!(DIDUrlQuery::from("did:iota:example/path").fragment().is_none());
    assert_eq!(
      DIDUrlQuery::from("did:iota:example/path?query#fragment").fragment(),
      Some("fragment")
    );
    assert_eq!(
      DIDUrlQuery::from("did:iota:example/path?query&relativeRef=/#fragment").fragment(),
      Some("fragment")
    );
  }

  #[test]
  fn test_matches() {
    let did_base: DIDUrl = DIDUrl::parse("did:iota:example").unwrap();
    let did_path: DIDUrl = DIDUrl::parse("did:iota:example/path").unwrap();
    let did_query: DIDUrl = DIDUrl::parse("did:iota:example?query").unwrap();
    let did_fragment: DIDUrl = DIDUrl::parse("did:iota:example#fragment").unwrap();
    let did_different_fragment: DIDUrl = DIDUrl::parse("did:iota:example#differentfragment").unwrap();
    let did_url: DIDUrl = DIDUrl::parse("did:iota:example/path?query#fragment").unwrap();
    let did_url_complex: DIDUrl = DIDUrl::parse("did:iota:example/path?query&relativeRef=/#fragment").unwrap();

    // INVALID: empty query should not match anything.
    {
      let query_empty = DIDUrlQuery::from("");
      assert!(query_empty.matches(&did_base).not());
      assert!(query_empty.matches(&did_path).not());
      assert!(query_empty.matches(&did_query).not());
      assert!(query_empty.matches(&did_fragment).not());
      assert!(query_empty.matches(&did_different_fragment).not());
      assert!(query_empty.matches(&did_url).not());
      assert!(query_empty.matches(&did_url_complex).not());
    }

    // VALID: query with only a fragment should match the same fragment.
    {
      let query_fragment_only = DIDUrlQuery::from("fragment");
      assert!(query_fragment_only.matches(&did_base).not());
      assert!(query_fragment_only.matches(&did_path).not());
      assert!(query_fragment_only.matches(&did_query).not());
      assert!(query_fragment_only.matches(&did_fragment));
      assert!(query_fragment_only.matches(&did_different_fragment).not());
      assert!(query_fragment_only.matches(&did_url));
      assert!(query_fragment_only.matches(&did_url_complex));
    }

    // VALID: query with differentfragment should only match the same fragment.
    {
      let query_different_fragment = DIDUrlQuery::from("differentfragment");
      assert!(query_different_fragment.matches(&did_base).not());
      assert!(query_different_fragment.matches(&did_path).not());
      assert!(query_different_fragment.matches(&did_query).not());
      assert!(query_different_fragment.matches(&did_fragment).not());
      assert!(query_different_fragment.matches(&did_different_fragment));
      assert!(query_different_fragment.matches(&did_url).not());
      assert!(query_different_fragment.matches(&did_url_complex).not());
    }

    // VALID: query with a #fragment should match the same fragment.
    {
      let query_fragment_delimiter = DIDUrlQuery::from("#fragment");
      assert!(query_fragment_delimiter.matches(&did_base).not());
      assert!(query_fragment_delimiter.matches(&did_path).not());
      assert!(query_fragment_delimiter.matches(&did_query).not());
      assert!(query_fragment_delimiter.matches(&did_fragment));
      assert!(query_fragment_delimiter.matches(&did_different_fragment).not());
      assert!(query_fragment_delimiter.matches(&did_url));
      assert!(query_fragment_delimiter.matches(&did_url_complex));
    }

    // VALID: query with a relative DID Url should match the same fragment.
    {
      let query_relative_did_url = DIDUrlQuery::from("/path?query#fragment");
      assert!(query_relative_did_url.matches(&did_base).not());
      assert!(query_relative_did_url.matches(&did_path).not());
      assert!(query_relative_did_url.matches(&did_query).not());
      assert!(query_relative_did_url.matches(&did_fragment));
      assert!(query_relative_did_url.matches(&did_different_fragment).not());
      assert!(query_relative_did_url.matches(&did_url));
      assert!(query_relative_did_url.matches(&did_url_complex));
    }

    // INVALID: query with DID and no fragment should not match anything.
    {
      let query_did = DIDUrlQuery::from("did:iota:example");
      assert!(query_did.matches(&did_base).not());
      assert!(query_did.matches(&did_path).not());
      assert!(query_did.matches(&did_query).not());
      assert!(query_did.matches(&did_fragment).not());
      assert!(query_did.matches(&did_different_fragment).not());
      assert!(query_did.matches(&did_url).not());
      assert!(query_did.matches(&did_url_complex).not());
    }

    // VALID: query with a DID fragment should match the same fragment.
    {
      let query_did_fragment = DIDUrlQuery::from("did:iota:example#fragment");
      assert!(query_did_fragment.matches(&did_base).not());
      assert!(query_did_fragment.matches(&did_path).not());
      assert!(query_did_fragment.matches(&did_query).not());
      assert!(query_did_fragment.matches(&did_fragment));
      assert!(query_did_fragment.matches(&did_different_fragment).not());
      assert!(query_did_fragment.matches(&did_url));
      assert!(query_did_fragment.matches(&did_url_complex));
    }

    // VALID: query with a DID Url with a fragment should match the same fragment.
    {
      let query_did_fragment = DIDUrlQuery::from("did:iota:example/path?query#fragment");
      assert!(query_did_fragment.matches(&did_base).not());
      assert!(query_did_fragment.matches(&did_path).not());
      assert!(query_did_fragment.matches(&did_query).not());
      assert!(query_did_fragment.matches(&did_fragment));
      assert!(query_did_fragment.matches(&did_different_fragment).not());
      assert!(query_did_fragment.matches(&did_url));
      assert!(query_did_fragment.matches(&did_url_complex));
    }

    // VALID: query with a complex DID Url with a fragment should match the same fragment.
    {
      let query_did_fragment = DIDUrlQuery::from("did:iota:example/path?query&relativeRef=/#fragment");
      assert!(query_did_fragment.matches(&did_base).not());
      assert!(query_did_fragment.matches(&did_path).not());
      assert!(query_did_fragment.matches(&did_query).not());
      assert!(query_did_fragment.matches(&did_fragment));
      assert!(query_did_fragment.matches(&did_different_fragment).not());
      assert!(query_did_fragment.matches(&did_url));
      assert!(query_did_fragment.matches(&did_url_complex));
    }
  }
}
