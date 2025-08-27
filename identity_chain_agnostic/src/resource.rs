// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::fmt::Write as _;

use crate::chain_id::chain_id_parser;
use crate::parser::*;
use crate::ChainId;

#[derive(Debug)]
pub struct OnChainResourceLocator {
  pub chain_id: ChainId,
  locator: RelativeUrl,
}

impl OnChainResourceLocator {
  /// Parses an [OnChainResourceLocator] from the given string.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::resource::InvalidOnChainResourceLocator;
  /// # use identity_chain_agnostic::resource::OnChainResourceLocator;
  /// # fn main() -> Result<(), InvalidOnChainResourceLocator> {
  /// let resource = OnChainResourceLocator::parse("chain:id/a/very/long/path?key=value#frag")?;
  /// assert_eq!(
  ///   resource.path_segments().collect::<Vec<_>>(),
  ///   vec!["a", "very", "long", "path"],
  /// );
  /// assert_eq!(
  ///   resource.query_pairs().collect::<Vec<_>>(),
  ///   vec![("key", "value")]
  /// );
  /// assert_eq!(resource.fragment(), Some("frag"));
  /// #   Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, InvalidOnChainResourceLocator> {
    all_consuming(resource_parser)
      .process(input)
      .map_err(|e| InvalidOnChainResourceLocator {
        input: input.to_owned(),
        source: e.into_owned(),
      })
      .map(|(_, out)| out)
  }

  pub fn path(&self) -> &str {
    self.locator.path()
  }

  pub fn path_segments(&self) -> impl Iterator<Item = &str> {
    self.locator.path_segments()
  }

  pub fn query(&self) -> Option<&str> {
    self.locator.query()
  }

  pub fn query_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
    self.locator.query_pairs()
  }

  pub fn fragment(&self) -> Option<&str> {
    self.locator.fragment()
  }
}

#[derive(Debug)]
pub struct InvalidOnChainResourceLocator {
  pub input: String,
  source: ParseError<'static>,
}

impl Display for InvalidOnChainResourceLocator {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "invalid resource resource \"{}\"", self.input)
  }
}

impl std::error::Error for InvalidOnChainResourceLocator {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativeUrl {
  data: Box<str>,
  query_start: Option<u32>,
  fragment_start: Option<u32>,
}

impl Display for RelativeUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.data)
  }
}

impl RelativeUrl {
  /// Returns the string representation of this relative URL.
  pub const fn as_str(&self) -> &str {
    &self.data
  }

  /// Parses a [RelativeUrl] from the given string.
  pub fn parse(input: &str) -> Result<RelativeUrl, InvalidRelativeUrl> {
    all_consuming(relative_url_parser)
      .process(input)
      .map(|(_, out)| out)
      .map_err(|e| InvalidRelativeUrl {
        url: input.to_owned(),
        source: e.into_owned(),
      })
  }

  /// Returns the path component.
  pub fn path(&self) -> &str {
    let end = self
      .query_start
      .or(self.fragment_start)
      .unwrap_or(self.data.len() as u32) as usize;
    let path = &self.data[..end];
    // Make sure default "/" path is returned in case path is empty.
    if path != "" {
      path
    } else {
      "/"
    }
  }

  /// Sets the path for this URL.
  /// # Errors
  /// Returns an [InvalidPath] if the given string `path` is not a valid URL path.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::resource::RelativeUrl;
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut relative_url = RelativeUrl::parse("the_answer_to_everything.pdf#conclusions")?;
  /// relative_url.set_path("we/know/its/42")?;
  /// assert_eq!(relative_url.as_str(), "we/know/its/42#conclusions");
  /// assert_eq!(relative_url.path(), "we/know/its/42");
  /// #   Ok(())
  /// # }
  /// ```
  pub fn set_path(&mut self, path: &str) -> Result<(), InvalidPath> {
    // Remove any leading slash.
    let path = path.trim_start_matches('/');
    all_consuming(path_parser).process(path).map_err(|e| InvalidPath {
      path: path.to_owned(),
      source: e.into_owned(),
    })?;

    let old_path_len = self.path().trim_start_matches('/').len();
    let mut data = std::mem::take(&mut self.data).into_string();

    let offset = path.len() as i32 - old_path_len as i32;
    let end_of_path = self.query_start.or(self.fragment_start).unwrap_or(old_path_len as u32) as usize;
    data.replace_range(..end_of_path, path);
    self.data = data.into_boxed_str();

    // Update query and fragment starts, if any.
    self
      .query_start
      .as_mut()
      .map(|idx| *idx = (*idx as i32 + offset) as u32);
    self
      .fragment_start
      .as_mut()
      .map(|idx| *idx = (*idx as i32 + offset) as u32);

    Ok(())
  }

  /// Returns an iterator yielding this [RelativeUrl] path's segments.
  pub fn path_segments(&self) -> impl Iterator<Item = &str> {
    iterator(self.path(), terminated(path_segment_parser, opt(char('/'))))
  }

  /// Returns the query component, if any.
  pub fn query(&self) -> Option<&str> {
    let end = self.fragment_start.unwrap_or(self.data.len() as u32) as usize;
    self.query_start.map(|idx| &self.data[idx as usize + 1..end])
  }

  /// Sets the query component of this URL.
  /// # Errors
  /// Returns an [InvalidQuery] if the given string `query` is not a valid URL query.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::resource::RelativeUrl;
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut relative_url = RelativeUrl::parse("a/very/long/path#section-2")?;
  /// relative_url.set_query("encoding=utf8")?;
  /// assert_eq!(
  ///   relative_url.as_str(),
  ///   "a/very/long/path?encoding=utf8#section-2"
  /// );
  /// assert_eq!(relative_url.query(), Some("encoding=utf8"));
  /// #   Ok(())
  /// # }
  /// ```
  pub fn set_query(&mut self, query: &str) -> Result<(), InvalidQuery> {
    let query = query.trim_start_matches('?');
    all_consuming(query_parser).process(query).map_err(|e| InvalidQuery {
      query: query.to_owned(),
      source: e.into_owned(),
    })?;

    let mut data = std::mem::take(&mut self.data).into_string();
    // A query was already set, replace it.
    if let Some(query_start) = self.query_start {
      let start = query_start as usize;
      let end = start + self.query().expect("query is set").len();
      data.replace_range(start..end, query);
      // Update the fragment position if one was already set.
      let new_fragment_start = start + query.len();
      self.fragment_start = self.fragment_start.and(Some(new_fragment_start as u32));
    }
    // A query wasn't set, but a fragment was, insert the new query before it
    // and update the fragment position.
    else if let Some(insertion_idx) = self.fragment_start {
      data.insert(insertion_idx as usize, '?');
      data.insert_str(insertion_idx as usize + 1, query);
      self.query_start = Some(insertion_idx);
      self.fragment_start = Some(insertion_idx + 1 + query.len() as u32);
    }
    // No query and no fragment, append the new query to the end of the string.
    else {
      let prev_len = self.data.len();
      write!(&mut data, "?{query}").unwrap();
      self.query_start = Some(prev_len as u32);
    }

    self.data = data.into_boxed_str();
    Ok(())
  }

  /// Returns an iterator yielding this [RelativeUrl] query parameters.
  pub fn query_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
    iterator(
      self.query().unwrap_or_default(),
      terminated(query_pair_parser, opt(char('&'))),
    )
  }

  /// Returns the fragment component, if any.
  pub fn fragment(&self) -> Option<&str> {
    self.fragment_start.map(|idx| &self.data[idx as usize + 1..])
  }

  /// Sets the fragment component of this URL.
  /// # Errors
  /// Return an [InvalidFragment] error if the given string `fragment` is not a valid fragment.
  /// # Example
  /// ```
  /// # use identity_chain_agnostic::resource::RelativeUrl;
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut relative_url = RelativeUrl::parse("path?key=value#fragment")?;
  /// relative_url.set_fragment("cooler-fragment")?;
  /// assert_eq!(relative_url.as_str(), "path?key=value#cooler-fragment");
  /// assert_eq!(relative_url.fragment(), Some("cooler-fragment"));
  /// #   Ok(())
  /// # }
  /// ```
  pub fn set_fragment(&mut self, fragment: &str) -> Result<(), InvalidFragment> {
    let fragment = fragment.trim_start_matches('#');
    all_consuming(fragment_parser)
      .process(fragment)
      .map_err(|e| InvalidFragment {
        fragment: fragment.to_owned(),
        source: e.into_owned(),
      })?;

    let mut data = std::mem::take(&mut self.data).into_string();
    if let Some(prev_fragment_start) = self.fragment_start {
      data.replace_range(prev_fragment_start as usize + 1.., fragment);
    } else {
      let fragment_start_idx = data.len();
      data.push('#');
      data.push_str(fragment);
      self.fragment_start = Some(fragment_start_idx as u32);
    }

    self.data = data.into_boxed_str();
    Ok(())
  }
}

#[derive(Debug)]
pub struct InvalidRelativeUrl {
  pub url: String,
  source: ParseError<'static>,
}

impl Display for InvalidRelativeUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "invalid relative url \"{}\"", self.url)
  }
}

impl std::error::Error for InvalidRelativeUrl {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn resource_parser(input: &str) -> ParserResult<'_, OnChainResourceLocator> {
  separated_pair(chain_id_parser, char('/'), relative_url_parser)
    .map(|(chain_id, locator)| OnChainResourceLocator { chain_id, locator })
    .process(input)
}

fn relative_url_parser(input: &str) -> ParserResult<'_, RelativeUrl> {
  let (after_path, _path) = path_parser(input)?;
  let (after_query, maybe_query_pairs) = opt(preceded(char('?'), query_parser))(after_path)?;
  let query_start = maybe_query_pairs.map(|_| (input.len() - after_path.len()) as u32);
  let (rem, maybe_fragment) = opt(preceded(char('#'), fragment_parser))(after_query)?;
  let fragment_start = maybe_fragment.map(|_| (input.len() - after_query.len()) as u32);
  let consumed = input.len() - rem.len();

  let locator = RelativeUrl {
    data: input[..consumed].into(),
    query_start,
    fragment_start,
  };
  Ok((rem, locator))
}

fn path_parser(input: &str) -> ParserResult<'_, &str> {
  recognize(many1(terminated(path_segment_parser, opt(char('/')))))(input)
}

fn path_segment_parser(input: &str) -> ParserResult<'_, &str> {
  recognize(many1(any((
    recognize(perc_encoded_parser),
    alphanumeric1,
    any_of("-_.~"),
  ))))
  .process(input)
}

fn query_parser(input: &str) -> ParserResult<'_, Vec<(&str, &str)>> {
  many1(query_pair_parser)(input)
}

fn query_pair_parser(input: &str) -> ParserResult<'_, (&str, &str)> {
  separated_pair(query_value_parser, char('='), query_value_parser)(input)
}

fn query_value_parser(input: &str) -> ParserResult<'_, &str> {
  recognize(many1(any((
    recognize(perc_encoded_parser),
    alphanumeric1,
    any_of("!$'()*+,-./:;@_?~"),
  ))))
  .process(input)
}

fn fragment_parser(input: &str) -> ParserResult<'_, &str> {
  recognize(many1(any((
    recognize(perc_encoded_parser),
    alphanumeric1,
    any_of("?/:@-._~!$&'()*+,;="),
  ))))
  .process(input)
}

/// Invalid path error.
#[derive(Debug)]
pub struct InvalidPath {
  /// The provided path.
  pub path: String,
  source: ParseError<'static>,
}

impl Display for InvalidPath {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "invalid path \"{}\"", self.path)
  }
}

impl std::error::Error for InvalidPath {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

/// Invalid query error.
#[derive(Debug)]
pub struct InvalidQuery {
  pub query: String,
  source: ParseError<'static>,
}

impl Display for InvalidQuery {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "invalid query \"{}\"", self.query)
  }
}

impl std::error::Error for InvalidQuery {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

/// Invalid fragment error.
#[derive(Debug)]
pub struct InvalidFragment {
  pub fragment: String,
  source: ParseError<'static>,
}

impl Display for InvalidFragment {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "invalid fragment \"{}\"", self.fragment)
  }
}

impl std::error::Error for InvalidFragment {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}
