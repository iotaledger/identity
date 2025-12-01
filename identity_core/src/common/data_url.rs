// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::str::FromStr;

use serde::Serialize;

use crate::common::Url;

const DEFAULT_MIME_TYPE: &str = "text/plain";

/// An URL using the "data" scheme, according to [RFC2397](https://datatracker.ietf.org/doc/html/rfc2397).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataUrl {
  serialized: Box<str>,
  start_of_data: u32,
  base64: bool,
}

impl AsRef<str> for DataUrl {
  fn as_ref(&self) -> &str {
    &self.serialized
  }
}

impl DataUrl {
  /// Return the string representation of this [DataUrl].
  pub const fn as_str(&self) -> &str {
    &self.serialized
  }

  /// Parses a [DataUrl] from the given string input.
  /// # Example
  /// ```
  /// # use identity_core::common::DataUrl;
  /// # use identity_core::common::InvalidDataUrl;
  /// #
  /// # fn main() -> Result<(), InvalidDataUrl> {
  /// let data_url = DataUrl::parse("data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==")?;
  /// assert!(data_url.is_base64());
  /// assert_eq!(data_url.mediatype(), "text/plain");
  /// assert_eq!(data_url.encoded_data(), "SGVsbG8sIFdvcmxkIQ==");
  /// #  Ok(())
  /// # }
  /// ```
  pub fn parse(input: &str) -> Result<Self, InvalidDataUrl> {
    use nom::combinator::all_consuming;
    use nom::Parser as _;

    let (_, data_url) = all_consuming(parsers::data_url)
      .parse(input)
      .map_err(|_| InvalidDataUrl {})?;
    Ok(data_url)
  }

  /// Returns whether this [DataUrl] has its `base64` flag set, e.g. "data:image/gif".
  pub const fn is_base64(&self) -> bool {
    self.base64
  }

  /// Returns the string representation of the data encoded within this [DataUrl].
  pub fn encoded_data(&self) -> &str {
    let idx = self.start_of_data as usize;
    &self.as_str()[idx..]
  }

  /// Returns the string representation of the MIME type of the data encoded within
  /// this [DataUrl]. The returned string also contains the type's parameters if any.
  /// ## Notes
  /// When a [DataUrl] omits the MIME type (e.g. "data:,A%20brief%20note"), this method
  /// returns the default MIME type "text/plain;charset=US-ASCII", instead of the empty
  /// string.
  /// # Example
  pub fn media_type(&self) -> &str {
    let start = "data:".len();
    let end = self.start_of_data as usize
      - 1 // ','
      - self.base64 as usize * ";base64".len(); // optional ";base64"

    let mime = &self.serialized[start..end];
    if mime.is_empty() {
      DEFAULT_MIME_TYPE
    } else {
      mime
    }
  }
}

impl Display for DataUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.serialized)
  }
}

impl FromStr for DataUrl {
  type Err = InvalidDataUrl;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    DataUrl::parse(s)
  }
}

impl From<DataUrl> for Url {
  fn from(data_url: DataUrl) -> Self {
    Url::parse(data_url.as_str()).expect("DataUrl is always a valid Url")
  }
}

impl Serialize for DataUrl {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(&self.serialized)
  }
}

impl<'de> serde::Deserialize<'de> for DataUrl {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    use serde::de::Error;

    let str = <&str>::deserialize(deserializer)?;
    DataUrl::parse(str).map_err(|_| Error::custom("invalid data URL"))
  }
}

/// Error indicating that a given string is not a valid data URL.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InvalidDataUrl {}

impl Display for InvalidDataUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("invalid data URL")
  }
}

impl std::error::Error for InvalidDataUrl {}
mod parsers {
  use nom::branch::alt;
  use nom::bytes::complete::tag;
  use nom::bytes::complete::take_while1;
  use nom::bytes::complete::take_while_m_n;
  #[cfg(test)]
  use nom::combinator::all_consuming;
  use nom::combinator::opt;
  use nom::combinator::recognize;
  use nom::multi::many1_count;
  use nom::sequence::preceded;
  use nom::sequence::separated_pair;
  use nom::IResult;
  use nom::Parser;

  use super::DataUrl;

  pub(super) fn data_url(input: &str) -> IResult<&str, DataUrl> {
    let (rem, (_type, base64, data)) = preceded(
      tag("data:"),
      (
        opt(mediatype),
        opt(tag(";base64")).map(|opt| opt.is_some()),
        preceded(tag(","), uri_char1),
      ),
    )
    .parse(input)?;

    let consumed = input.len() - rem.len();
    let serialized = input[..consumed].to_owned().into_boxed_str();
    let start_of_data = (consumed - data.len()) as u32;

    Ok((
      rem,
      DataUrl {
        serialized,
        start_of_data,
        base64,
      },
    ))
  }

  fn mediatype(input: &str) -> IResult<&str, &str> {
    let type_ = separated_pair(media_char1, tag("/"), media_char1);
    let parameters = many1_count(preceded(tag(";"), separated_pair(media_char1, tag("="), media_char1)));

    recognize((type_, opt(parameters))).parse(input)
  }

  fn uri_char1(input: &str) -> IResult<&str, &str> {
    let reserved = take_while1(|c: char| ";/?:@&=+$,".contains(c));
    let unreserved = take_while1(|c: char| "-_.!~*'(|)".contains(c) || c.is_ascii_alphanumeric());
    let escaped = recognize(percent_escaped);

    recognize(many1_count(alt((reserved, unreserved, escaped)))).parse(input)
  }

  fn media_char1(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_ascii_alphanumeric() || "-_.+".contains(c))(input)
  }

  fn percent_escaped(input: &str) -> IResult<&str, u8> {
    preceded(tag("%"), take_while_m_n(2, 2, |c: char| c.is_ascii_hexdigit()))
      .map_res(|hex_byte| u8::from_str_radix(hex_byte, 16))
      .parse(input)
  }

  #[cfg(test)]
  #[test]
  fn mediatype_parser() {
    all_consuming(mediatype).parse("text/plain").unwrap();
    all_consuming(mediatype).parse("application/vc+jwt").unwrap();
    all_consuming(mediatype).parse("video/mp4").unwrap();
    all_consuming(mediatype).parse("text/plain;charset=us-ascii").unwrap();
  }

  #[cfg(test)]
  #[test]
  fn data_url_parser() {
    all_consuming(data_url).parse("data:text/plain,hello").unwrap();
    all_consuming(data_url)
      .parse("data:text/plain;charset=us-ascii,hello%20world")
      .unwrap();
    all_consuming(data_url).parse("data:,hello%20world").unwrap();
    all_consuming(data_url).parse("data:application/vc+jwt,ey").unwrap();
    let (_, data_url) = all_consuming(data_url)
      .parse("data:application/vc+jwt;base64,ey")
      .unwrap();
    assert!(data_url.is_base64());
  }
}
