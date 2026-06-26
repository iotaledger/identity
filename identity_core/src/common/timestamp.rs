// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::str::FromStr;
use std::borrow::Borrow;
use std::borrow::Cow;

use serde;
use serde::Deserialize;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use time::UtcOffset;

use crate::error::Error;
use crate::error::Result;

/// A parsed Timestamp.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(try_from = "ProvisionalTimestamp<'_>", into = "String")]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
  /// Parses a `Timestamp` from the provided input string, normalized to UTC+00:00 with fractional
  /// seconds truncated.
  ///
  /// See the [`datetime` DID-core specification](https://www.w3.org/TR/did-core/#production).
  pub fn parse(input: &str) -> Result<Self> {
    let offset_date_time = OffsetDateTime::parse(input, &Rfc3339)
      .map_err(time::Error::from)
      .map_err(Error::InvalidTimestamp)?
      .to_offset(UtcOffset::UTC);
    Ok(Timestamp(truncate_fractional_seconds(offset_date_time)))
  }

  /// Creates a new `Timestamp` with the current date and time, normalized to UTC+00:00 with
  /// fractional seconds truncated.
  ///
  /// See the [`datetime` DID-core specification](https://www.w3.org/TR/did-core/#production).
  #[cfg(all(
    not(all(target_arch = "wasm32", not(target_os = "wasi"))),
    not(feature = "custom_time")
  ))]
  pub fn now_utc() -> Self {
    Self(truncate_fractional_seconds(OffsetDateTime::now_utc()))
  }

  /// Creates a new `Timestamp` with the current date and time, normalized to UTC+00:00 with
  /// fractional seconds truncated.
  ///
  /// See the [`datetime` DID-core specification](https://www.w3.org/TR/did-core/#production).
  #[cfg(all(target_arch = "wasm32", not(target_os = "wasi"), not(feature = "custom_time")))]
  pub fn now_utc() -> Self {
    let milliseconds_since_unix_epoch: i64 = js_sys::Date::now() as i64;
    let seconds: i64 = milliseconds_since_unix_epoch / 1000;
    // expect is okay, we assume the current time is between 0AD and 9999AD
    Self::from_unix(seconds).expect("Timestamp failed to convert system datetime")
  }

  /// Creates a new `Timestamp` with the current date and time, normalized to UTC+00:00 with
  /// fractional seconds truncated.
  ///
  /// See the [`datetime` DID-core specification](https://www.w3.org/TR/did-core/#production).
  #[cfg(feature = "custom_time")]
  pub fn now_utc() -> Self {
    crate::custom_time::now_utc_custom()
  }

  /// Returns the `Timestamp` as an [RFC 3339](https://tools.ietf.org/html/rfc3339) `String`.
  pub fn to_rfc3339(&self) -> String {
    // expect is okay, constructors ensure RFC 3339 compatible timestamps.
    // Making this fallible would break our interface such as From<Timestamp> for String.
    self.0.format(&Rfc3339).expect("Timestamp incompatible with RFC 3339")
  }

  /// Returns the `Timestamp` as a Unix timestamp.
  pub fn to_unix(&self) -> i64 {
    self.0.unix_timestamp()
  }

  /// Creates a new `Timestamp` from the given Unix timestamp.
  ///
  /// The timestamp must be in the valid range for [RFC 3339](https://tools.ietf.org/html/rfc3339).
  ///
  /// # Errors
  /// [`Error::InvalidTimestamp`] if `seconds` is outside of the interval [-62167219200,253402300799].
  pub fn from_unix(seconds: i64) -> Result<Self> {
    let offset_date_time = OffsetDateTime::from_unix_timestamp(seconds)
      .map_err(time::error::Error::from)
      .map_err(Error::InvalidTimestamp)?;

    // Reject years outside of the range 0000AD - 9999AD per Rfc3339
    // upfront to prevent conversion errors in to_rfc3339().
    // https://datatracker.ietf.org/doc/html/rfc3339#section-1
    if !(0..10_000).contains(&offset_date_time.year()) {
      return Err(Error::InvalidTimestamp(time::error::Error::Format(
        time::error::Format::InvalidComponent("invalid year"),
      )));
    }
    Ok(Self(offset_date_time))
  }

  /// Computes `self + duration`
  ///
  /// Returns `None` if the operation leads to a timestamp not in the valid range for [RFC 3339](https://tools.ietf.org/html/rfc3339).
  pub fn checked_add(self, duration: Duration) -> Option<Self> {
    self
      .0
      .checked_add(duration.0)
      .and_then(|offset_date_time| Self::from_unix(offset_date_time.unix_timestamp()).ok())
  }

  /// Computes `self - duration`
  ///
  /// Returns `None` if the operation leads to a timestamp not in the valid range for [RFC 3339](https://tools.ietf.org/html/rfc3339).
  pub fn checked_sub(self, duration: Duration) -> Option<Self> {
    self
      .0
      .checked_sub(duration.0)
      .and_then(|offset_date_time| Self::from_unix(offset_date_time.unix_timestamp()).ok())
  }
}

impl Default for Timestamp {
  fn default() -> Self {
    Self::now_utc()
  }
}

impl Debug for Timestamp {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    write!(f, "{:?}", self.to_rfc3339())
  }
}

impl Display for Timestamp {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    write!(f, "{}", self.to_rfc3339())
  }
}

impl From<Timestamp> for String {
  fn from(timestamp: Timestamp) -> Self {
    timestamp.to_rfc3339()
  }
}

impl TryFrom<&'_ str> for Timestamp {
  type Error = Error;

  fn try_from(string: &'_ str) -> Result<Self, Self::Error> {
    Self::parse(string)
  }
}

// This struct is only used to (potentially) avoid an allocation when deserializing a Timestamp. We cannot deserialize
// via &str because that breaks serde_json::from_value which we use extensively in the Stronghold bindings.
// This approach is inspired by https://crates.io/crates/serde_str_helpers, but we only use a subset of the functionality offered by that crate.
#[derive(Deserialize)]
struct ProvisionalTimestamp<'a>(#[serde(borrow)] Cow<'a, str>);

impl<'a> TryFrom<ProvisionalTimestamp<'a>> for Timestamp {
  type Error = Error;

  fn try_from(value: ProvisionalTimestamp<'a>) -> Result<Self, Self::Error> {
    Timestamp::parse(value.0.borrow())
  }
}

impl TryFrom<String> for Timestamp {
  type Error = Error;

  fn try_from(string: String) -> Result<Self, Self::Error> {
    Self::parse(&string)
  }
}

impl FromStr for Timestamp {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    Self::parse(string)
  }
}

/// Truncates an `OffsetDateTime` to the second.
fn truncate_fractional_seconds(offset_date_time: OffsetDateTime) -> OffsetDateTime {
  offset_date_time - time::Duration::nanoseconds(offset_date_time.nanosecond() as i64)
}

/// A span of time.
///
/// This type is typically used to increment or decrement a [`Timestamp`].
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Duration(time::Duration);

// Re-expose a small subset of time::Duration and use u32 instead of i64
// to disallow negative durations. This gives us the flexibility to migrate
// the internal representation to e.g. std::time::Duration in the future
// if required.
impl Duration {
  /// Create a new [`Duration`] with the given number of seconds.
  pub const fn seconds(seconds: u32) -> Self {
    Self(time::Duration::seconds(seconds as i64))
  }
  /// Create a new [`Duration`] with the given number of minutes.
  pub const fn minutes(minutes: u32) -> Self {
    Self(time::Duration::minutes(minutes as i64))
  }

  /// Create a new [`Duration`] with the given number of days.
  pub const fn days(days: u32) -> Self {
    Self(time::Duration::days(days as i64))
  }

  /// Create a new [`Duration`] with the given number of hours.
  pub const fn hours(hours: u32) -> Self {
    Self(time::Duration::hours(hours as i64))
  }

  /// Create a new [`Duration`] with the given number of weeks.
  pub const fn weeks(weeks: u32) -> Self {
    Self(time::Duration::weeks(weeks as i64))
  }
}

#[cfg(test)]
mod tests {
  use crate::common::Timestamp;
  use crate::convert::FromJson;
  use crate::convert::ToJson;
  use proptest::proptest;

  use super::Duration;

  // 0000-01-01T00:00:00Z
  const FIRST_VALID_UNIX_TIMESTAMP: i64 = -62167219200;
  // 9999-12-31T23:59:59Z
  const LAST_VALID_UNIX_TIMESTAMP: i64 = 253402300799;

  #[test]
  fn test_parse_valid() {
    let original = "2020-01-01T00:00:00Z";
    let timestamp = Timestamp::parse(original).unwrap();

    assert_eq!(timestamp.to_rfc3339(), original);

    let original = "1980-01-01T12:34:56Z";
    let timestamp = Timestamp::parse(original).unwrap();

    assert_eq!(timestamp.to_rfc3339(), original);
  }

  #[test]
  fn test_parse_valid_truncated() {
    let original = "1980-01-01T12:34:56.789Z";
    let expected = "1980-01-01T12:34:56Z";
    let timestamp = Timestamp::parse(original).unwrap();

    assert_eq!(timestamp.to_rfc3339(), expected);
  }

  #[test]
  fn test_parse_valid_offset_normalised() {
    let original = "1937-01-01T12:00:27.87+00:20";
    let expected = "1937-01-01T11:40:27Z";
    let timestamp = Timestamp::parse(original).unwrap();

    assert_eq!(timestamp.to_rfc3339(), expected);
  }

  #[test]
  fn test_checked_add() {
    let timestamp = Timestamp::parse("1980-01-01T12:34:56Z").unwrap();
    let second_later = timestamp.checked_add(Duration::seconds(1)).unwrap();
    assert_eq!(second_later.to_rfc3339(), "1980-01-01T12:34:57Z");
    let minute_later = timestamp.checked_add(Duration::minutes(1)).unwrap();
    assert_eq!(minute_later.to_rfc3339(), "1980-01-01T12:35:56Z");
    let hour_later = timestamp.checked_add(Duration::hours(1)).unwrap();
    assert_eq!(hour_later.to_rfc3339(), "1980-01-01T13:34:56Z");
    let day_later = timestamp.checked_add(Duration::days(1)).unwrap();
    assert_eq!(day_later.to_rfc3339(), "1980-01-02T12:34:56Z");
    let week_later = timestamp.checked_add(Duration::weeks(1)).unwrap();
    assert_eq!(week_later.to_rfc3339(), "1980-01-08T12:34:56Z");

    // check overflow
    assert!(Timestamp::from_unix(LAST_VALID_UNIX_TIMESTAMP)
      .unwrap()
      .checked_add(Duration::seconds(1))
      .is_none());
  }

  #[test]
  fn test_checked_sub() {
    let timestamp = Timestamp::parse("1980-01-01T12:34:56Z").unwrap();
    let second_earlier = timestamp.checked_sub(Duration::seconds(1)).unwrap();
    assert_eq!(second_earlier.to_rfc3339(), "1980-01-01T12:34:55Z");
    let minute_earlier = timestamp.checked_sub(Duration::minutes(1)).unwrap();
    assert_eq!(minute_earlier.to_rfc3339(), "1980-01-01T12:33:56Z");
    let hour_earlier = timestamp.checked_sub(Duration::hours(1)).unwrap();
    assert_eq!(hour_earlier.to_rfc3339(), "1980-01-01T11:34:56Z");
    let day_earlier = timestamp.checked_sub(Duration::days(1)).unwrap();
    assert_eq!(day_earlier.to_rfc3339(), "1979-12-31T12:34:56Z");
    let week_earlier = timestamp.checked_sub(Duration::weeks(1)).unwrap();
    assert_eq!(week_earlier.to_rfc3339(), "1979-12-25T12:34:56Z");

    // check underflow
    assert!(Timestamp::from_unix(FIRST_VALID_UNIX_TIMESTAMP)
      .unwrap()
      .checked_sub(Duration::seconds(1))
      .is_none());
  }

  #[test]
  fn test_from_unix_zero_to_rfc3339() {
    let unix_epoch = Timestamp::from_unix(0).unwrap();
    assert_eq!(unix_epoch.to_rfc3339(), "1970-01-01T00:00:00Z");
  }

  #[test]
  fn test_from_unix_invalid_edge_cases() {
    assert!(Timestamp::from_unix(LAST_VALID_UNIX_TIMESTAMP + 1).is_err());
    assert!(Timestamp::from_unix(FIRST_VALID_UNIX_TIMESTAMP - 1).is_err());
  }

  #[test]
  fn test_from_unix_to_rfc3339_boundaries() {
    let beginning = Timestamp::from_unix(FIRST_VALID_UNIX_TIMESTAMP).unwrap();
    let end = Timestamp::from_unix(LAST_VALID_UNIX_TIMESTAMP).unwrap();
    assert_eq!(beginning.to_rfc3339(), "0000-01-01T00:00:00Z");
    assert_eq!(end.to_rfc3339(), "9999-12-31T23:59:59Z");
  }

  proptest! {
    #[test]
    fn test_from_unix_to_rfc3339_valid_no_panic(seconds in FIRST_VALID_UNIX_TIMESTAMP..=LAST_VALID_UNIX_TIMESTAMP) {
      let timestamp = Timestamp::from_unix(seconds).unwrap();
      let expected_length = "dddd-dd-ddTdd:dd:ddZ".len();
      assert_eq!(timestamp.to_rfc3339().len(), expected_length);
    }
  }

  #[test]
  #[should_panic = "InvalidTimestamp"]
  fn test_parse_empty() {
    Timestamp::parse("").unwrap();
  }

  #[test]
  #[should_panic = "InvalidTimestamp"]
  fn test_parse_invalid_date() {
    Timestamp::parse("foo bar").unwrap();
  }

  #[test]
  #[should_panic = "InvalidTimestamp"]
  fn test_parse_invalid_fmt() {
    Timestamp::parse("2020/01/01 03:30:16").unwrap();
  }

  #[test]
  fn test_json_vec_roundtrip() {
    let time1: Timestamp = Timestamp::now_utc();
    let json: Vec<u8> = time1.to_json_vec().unwrap();
    let time2: Timestamp = Timestamp::from_json_slice(&json).unwrap();

    assert_eq!(time1, time2);
  }

  #[test]
  fn test_json_value_roundtrip() {
    let time1: Timestamp = Timestamp::now_utc();
    let json: serde_json::Value = time1.to_json_value().unwrap();
    let time2: Timestamp = Timestamp::from_json_value(json).unwrap();

    assert_eq!(time1, time2);
  }
}
