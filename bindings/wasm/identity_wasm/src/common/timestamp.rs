// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Duration;
use identity_iota::core::Timestamp;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Timestamp | undefined")]
  pub type OptionTimestamp;
}

/// A parsed Timestamp.
#[wasm_bindgen(js_name = Timestamp, inspectable)]
pub struct WasmTimestamp(pub(crate) Timestamp);

#[wasm_bindgen(js_class = Timestamp)]
#[allow(clippy::new_without_default)]
impl WasmTimestamp {
  /// Creates a new {@link Timestamp} with the current date and time.
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
    Self::now_utc()
  }

  /// Parses a {@link Timestamp} from the provided input string.
  #[wasm_bindgen]
  pub fn parse(input: &str) -> Result<WasmTimestamp> {
    Ok(Self(Timestamp::parse(input).wasm_result()?))
  }

  /// Creates a new {@link Timestamp} with the current date and time.
  #[wasm_bindgen(js_name = nowUTC)]
  pub fn now_utc() -> Self {
    Self(Timestamp::now_utc())
  }

  /// Returns the {@link Timestamp} as an RFC 3339 `String`.
  #[wasm_bindgen(js_name = toRFC3339)]
  #[allow(clippy::wrong_self_convention)]
  pub fn to_rfc3339(&self) -> String {
    self.0.to_rfc3339()
  }

  /// Computes `self + duration`
  ///
  /// Returns `null` if the operation leads to a timestamp not in the valid range for [RFC 3339](https://tools.ietf.org/html/rfc3339).
  #[wasm_bindgen(js_name = checkedAdd)]
  pub fn checked_add(&self, duration: &WasmDuration) -> Option<WasmTimestamp> {
    self.0.checked_add(duration.0).map(WasmTimestamp)
  }

  /// Computes `self - duration`
  ///
  /// Returns `null` if the operation leads to a timestamp not in the valid range for [RFC 3339](https://tools.ietf.org/html/rfc3339).
  #[wasm_bindgen(js_name = checkedSub)]
  pub fn checked_sub(&self, duration: &WasmDuration) -> Option<WasmTimestamp> {
    self.0.checked_sub(duration.0).map(WasmTimestamp)
  }
}

impl_wasm_json!(WasmTimestamp, Timestamp);

impl From<Timestamp> for WasmTimestamp {
  fn from(timestamp: Timestamp) -> Self {
    Self(timestamp)
  }
}

/// A span of time.
#[wasm_bindgen(js_name = Duration, inspectable)]
pub struct WasmDuration(pub(crate) Duration);

#[wasm_bindgen(js_class = Duration)]
impl WasmDuration {
  /// Create a new {@link Duration} with the given number of seconds.
  #[wasm_bindgen]
  pub fn seconds(seconds: u32) -> WasmDuration {
    Self(Duration::seconds(seconds))
  }
  /// Create a new {@link Duration} with the given number of minutes.
  #[wasm_bindgen]
  pub fn minutes(minutes: u32) -> WasmDuration {
    Self(Duration::minutes(minutes))
  }

  /// Create a new {@link Duration} with the given number of hours.
  #[wasm_bindgen]
  pub fn hours(hours: u32) -> WasmDuration {
    Self(Duration::hours(hours))
  }

  /// Create a new {@link Duration} with the given number of days.
  #[wasm_bindgen]
  pub fn days(days: u32) -> WasmDuration {
    Self(Duration::days(days))
  }

  /// Create a new {@link Duration} with the given number of weeks.
  #[wasm_bindgen]
  pub fn weeks(weeks: u32) -> WasmDuration {
    Self(Duration::weeks(weeks))
  }
}

impl_wasm_json!(WasmDuration, Duration);

impl From<Duration> for WasmDuration {
  fn from(duration: Duration) -> Self {
    Self(duration)
  }
}

impl From<WasmDuration> for Duration {
  fn from(duration: WasmDuration) -> Self {
    duration.0
  }
}
