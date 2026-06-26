// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

/// This JSON Proof Token could represent a JWP both in the Issued and Presented forms.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Jpt(String);

impl Jpt {
  /// Creates a new `Jwt` from the given string.
  pub fn new(jpt_string: String) -> Self {
    Self(jpt_string)
  }

  /// Returns a reference of the JWT string.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl From<String> for Jpt {
  fn from(jpt: String) -> Self {
    Self::new(jpt)
  }
}

impl From<Jpt> for String {
  fn from(jpt: Jpt) -> Self {
    jpt.0
  }
}
