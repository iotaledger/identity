// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Url;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// SD-JWT VC's `status` claim value. Used to retrieve the status of the token.
pub struct Status(pub StatusMechanism);

/// Mechanism used for representing the status of an SD-JWT VC token.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StatusMechanism {
  /// Reference to a status list containing this token's status.
  #[serde(rename = "status_list")]
  StatusList(StatusListRef),
  /// A non-standard status mechanism.
  #[serde(untagged)]
  Custom(serde_json::Value),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// A reference to an OAuth status list.
/// See [OAuth StatusList specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-02)
/// for more information.
pub struct StatusListRef {
  /// URI of the status list.
  pub uri: Url,
  /// Index of the entry containing this token's status.
  pub idx: usize,
}

#[cfg(test)]
mod tests {
  use super::*;

  use serde_json::json;

  #[test]
  fn round_trip() {
    let status_value = json!({
      "status_list": {
        "idx": 420,
        "uri": "https://example.com/statuslists/1"
      }
    });
    let status: Status = serde_json::from_value(status_value.clone()).unwrap();
    assert_eq!(serde_json::to_value(status).unwrap(), status_value);
  }
}
