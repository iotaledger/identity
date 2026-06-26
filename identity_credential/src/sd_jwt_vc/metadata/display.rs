// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Credential type's display information of a given language.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisplayMetadata {
  /// Language tag as defined in [RFC5646](https://www.rfc-editor.org/rfc/rfc5646.txt).
  pub locale: String,
  /// VC type's human-readable name.
  pub name: String,
  /// VC type's human-readable description.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub description: Option<String>,
  /// Optional rendering information.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rendering: Option<RenderingMetadata>,
}

/// Information on how to render a given credential type.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RenderingMetadata(serde_json::Map<String, Value>);
