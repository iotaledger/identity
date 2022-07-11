// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use serde::Deserialize;
use serde::Serialize;

use crate::agent::Endpoint;
use crate::agent::RequestMode;

/// A request message containing some opaque data together with the endpoint it is inteded for and its request mode.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RequestMessage {
  pub(crate) endpoint: Endpoint,
  pub(crate) request_mode: RequestMode,
  pub(crate) data: Vec<u8>,
}

impl RequestMessage {
  /// Creates a new request message from its parts.
  pub(crate) fn new(endpoint: Endpoint, request_mode: RequestMode, data: Vec<u8>) -> Self {
    Self {
      endpoint,
      request_mode,
      data,
    }
  }

  /// Deserializes some JSON bytes into a request message.
  pub(crate) fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
    serde_json::from_slice::<'_, Self>(bytes)
      .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
  }

  /// Serializes the request message into JSON bytes.
  pub(crate) fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(self).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
  }
}

/// A response message containing some opaque data.
#[derive(Debug)]
pub(crate) struct ResponseMessage(pub(crate) Vec<u8>);
