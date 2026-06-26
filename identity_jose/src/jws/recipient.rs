// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::jws::JwsHeader;

/// The recipient of a JWS.
///
/// The contained headers determine the specifics of the signature for that recipient,
/// such as what algorithm (`alg`) or key (`kid`) will be or was used to create the signature.
#[derive(Clone, Copy)]
pub struct Recipient<'a> {
  /// The integrity-protected JOSE header.
  pub protected: Option<&'a JwsHeader>,
  /// The non integrity-protected JOSE header.
  pub unprotected: Option<&'a JwsHeader>,
}

impl Default for Recipient<'_> {
  fn default() -> Self {
    Self::new()
  }
}

impl<'a> Recipient<'a> {
  /// Creates a new recipient with no header set.
  pub fn new() -> Self {
    Self {
      protected: None,
      unprotected: None,
    }
  }

  /// Set the integrity-protected JOSE header.
  pub fn protected(mut self, value: &'a JwsHeader) -> Self {
    self.protected = Some(value);
    self
  }

  /// Set the non integrity-protected JOSE header.
  pub fn unprotected(mut self, value: &'a JwsHeader) -> Self {
    self.unprotected = Some(value);
    self
  }
}
