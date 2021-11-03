// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;

use identity_core::crypto::KeyType;
use identity_iota::tangle::NetworkName;

use crate::types::MethodSecret;
use crate::Result;

/// Configuration used to create a new Identity.
#[derive(Clone, Debug)]
pub struct IdentityCreate {
  pub(crate) key_type: KeyType,
  pub(crate) name: Option<String>,
  pub(crate) network: Option<NetworkName>,
  pub(crate) method_secret: Option<MethodSecret>,
}

impl IdentityCreate {
  /// Creates a new `IdentityCreate` instance.
  pub const fn new() -> Self {
    Self {
      key_type: KeyType::Ed25519,
      name: None,
      network: None,
      method_secret: None,
    }
  }

  /// Sets the key type of the initial verification method.
  #[must_use]
  pub fn key_type(mut self, value: KeyType) -> Self {
    self.key_type = value;
    self
  }

  /// Sets the name of the Identity.
  #[must_use]
  pub fn name<T>(mut self, value: T) -> Self
  where
    T: Into<String>,
  {
    self.name = Some(value.into());
    self
  }

  /// Sets the IOTA Tangle network of the Identity DID.
  #[allow(clippy::double_must_use)]
  #[must_use]
  pub fn network<T>(mut self, value: T) -> Result<Self>
  where
    T: TryInto<NetworkName>,
  {
    self.network = Some(value.try_into().map_err(|_| identity_iota::Error::InvalidNetworkName)?);
    Ok(self)
  }

  /// Sets the [`MethodSecret`] for the Identity creation.
  ///
  /// Note that only [`MethodSecret::Ed25519`] is currently supported.
  #[must_use]
  pub fn method_secret(mut self, value: MethodSecret) -> Self {
    self.method_secret = Some(value);
    self
  }
}

impl Default for IdentityCreate {
  fn default() -> Self {
    Self::new()
  }
}
