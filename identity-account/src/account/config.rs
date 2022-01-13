// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use identity_iota::tangle::Client;

use crate::storage::Storage;

/// A wrapper that holds configuration for an [`Account`] instantiation.
///
/// The setup implements `Clone` so multiple [`Account`]s can be created
/// from the same setup. [`Storage`] and [`Client`] are shared among
/// those accounts, while the [`Config`] is unique to each account.
///
/// [`Account`]([crate::account::Account])
#[derive(Clone, Debug)]
pub(crate) struct AccountSetup {
  pub(crate) storage: Arc<dyn Storage>,
  pub(crate) client: Arc<Client>,
  pub(crate) config: AccountConfig,
}

impl AccountSetup {
  /// Create a new setup from the given [`Storage`] implementation
  /// and with defaults for [`Config`] and [`Client`].
  pub(crate) fn new(storage: Arc<dyn Storage>, client: Arc<Client>, config: AccountConfig) -> Self {
    Self {
      storage,
      client,
      config,
    }
  }
}

/// Configuration for [`Account`][crate::account::Account]s.
#[derive(Clone, Debug)]
pub(crate) struct AccountConfig {
  pub(crate) autosave: AutoSave,
  pub(crate) autopublish: bool,
  pub(crate) testmode: bool,
  pub(crate) milestone: u32,
}

impl AccountConfig {
  const MILESTONE: u32 = 1;

  /// Creates a new default [`Config`].
  pub(crate) fn new() -> Self {
    Self {
      autosave: AutoSave::Every,
      autopublish: true,
      testmode: false,
      milestone: Self::MILESTONE,
    }
  }

  /// Sets the account auto-save behaviour.
  /// - [`Every`][AutoSave::Every] => Save to storage on every update
  /// - [`Never`][AutoSave::Never] => Never save to storage when updating
  /// - [`Batch(n)`][AutoSave::Batch] => Save to storage after every `n` updates.
  ///
  /// Default: [`Every`][AutoSave::Every]
  pub(crate) fn autosave(mut self, value: AutoSave) -> Self {
    self.autosave = value;
    self
  }

  /// Sets the account auto-publish behaviour.
  /// - `true` => publish to the Tangle on every DID document change
  /// - `false` => never publish automatically
  ///
  /// Default: `true`
  pub(crate) fn autopublish(mut self, value: bool) -> Self {
    self.autopublish = value;
    self
  }

  /// Save a state snapshot every N actions.
  pub(crate) fn milestone(mut self, value: u32) -> Self {
    self.milestone = value;
    self
  }

  /// Set whether the account is in testmode or not.
  /// In testmode, the account skips publishing to the tangle.
  #[cfg(test)]
  pub(crate) fn testmode(mut self, value: bool) -> Self {
    self.testmode = value;
    self
  }
}

impl Default for AccountConfig {
  fn default() -> Self {
    Self::new()
  }
}

/// Available auto-save behaviours.
#[derive(Clone, Copy, Debug)]
pub enum AutoSave {
  /// Never save
  Never,
  /// Save after every action
  Every,
  /// Save after every N actions
  Batch(usize),
}
