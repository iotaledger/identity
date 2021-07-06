// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;
use std::marker::PhantomData;
use zeroize::Zeroize;

/// A cryptographic key with `Public` components.
pub type PublicKey = Key<Public>;

/// A cryptographic key with `Secret` components.
pub type SecretKey = Key<Secret>;

// =============================================================================
// =============================================================================

mod private {
  pub trait Sealed {}
}

// A marker type for the `Public` components of a cryptographic key.
#[derive(Clone, Copy, Debug)]
pub enum Public {}

// A marker type for the `Secret` components of a cryptographic key.
#[derive(Clone, Copy, Debug)]
pub enum Secret {}

impl private::Sealed for Public {}

impl private::Sealed for Secret {}

// =============================================================================
// =============================================================================

/// A cryptographic key.
#[derive(Clone)]
pub struct Key<V: private::Sealed> {
  key: Box<[u8]>,
  vis: PhantomData<V>,
}

impl<V: private::Sealed> Debug for Key<V> {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str("Key")
  }
}

impl<V: private::Sealed> Display for Key<V> {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str("Key")
  }
}

impl<V: private::Sealed> Drop for Key<V> {
  fn drop(&mut self) {
    self.key.zeroize();
  }
}

impl<V: private::Sealed> Zeroize for Key<V> {
  fn zeroize(&mut self) {
    self.key.zeroize();
  }
}

impl<V: private::Sealed> AsRef<[u8]> for Key<V> {
  fn as_ref(&self) -> &[u8] {
    &self.key
  }
}

impl<V: private::Sealed> From<Box<[u8]>> for Key<V> {
  fn from(other: Box<[u8]>) -> Self {
    Self {
      key: other,
      vis: PhantomData,
    }
  }
}

impl<V: private::Sealed> From<Vec<u8>> for Key<V> {
  fn from(other: Vec<u8>) -> Self {
    other.into_boxed_slice().into()
  }
}
