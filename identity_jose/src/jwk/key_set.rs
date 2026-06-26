// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::iter::FromIterator;
use core::ops::Index;
use core::ops::IndexMut;
use core::slice::Iter;
use core::slice::SliceIndex;
use zeroize::Zeroize;

use crate::jwk::Jwk;

/// JSON Web Key Set.
///
/// [More Info](https://tools.ietf.org/html/rfc7517#section-5)
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct JwkSet {
  /// An array of JWK values.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-5.1)
  keys: Vec<Jwk>,
}

impl JwkSet {
  /// Creates a new `JwkSet`.
  pub const fn new() -> Self {
    Self { keys: Vec::new() }
  }

  /// Returns the total number of keys in the set.
  pub fn len(&self) -> usize {
    self.keys.len()
  }

  /// Returns a boolean indicating if the set of keys is empty.
  pub fn is_empty(&self) -> bool {
    self.keys.is_empty()
  }

  /// Returns a slice containing the entire vector of keys.
  pub fn as_slice(&self) -> &[Jwk] {
    &self.keys
  }

  /// Returns an iterator over the contained [`Jwk`]s.
  pub fn iter(&self) -> Iter<'_, Jwk> {
    self.keys.iter()
  }

  /// Returns a list of keys matching the given `kid`.
  pub fn get(&self, kid: &str) -> Vec<&Jwk> {
    self
      .keys
      .iter()
      .filter(|key| matches!(key.kid(), Some(value) if value == kid))
      .collect()
  }

  /// Adds a new `key` to the set.
  pub fn add(&mut self, key: impl Into<Jwk>) {
    self.keys.push(key.into());
  }

  /// Removes the key at position `index`, returning `true` if the key was
  /// removed.
  pub fn del(&mut self, index: usize) -> bool {
    if index < self.keys.len() {
      self.keys.remove(index);
      true
    } else {
      false
    }
  }

  /// Removes and returns the last `key` in the set.
  pub fn pop(&mut self) -> Option<Jwk> {
    self.keys.pop()
  }
}

impl FromIterator<Jwk> for JwkSet {
  fn from_iter<I>(iter: I) -> Self
  where
    I: IntoIterator<Item = Jwk>,
  {
    Self {
      keys: Vec::from_iter(iter),
    }
  }
}

impl<I> Index<I> for JwkSet
where
  I: SliceIndex<[Jwk]>,
{
  type Output = I::Output;

  fn index(&self, index: I) -> &Self::Output {
    Index::index(&*self.keys, index)
  }
}

impl<I> IndexMut<I> for JwkSet
where
  I: SliceIndex<[Jwk]>,
{
  fn index_mut(&mut self, index: I) -> &mut Self::Output {
    IndexMut::index_mut(&mut *self.keys, index)
  }
}

impl Zeroize for JwkSet {
  fn zeroize(&mut self) {
    self.keys.zeroize();
  }
}

impl Drop for JwkSet {
  fn drop(&mut self) {
    self.zeroize();
  }
}
