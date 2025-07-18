// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Formatter;
use core::iter::FromIterator;
use core::ops::Deref;
use core::slice::Iter;
use core::slice::IterMut;
use std::vec::IntoIter;

use serde::Deserialize;
use serde::Serialize;

use crate::common::KeyComparable;
use crate::error::Error;
use crate::error::Result;

/// An ordered set backed by a `Vec<T>`.
///
/// Note: Ordering is based on insert order and **not** [`Ord`].
///
/// See the [Infra standard definition](https://infra.spec.whatwg.org/#ordered-set).
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(bound(deserialize = "T: KeyComparable + Deserialize<'de>"), try_from = "Vec<T>")]
pub struct OrderedSet<T>(Vec<T>);

impl<T> OrderedSet<T> {
  /// Creates a new `OrderedSet`.
  #[inline]
  pub const fn new() -> Self {
    Self(Vec::new())
  }

  /// Creates a new `OrderedSet` with the specified capacity.
  #[inline]
  pub fn with_capacity(capacity: usize) -> Self {
    Self(Vec::with_capacity(capacity))
  }

  /// Returns the number of elements in the `OrderedSet`.
  #[inline]
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns `true` if the `OrderedSet` contains no elements.
  #[inline]
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// Returns an iterator over the slice of elements.
  #[inline]
  pub fn iter(&self) -> Iter<'_, T> {
    self.0.iter()
  }

  /// Returns an iterator that allows modifying each value.
  ///
  /// WARNING: improper usage of this allows violating the key-uniqueness of the OrderedSet.
  #[inline]
  pub fn iter_mut_unchecked(&mut self) -> IterMut<'_, T> {
    self.0.iter_mut()
  }

  /// Returns the first element in the set, or `None` if the set is empty.
  #[inline]
  pub fn head(&self) -> Option<&T> {
    self.0.first()
  }

  /// Returns a mutable reference to the first element in the set, or `None` if
  /// the set is empty.
  ///
  /// # Warning
  /// Incorrect use of this can break the invariants of [`OrderedSet`].
  #[inline]
  pub fn head_mut(&mut self) -> Option<&mut T> {
    self.0.first_mut()
  }

  /// Returns the last element in the set, or `None` if the set is empty.
  #[inline]
  pub fn tail(&self) -> Option<&T> {
    self.0.last()
  }

  /// Returns a mutable reference the last element in the set, or `None` if the
  /// set is empty.
  ///
  /// # Warning
  /// Incorrect use of this can break the invariants of [`OrderedSet`].
  #[inline]
  pub fn tail_mut(&mut self) -> Option<&mut T> {
    self.0.last_mut()
  }

  /// Returns a slice containing all elements in the `OrderedSet`.
  #[inline]
  pub fn as_slice(&self) -> &[T] {
    &self.0
  }

  /// Consumes the `OrderedSet` and returns the elements as a `Vec<T>`.
  #[inline]
  pub fn into_vec(self) -> Vec<T> {
    self.0
  }

  /// Clears the `OrderedSet`, removing all values.
  #[inline]
  pub fn clear(&mut self) {
    self.0.clear();
  }

  /// Returns `true` if the `OrderedSet` contains the given value.
  pub fn contains<U>(&self, item: &U) -> bool
  where
    T: KeyComparable,
    U: KeyComparable<Key = T::Key> + ?Sized,
  {
    self.0.iter().any(|other| other.key() == item.key())
  }

  /// Adds a new value to the end of the `OrderedSet`; returns `true` if the
  /// value was successfully added.
  pub fn append(&mut self, item: T) -> bool
  where
    T: KeyComparable,
  {
    if self.contains(&item) {
      false
    } else {
      self.0.push(item);
      true
    }
  }

  /// Adds a new value to the start of the `OrderedSet`; returns `true` if the
  /// value was successfully added.
  pub fn prepend(&mut self, item: T) -> bool
  where
    T: KeyComparable,
  {
    if self.contains(&item) {
      false
    } else {
      self.0.insert(0, item);
      true
    }
  }

  /// Replaces a `current` value with the given `update` value; returns `true`
  /// if the value was successfully replaced.
  #[inline]
  pub fn replace<U>(&mut self, current: &U, update: T) -> bool
  where
    T: KeyComparable,
    U: KeyComparable<Key = T::Key>,
  {
    self.change(update, |item, update| {
      item.key() == current.key() || item.key() == update.key()
    })
  }

  /// Updates an existing value in the `OrderedSet`; returns `true` if the value
  /// was successfully updated.
  #[inline]
  pub fn update(&mut self, update: T) -> bool
  where
    T: KeyComparable,
  {
    self.change(update, |item, update| item.key() == update.key())
  }

  /// Removes and returns the item with the matching key from the set, if it exists.
  #[inline]
  pub fn remove<U>(&mut self, item: &U) -> Option<T>
  where
    T: KeyComparable,
    U: KeyComparable<Key = T::Key>,
  {
    self
      .0
      .iter()
      .enumerate()
      .find(|(_, entry)| entry.key() == item.key())
      .map(|(idx, _)| idx)
      .map(|idx| self.0.remove(idx))
  }

  fn change<F>(&mut self, data: T, f: F) -> bool
  where
    F: Fn(&T, &T) -> bool,
  {
    let index: Option<usize> = self.0.iter().position(|item| f(item, &data));

    if let Some(index) = index {
      let keep: Vec<T> = self.0.drain(index..).filter(|item| !f(item, &data)).collect();

      self.0.extend(keep);
      self.0.insert(index, data);
    }

    index.is_some()
  }
}

impl<T> IntoIterator for OrderedSet<T> {
  type Item = T;
  type IntoIter = IntoIter<T>;

  fn into_iter(self) -> Self::IntoIter {
    self.0.into_iter()
  }
}

impl<T> Debug for OrderedSet<T>
where
  T: Debug,
{
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_set().entries(self.iter()).finish()
  }
}

impl<T> Deref for OrderedSet<T> {
  type Target = [T];

  #[inline]
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl<T: KeyComparable> Default for OrderedSet<T> {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl<T: KeyComparable> FromIterator<T> for OrderedSet<T>
where
  T: KeyComparable,
{
  fn from_iter<I>(iter: I) -> Self
  where
    I: IntoIterator<Item = T>,
  {
    let iter = iter.into_iter();
    let size: usize = iter.size_hint().1.unwrap_or(0);

    let mut this: Self = Self::with_capacity(size);

    // Ignore duplicates.
    for item in iter {
      this.append(item);
    }

    this
  }
}

impl<T> TryFrom<Vec<T>> for OrderedSet<T>
where
  T: KeyComparable,
{
  type Error = Error;

  fn try_from(other: Vec<T>) -> Result<Self, Self::Error> {
    let mut this: Self = Self::with_capacity(other.len());

    for item in other {
      if !this.append(item) {
        return Err(Error::OrderedSetDuplicate);
      }
    }

    Ok(this)
  }
}

#[cfg(test)]
mod tests {
  use std::collections::HashSet;
  use std::hash::Hash;

  use super::*;
  use proptest::prelude::Rng;
  use proptest::strategy::Strategy;
  use proptest::test_runner::TestRng;
  use proptest::*;

  #[test]
  fn test_ordered_set_works() {
    let mut set = OrderedSet::new();

    set.append("a");
    set.append("b");
    set.append("c");

    assert_eq!(set.as_slice(), &["a", "b", "c"]);
    assert_eq!(set.head(), Some(&"a"));
    assert_eq!(set.tail(), Some(&"c"));

    set.replace(&"a", "c");

    assert_eq!(set.as_slice(), &["c", "b"]);

    let mut set = OrderedSet::new();

    set.prepend("a");
    set.prepend("b");
    set.prepend("c");

    assert_eq!(set.as_slice(), &["c", "b", "a"]);
    assert_eq!(set.head(), Some(&"c"));
    assert_eq!(set.tail(), Some(&"a"));

    set.replace(&"a", "c");

    assert_eq!(set.as_slice(), &["c", "b"]);
  }

  #[test]
  fn test_from_vec_valid() {
    let source: Vec<u8> = vec![3, 1, 2, 0];
    let set: OrderedSet<u8> = OrderedSet::try_from(source).unwrap();

    assert_eq!(&*set, &[3, 1, 2, 0]);
  }

  #[test]
  #[should_panic = "OrderedSetDuplicate"]
  fn test_from_vec_invalid() {
    let source: Vec<u8> = vec![1, 2, 2, 5];
    let _: OrderedSet<u8> = OrderedSet::try_from(source).unwrap();
  }

  #[test]
  fn test_collect() {
    let source: Vec<u8> = vec![1, 2, 3, 3, 2, 4, 5, 1, 1];
    let set: OrderedSet<u8> = source.into_iter().collect();

    assert_eq!(&*set, &[1, 2, 3, 4, 5]);
  }

  #[test]
  fn test_contains() {
    let cs1 = ComparableStruct { key: 0, value: 10 };
    let cs2 = ComparableStruct { key: 1, value: 20 };
    let cs3 = ComparableStruct { key: 2, value: 10 };
    let cs4 = ComparableStruct { key: 3, value: 20 };

    let source: Vec<ComparableStruct> = vec![cs1, cs2];
    let set: OrderedSet<ComparableStruct> = source.into_iter().collect();

    assert!(set.contains(&cs1));
    assert!(set.contains(&cs2));
    assert!(!set.contains(&cs3));
    assert!(!set.contains(&cs4));
  }

  #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
  struct ComparableStruct {
    key: u8,
    value: i32,
  }

  impl KeyComparable for ComparableStruct {
    type Key = u8;

    #[inline]
    fn key(&self) -> &Self::Key {
      &self.key
    }
  }

  #[test]
  fn test_ordered_set_replace() {
    let mut set = OrderedSet::new();

    // Create two structs with the same key.
    let cs1 = ComparableStruct { key: 0, value: 10 };
    let cs2 = ComparableStruct { key: 0, value: 20 };

    // Try replace it with the second.
    // This should succeed because the keys are equivalent.
    assert!(set.append(cs1));
    assert_eq!(set.len(), 1);

    assert!(set.replace(&cs1, cs2));
    assert_eq!(set.len(), 1);
    assert_eq!(set.head().unwrap().key, cs2.key);
    assert_eq!(set.head().unwrap().value, cs2.value);
  }

  #[test]
  fn test_ordered_set_replace_all() {
    let mut set = OrderedSet::new();
    let cs1 = ComparableStruct { key: 0, value: 10 };
    let cs2 = ComparableStruct { key: 1, value: 20 };
    assert!(set.append(cs1));
    assert!(set.append(cs2));
    assert_eq!(set.len(), 2);

    // Now replace cs1 with something that has the same key as cs2.
    // This should replace BOTH cs1 AND cs2.
    let cs3 = ComparableStruct { key: 1, value: 30 };
    assert!(set.replace(&cs1, cs3));
    assert_eq!(set.len(), 1);
    assert_eq!(set.head().unwrap().key, cs3.key);
    assert_eq!(set.head().unwrap().value, cs3.value);
  }

  #[test]
  fn test_ordered_set_update() {
    let mut set = OrderedSet::new();
    let cs1 = ComparableStruct { key: 0, value: 10 };
    assert!(set.append(cs1));
    assert_eq!(set.len(), 1);

    // This should update the value of cs1 since the keys are the same.
    let cs2 = ComparableStruct { key: 0, value: 20 };
    assert!(set.update(cs2));
    assert_eq!(set.len(), 1);
    assert_eq!(set.head().unwrap().key, cs2.key);
    assert_eq!(set.head().unwrap().value, cs2.value);

    // This should NOT update anything since the key does not match.
    let cs3 = ComparableStruct { key: 1, value: 20 };
    assert!(!set.update(cs3));
    assert_eq!(set.len(), 1);
    assert_eq!(set.head().unwrap().key, cs2.key);
    assert_eq!(set.head().unwrap().value, cs2.value);
  }

  // ===========================================================================================================================
  // Test key uniqueness invariant with randomly generated input
  // ===========================================================================================================================

  /// Produce a strategy for generating a pair of ordered sets of ComparableStruct
  fn arbitrary_sets_comparable_struct(
  ) -> impl Strategy<Value = (OrderedSet<ComparableStruct>, OrderedSet<ComparableStruct>)> {
    proptest::arbitrary::any::<Vec<(u8, i32)>>().prop_map(|mut x_vec| {
      let half = x_vec.len() / 2;
      let y_vec = x_vec.split_off(half);
      let mapper = |(key, value)| ComparableStruct { key, value };
      (
        x_vec.into_iter().map(mapper).collect(),
        y_vec.into_iter().map(mapper).collect(),
      )
    })
  }

  /// Produce a strategy for generating a pair of ordered sets of u128
  fn arbitrary_sets_u128() -> impl Strategy<Value = (OrderedSet<u128>, OrderedSet<u128>)> {
    proptest::arbitrary::any::<Vec<u128>>().prop_map(|mut x_vec| {
      let half = x_vec.len() / 2;
      let y_vec = x_vec.split_off(half);
      (x_vec.into_iter().collect(), y_vec.into_iter().collect())
    })
  }

  /// Trait for replacing the key of a KeyComparable value
  trait ReplaceKey: KeyComparable {
    fn set_key(&mut self, key: Self::Key);
  }

  impl ReplaceKey for ComparableStruct {
    fn set_key(&mut self, key: Self::Key) {
      let ComparableStruct { key: current_key, .. } = self;
      *current_key = key;
    }
  }

  impl ReplaceKey for u128 {
    fn set_key(&mut self, key: Self::Key) {
      *self = key;
    }
  }

  /// Produces a strategy for generating an ordered set together with two values according to the following algorithm:
  /// 1. Call `f` to get a pair of sets (x,y).
  /// 2. Toss a coin to decide whether to pick an element from x at random, or from y (if the chosen set is empty
  ///    Default is called). 3. Repeat step 2 and let the two outcomes be denoted a and b.
  /// 4. Toss a coin to decide whether to swap the keys of a and b.
  /// 5. return (x,a,b)
  fn set_with_values<F, T, U>(f: F) -> impl Strategy<Value = (OrderedSet<T>, T, T)>
  where
    T: KeyComparable + Default + Debug + Clone + ReplaceKey,
    <T as KeyComparable>::Key: Clone,
    U: Strategy<Value = (OrderedSet<T>, OrderedSet<T>)>,
    F: Fn() -> U,
  {
    f().prop_perturb(|(x, y), mut rng| {
      let sets = [&x, &y];

      let sample = |generator: &mut TestRng| {
        let set_idx = usize::from(generator.random_bool(0.5));
        let set_range = if set_idx == 0 { 0..x.len() } else { 0..y.len() };
        if set_range.is_empty() {
          T::default()
        } else {
          let entry_idx = generator.random_range(set_range);
          (sets[set_idx])[entry_idx].clone()
        }
      };

      let (mut a, mut b) = (sample(&mut rng), sample(&mut rng));
      if rng.random_bool(0.5) {
        let key_a = a.key().clone();
        let key_b = b.key().clone();
        a.set_key(key_b);
        b.set_key(key_a);
      }

      (x, a, b)
    })
  }

  fn set_with_values_comparable_struct(
  ) -> impl Strategy<Value = (OrderedSet<ComparableStruct>, ComparableStruct, ComparableStruct)> {
    set_with_values(arbitrary_sets_comparable_struct)
  }

  fn set_with_values_u128() -> impl Strategy<Value = (OrderedSet<u128>, u128, u128)> {
    set_with_values(arbitrary_sets_u128)
  }

  fn assert_operation_preserves_invariant<F, T, S>(mut set: OrderedSet<T>, operation: F, val: T)
  where
    T: KeyComparable,
    T::Key: Hash + Eq,
    F: Fn(&mut OrderedSet<T>, T) -> S,
  {
    operation(&mut set, val);
    assert_unique_keys(set);
  }

  fn assert_unique_keys<T>(set: OrderedSet<T>)
  where
    T: KeyComparable,
    T::Key: Hash + Eq,
  {
    let mut keys: HashSet<&T::Key> = HashSet::new();
    for key in set.as_slice().iter().map(KeyComparable::key) {
      assert!(keys.insert(key));
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_append_comparable_struct((set, element, _) in set_with_values_comparable_struct()) {
      assert_operation_preserves_invariant(set,OrderedSet::append, element);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_append_u128((set, element, _) in set_with_values_u128()) {
      assert_operation_preserves_invariant(set,OrderedSet::append, element);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_prepend_comparable_struct((set, element, _) in set_with_values_comparable_struct()) {
      assert_operation_preserves_invariant(set,OrderedSet::prepend, element);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_prepend_u128((set, element, _) in set_with_values_u128()) {
      assert_operation_preserves_invariant(set,OrderedSet::prepend, element);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_update_comparable_struct((set, element, _) in set_with_values_comparable_struct()) {
      assert_operation_preserves_invariant(set,OrderedSet::update, element);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_update_u128((set, element, _) in set_with_values_u128()) {
      assert_operation_preserves_invariant(set,OrderedSet::update, element);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_replace_comparable_struct((mut set, current, update) in set_with_values_comparable_struct()) {
      set.replace(current.key(), update);
      assert_unique_keys(set);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_replace_u128((mut set, current, update) in set_with_values_u128()) {
      set.replace(current.key(), update);
      assert_unique_keys(set);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_remove_u128((mut set, element, _) in set_with_values_u128()) {
      set.remove(element.key());
      assert_unique_keys(set);
    }
  }

  proptest! {
    #[test]
    fn preserves_invariant_remove_comparable_struct((mut set, element, _) in set_with_values_comparable_struct()) {
      set.remove(element.key());
      assert_unique_keys(set);
    }
  }
}
