// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use identity_core::convert::Base;
use identity_core::convert::BaseEncoding;
use std::io::Write;
use thiserror::Error;

const MINIMUM_LIST_SIZE: usize = 16 * 1024 * 8;

/// [`std::error::Error`] type for [`StatusList2021`]'s operations.
#[derive(Debug, Error, PartialEq, Eq, Clone, strum::IntoStaticStr)]
pub enum StatusListError {
  /// Requested entry is not in the list.
  #[error("The requested entry is not in the list.")]
  IndexOutOfBounds,
  /// Improperly encoded status list.
  #[error("\"{0}\" is not a valid encoded status list.")]
  InvalidEncoding(String),
  /// Invalid list size
  #[error("A StatusList2021 must have at least {MINIMUM_LIST_SIZE} entries.")]
  InvalidListSize,
}

/// StatusList2021 data structure as described in [W3C's VC status list 2021](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct StatusList2021(Box<[u8]>);

impl Default for StatusList2021 {
  fn default() -> Self {
    StatusList2021::new(MINIMUM_LIST_SIZE).unwrap()
  }
}

impl StatusList2021 {
  /// Returns a new zero-filled [`StatusList2021`] that can hold `num_entries` credential statuses.
  ///
  /// ## Notes:
  /// - The actual length of the list will be rounded up to the closest multiple of 8 to accommodate for byte sizes.
  /// - `num_entries` must be at least 131,072 which corresponds to a size of 16KB.
  pub fn new(num_entries: usize) -> Result<Self, StatusListError> {
    if num_entries < MINIMUM_LIST_SIZE {
      return Err(StatusListError::InvalidListSize);
    }

    let size = num_entries / 8 + (!num_entries.is_multiple_of(8) as usize);
    let store = vec![0; size];

    Ok(StatusList2021(store.into_boxed_slice()))
  }

  /// Returns the number of entries.
  #[allow(clippy::len_without_is_empty)]
  pub const fn len(&self) -> usize {
    self.0.len() * 8
  }

  /// Returns the status of the entry at `index` without bound checking.
  /// ## Panic:
  /// * if `index` is greater than or equal to `self.len()`.
  const fn get_unchecked(&self, index: usize) -> bool {
    let (i, offset) = Self::entry_index_to_store_index(index);
    self.0[i] & (0b1000_0000 >> offset) != 0
  }

  /// Sets the status of the `index`-th entry to `value`.
  ///
  /// ## Panic:
  /// * if `index` is greater than or equal to `self.len()`.
  fn set_unchecked(&mut self, index: usize, value: bool) {
    let (i, offset) = Self::entry_index_to_store_index(index);
    if value {
      self.0[i] |= 0b1000_0000 >> offset
    } else {
      self.0[i] &= 0b0111_1111 >> offset
    }
  }

  /// Returns the status of the `index`-th entry, if it exists.
  pub fn get(&self, index: usize) -> Result<bool, StatusListError> {
    (index < self.len())
      .then_some(self.get_unchecked(index))
      .ok_or(StatusListError::IndexOutOfBounds)
  }

  /// Sets the status of the `index`-th entry to `value`.
  pub fn set(&mut self, index: usize, value: bool) -> Result<(), StatusListError> {
    if index < self.len() {
      self.set_unchecked(index, value);
      Ok(())
    } else {
      Err(StatusListError::IndexOutOfBounds)
    }
  }

  /// Attempts to parse a [`StatusList2021`] from a string, following the
  /// [StatusList2021 expansion algorithm](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#bitstring-expansion-algorithm).
  pub fn try_from_encoded_str(s: &str) -> Result<Self, StatusListError> {
    let compressed_status_list =
      BaseEncoding::decode(s, Base::Base64).or(Err(StatusListError::InvalidEncoding(s.to_owned())))?;
    let status_list = {
      use std::io::Read;

      let mut decompressor = GzDecoder::new(&compressed_status_list[..]);
      let mut status_list = vec![];
      decompressor
        .read_to_end(&mut status_list)
        .or(Err(StatusListError::InvalidEncoding(s.to_owned())))?;

      StatusList2021(status_list.into_boxed_slice())
    };

    Ok(status_list)
  }

  /// Encode this [`StatusList2021`] into its string representation following
  /// [StatusList2021 generation algorithm](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#bitstring-generation-algorithm).
  pub fn into_encoded_str(self) -> String {
    let compressed_status_list = {
      let mut compressor = GzEncoder::new(vec![], Compression::best());
      compressor.write_all(&self.0).unwrap();
      compressor.finish().unwrap()
    };

    BaseEncoding::encode(&compressed_status_list[..], Base::Base64)
  }

  /// Returns the byte location and the bit location within it.
  const fn entry_index_to_store_index(index: usize) -> (usize, usize) {
    (index / 8, index % 8)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_status_list() {
    let mut status_list = StatusList2021::default();
    status_list.set(131071, true).unwrap();
    assert!(status_list.get(131071).unwrap());
    assert_eq!(status_list.set(131072, true), Err(StatusListError::IndexOutOfBounds));
  }

  #[test]
  fn status_list_too_short_fails() {
    assert_eq!(StatusList2021::new(100), Err(StatusListError::InvalidListSize));
  }

  #[test]
  fn status_list_entry_access() {
    let mut status_list = StatusList2021::default();
    status_list.set(42, true).unwrap();
    assert!(status_list.get(42).unwrap());

    status_list.set(42, false).unwrap();
    assert_eq!(status_list, StatusList2021::default());
  }

  #[test]
  fn status_list_encode_decode() {
    let mut status_list = StatusList2021::default();
    status_list.set(42, true).unwrap();
    status_list.set(420, true).unwrap();
    status_list.set(4200, true).unwrap();
    let encoded = status_list.clone().into_encoded_str();
    let decoded = StatusList2021::try_from_encoded_str(&encoded).unwrap();
    assert_eq!(decoded, status_list);
  }
}
