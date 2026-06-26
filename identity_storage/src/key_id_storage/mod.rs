// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A Key ID Storage is used to store the identifiers of keys
//! that were generated in a Key Storage.
//!
//! This module provides the [`KeyIdStorage`] trait that
//! stores the mapping from a method, identified by a [`MethodDigest`],
//! to its [`KeyId`](crate::key_storage::KeyId).

#[allow(clippy::module_inception)]
mod key_id_storage;
mod key_id_storage_error;
mod method_digest;

#[cfg(feature = "keytool")]
mod keytool;
#[cfg(feature = "memstore")]
mod memstore;

#[cfg(test)]
mod tests;

pub use key_id_storage::*;
pub use key_id_storage_error::*;
#[cfg(feature = "memstore")]
pub use memstore::*;
pub use method_digest::*;
