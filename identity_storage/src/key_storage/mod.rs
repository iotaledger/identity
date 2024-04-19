// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A Key Storage is used to securely store private keys.
//!
//! This module provides the [`JwkStorage`] trait that
//! abstracts over storages that store JSON Web Keys.

#[cfg(all(feature = "memstore", feature = "jpt-bbs-plus"))]
mod bls;
#[cfg(feature = "memstore")]
mod ed25519;
mod jwk_gen_output;
mod jwk_storage;
#[cfg(feature = "jpt-bbs-plus")]
mod jwk_storage_bbs_plus_ext;
mod key_id;
mod key_storage_error;
mod key_type;
#[cfg(feature = "memstore")]
mod memstore;

#[cfg(test)]
pub(crate) mod tests;

pub use jwk_gen_output::*;
pub use jwk_storage::*;
#[cfg(feature = "jpt-bbs-plus")]
pub use jwk_storage_bbs_plus_ext::*;
pub use key_id::*;
pub use key_storage_error::*;
pub use key_type::*;
#[cfg(feature = "memstore")]
pub use memstore::*;
