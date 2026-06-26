// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::rebased::client::IdentityClientReadOnly;
use crate::Error;
use crate::IotaDID;
use crate::IotaDocument;
use crate::Result;

/// An extension trait that provides helper functions for publication
/// and resolution of DID documents in identities.
///
/// This trait is not intended to be implemented directly, a blanket implementation is
/// provided for [`IotaIdentityClient`] implementers.
#[cfg_attr(feature = "send-sync-client-ext", async_trait::async_trait)]
#[cfg_attr(not(feature = "send-sync-client-ext"), async_trait::async_trait(?Send))]
pub trait DidResolutionHandler {
  /// Resolve a [`IotaDocument`]. Returns an empty, deactivated document if the state metadata
  /// of the identity is empty.
  ///
  /// # Errors
  ///
  /// - [`DID resolution failed`](Error::DIDResolutionError) if the DID could not be resolved.
  async fn resolve_did(&self, did: &IotaDID) -> Result<IotaDocument>;
}

#[cfg_attr(feature = "send-sync-client-ext", async_trait::async_trait)]
#[cfg_attr(not(feature = "send-sync-client-ext"), async_trait::async_trait(?Send))]
impl DidResolutionHandler for IdentityClientReadOnly {
  async fn resolve_did(&self, did: &IotaDID) -> Result<IotaDocument> {
    self
      .resolve_did(did)
      .await
      .map_err(|err| Error::DIDResolutionError(err.to_string()))
  }
}
