// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::actor::Endpoint;

use libp2p::PeerId;

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RequestContext<T> {
  pub input: T,
  pub peer: PeerId,
  pub endpoint: Endpoint,
}

impl<T> RequestContext<T> {
  pub(crate) fn new(input: T, peer: PeerId, endpoint: Endpoint) -> Self {
    Self { input, peer, endpoint }
  }

  pub(crate) fn convert<I>(self, input: I) -> RequestContext<I> {
    RequestContext::new(input, self.peer, self.endpoint)
  }
}
