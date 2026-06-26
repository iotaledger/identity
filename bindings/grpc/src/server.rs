// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use identity_stronghold::StrongholdStorage;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use tonic::transport::server::Router;
use tonic::transport::server::Server;

use crate::services;

#[derive(Debug)]
pub struct GRpcServer {
  router: Router,
  stronghold: StrongholdStorage,
}

impl GRpcServer {
  pub fn new(client: IdentityClientReadOnly, stronghold: StrongholdStorage) -> Self {
    let router = Server::builder().add_routes(services::routes(&client, &stronghold));
    Self { router, stronghold }
  }
  pub async fn serve(self, addr: SocketAddr) -> Result<(), tonic::transport::Error> {
    self.router.serve(addr).await
  }
  pub fn into_router(self) -> Router {
    self.router
  }
  pub fn stronghold(&self) -> StrongholdStorage {
    self.stronghold.clone()
  }
}
