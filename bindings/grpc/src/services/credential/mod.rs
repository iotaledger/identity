// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod jwt;
pub mod revocation;
pub mod validation;

use identity_stronghold::StrongholdStorage;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use tonic::service::RoutesBuilder;

pub fn init_services(routes: &mut RoutesBuilder, client: &IdentityClientReadOnly, stronghold: &StrongholdStorage) {
  routes.add_service(revocation::service(client));
  routes.add_service(jwt::service(client, stronghold));
  routes.add_service(validation::service(client));
}
