// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod credential;
pub mod document;
pub mod domain_linkage;
pub mod health_check;
pub mod sd_jwt;
pub mod status_list_2021;
pub mod utils;

use identity_stronghold::StrongholdStorage;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use tonic::service::Routes;
use tonic::service::RoutesBuilder;

pub fn routes(client: &IdentityClientReadOnly, stronghold: &StrongholdStorage) -> Routes {
  let mut routes = RoutesBuilder::default();
  routes.add_service(health_check::service());
  credential::init_services(&mut routes, client, stronghold);
  routes.add_service(sd_jwt::service(client));
  routes.add_service(domain_linkage::service(client));
  routes.add_service(document::service(client, stronghold));
  routes.add_service(status_list_2021::service());
  routes.add_service(utils::service(stronghold));

  routes.routes()
}
