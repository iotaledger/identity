// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _health_check::health_check_client::HealthCheckClient;
use _health_check::HealthCheckRequest;
use _health_check::HealthCheckResponse;

use crate::helpers::TestServer;

mod _health_check {
  tonic::include_proto!("health_check");
}

#[tokio::test]
async fn health_check() -> anyhow::Result<()> {
  let server = TestServer::new().await;
  let mut grpc_client = HealthCheckClient::connect(server.endpoint()).await?;
  let request = tonic::Request::new(HealthCheckRequest {});

  let response = grpc_client.check(request).await?;
  assert_eq!(response.into_inner(), HealthCheckResponse { status: "OK".into() });

  Ok(())
}
