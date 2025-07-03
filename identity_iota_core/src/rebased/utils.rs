// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::process::Output;

use anyhow::Context as _;
use iota_interaction::types::base_types::ObjectID;
use iota_sdk::IotaClient;
use iota_sdk::IotaClientBuilder;
use serde::Deserialize;
#[cfg(not(target_arch = "wasm32"))]
use tokio::process::Command;

use crate::rebased::Error;
use iota_interaction::types::base_types::IotaAddress;

const FUND_WITH_ACTIVE_ADDRESS_FUNDING_TX_BUDGET: u64 = 5_000_000;
const FUND_WITH_ACTIVE_ADDRESS_FUNDING_VALUE: u64 = 500_000_000;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CoinOutput {
  gas_coin_id: ObjectID,
  nanos_balance: u64,
}

/// Builds an `IOTA` client for the given network.
pub async fn get_client(network: &str) -> Result<IotaClient, Error> {
  let client = IotaClientBuilder::default()
    .build(network)
    .await
    .map_err(|err| Error::Network(format!("failed to connect to {network}"), err))?;

  Ok(client)
}

fn unpack_command_output(output: &Output, task: &str) -> anyhow::Result<String> {
  let stdout = std::str::from_utf8(&output.stdout)?;
  if !output.status.success() {
    let stderr = std::str::from_utf8(&output.stderr)?;
    anyhow::bail!("Failed to {task}: {stdout}, {stderr}");
  }

  Ok(stdout.to_string())
}

/// Requests funds from the local IOTA client's configured faucet.
///
/// This behavior can be changed to send funds with local IOTA client's active address to the given address.
/// For that the env variable `IOTA_IDENTITY_FUND_WITH_ACTIVE_ADDRESS` must be set to `true`.
/// Notice, that this is a setting mostly intended for internal test use and must be used with care.
/// For details refer to `identity_iota_core`'s README.md.
#[cfg(not(target_arch = "wasm32"))]
pub async fn request_funds(address: &IotaAddress) -> anyhow::Result<()> {
  let fund_with_active_address = std::env::var("IOTA_IDENTITY_FUND_WITH_ACTIVE_ADDRESS")
    .map(|v| !v.is_empty() && v.to_lowercase() == "true")
    .unwrap_or(false);

  if !fund_with_active_address {
    let output = Command::new("iota")
      .arg("client")
      .arg("faucet")
      .arg("--address")
      .arg(address.to_string())
      .arg("--json")
      .output()
      .await
      .context("Failed to execute command")?;
    unpack_command_output(&output, "request funds from faucet")?;
  } else {
    let output = Command::new("iota")
      .arg("client")
      .arg("gas")
      .arg("--json")
      .output()
      .await
      .context("Failed to execute command")?;
    let output_str = unpack_command_output(&output, "fetch active account's gas coins")?;

    let parsed: Vec<CoinOutput> = serde_json::from_str(&output_str)?;
    let min_balance = FUND_WITH_ACTIVE_ADDRESS_FUNDING_VALUE + FUND_WITH_ACTIVE_ADDRESS_FUNDING_TX_BUDGET;
    let matching = parsed.into_iter().find(|coin| coin.nanos_balance >= min_balance);
    let Some(coin_to_use) = matching else {
      anyhow::bail!("Failed to find coin object with enough funds to transfer to test account");
    };

    let address_string = address.to_string();
    let output = Command::new("iota")
      .arg("client")
      .arg("pay-iota")
      .arg("--recipients")
      .arg(&address_string)
      .arg("--input-coins")
      .arg(coin_to_use.gas_coin_id.to_string())
      .arg("--amounts")
      .arg(FUND_WITH_ACTIVE_ADDRESS_FUNDING_VALUE.to_string())
      .arg("--gas-budget")
      .arg(FUND_WITH_ACTIVE_ADDRESS_FUNDING_TX_BUDGET.to_string())
      .arg("--json")
      .output()
      .await
      .context("Failed to execute command")?;
    unpack_command_output(&output, &format!("send funds from active account to {address_string}"))?;
  }

  Ok(())
}
