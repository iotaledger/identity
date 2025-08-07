use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;

const PACKAGE_REGISTRY_FILE: &str = "src/rebased/iota/package_registry.rs";
const MOVE_LOCK_PATH: &str = "packages/iota_identity/Move.lock";

#[derive(Debug, Serialize, Deserialize)]
struct Env {
  id: String,
  alias: String,
  packages: Vec<String>,
}

fn read_history() -> anyhow::Result<[Env; 3]> {
  let registy_src_content = std::fs::read_to_string(PACKAGE_REGISTRY_FILE)?;
  let registry_json_str = {
    let start_of_comment = registy_src_content
      .find("/*")
      .context("cannot find start of comment containing JSON history")?;
    let end_of_comment = registy_src_content
      .find("*/")
      .context("cannot find end of coment containing JSON history")?;
    // The part of the source file inside /*  */
    let comment_section = &registy_src_content[start_of_comment + 2..end_of_comment];
    comment_section.trim_ascii()
  };

  serde_json::from_str(registry_json_str).context("failed to parse JSON history")
}

fn read_lock_file() -> anyhow::Result<[String; 3]> {
  let lock_table = {
    let lock_file_content = std::fs::read_to_string(MOVE_LOCK_PATH)?;
    lock_file_content.parse::<toml::Table>()?
  };

  let env_table = lock_table
    .get("env")
    .and_then(toml::Value::as_table)
    .context("malformed Move.lock: missing or malformed `env` table")?;

  let mut latest_packages: [String; 3] = Default::default();
  for (i, network) in ["mainnet", "testnet", "devnet"].into_iter().enumerate() {
    latest_packages[i] = env_table
      .get(network)
      .and_then(toml::Value::as_table)
      .and_then(|table| table.get("latest-published-id"))
      .and_then(toml::Value::as_str)
      .context(format!(
        "malformed Move.lock: failed to read property `latest-published-id` of table `env.{network}`"
      ))?
      .to_owned();
  }

  Ok(latest_packages)
}

fn write_history(history: [Env; 3]) -> anyhow::Result<()> {
  use std::io::Write as _;

  let mut history_file = std::fs::File::create(PACKAGE_REGISTRY_FILE)?;
  writeln!(&mut history_file, "// Copyright 2020-2025 IOTA Stiftung")?;
  writeln!(&mut history_file, "// SPDX-License-Identifier: Apache-2.0\n")?;

  writeln!(&mut history_file, "/*\n{}\n*/", serde_json::to_string_pretty(&history)?)?;

  writeln!(
    &mut history_file,
    "
use iota_interaction::types::base_types::ObjectID;
use std::sync::LazyLock;
use tokio::sync::RwLock;

use super::package::Env;
use super::package::PackageRegistry;

#[rustfmt::skip]
pub(crate) static IOTA_IDENTITY_PACKAGE_REGISTRY: LazyLock<RwLock<PackageRegistry>> = LazyLock::new(|| {{
  RwLock::new({{
    let mut registry = PackageRegistry::default();"
  )?;
  for env in history {
    writeln!(
      &mut history_file,
      "
    registry.insert_env(
      Env::new_with_alias(\"{}\", \"{}\"),
      vec![",
      env.id, env.alias
    )?;
    for pkg in env.packages {
      writeln!(
        &mut history_file,
        "        ObjectID::from_hex_literal(\"{}\").unwrap(),",
        pkg
      )?;
    }
    write!(&mut history_file, "      ],\n    );")?;
  }
  writeln!(
    &mut history_file,
    "
    registry
  }})
}});"
  )?;

  Ok(())
}

fn main() -> anyhow::Result<()> {
  let mut history = read_history()?;
  let latest = read_lock_file()?;

  for (latest_id, history) in latest.iter().zip(history.iter_mut()) {
    if history.packages.last().unwrap() == latest_id {
      continue;
    }

    history.packages.push(latest_id.clone());
  }

  write_history(history)?;

  println!("cargo::rerun-if-changed=packages/iota_identity/Move.lock");

  Ok(())
}
