#!/bin/bash

# Copyright 2020-2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

script_dir=$(cd "$(dirname $0)" && pwd)
package_dir=$script_dir/../packages/iota_identity

chain_id=$(iota client chain-identifier)
current_pkg_id=$(toml get "$package_dir/Move.lock" env | jq --raw-output "map(values | select(.[\"chain-id\"] == \"$chain_id\") .[\"latest-published-id\"]) | first")
upgrade_cap_id=$(iota client objects --json | jq --raw-output "map(select(.data.type == \"0x2::package::UpgradeCap\" and .data.content.fields.package == \"$current_pkg_id\")) | first | .data.objectId")

iota client upgrade --upgrade-capability $upgrade_cap_id $package_dir
