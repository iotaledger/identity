#!/bin/bash

# Copyright 2020-2024 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

script_dir=$(cd "$(dirname $0)" && pwd)
package_dir=$script_dir/../packages/iota_identity

# echo "publishing package from $package_dir"
RESPONSE=$(iota client publish --with-unpublished-dependencies --silence-warnings --json --gas-budget 500000000 $package_dir)
{ # try
  PACKAGE_ID=$(echo $RESPONSE | jq --raw-output '.objectChanges[] | select(.type | contains("published")) | .packageId')
} || { # catch
  echo $RESPONSE
}

export IOTA_IDENTITY_PKG_ID=$PACKAGE_ID
echo "${IOTA_IDENTITY_PKG_ID}"
