#!/bin/sh
cd ..

API_ENDPOINT=replace_me \
STRONGHOLD_PWD=replace_me \
SNAPSHOT_PATH=replace_me \
cargo +nightly run --release
