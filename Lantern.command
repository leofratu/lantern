#!/bin/sh
set -eu
cd -- "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -x target/aarch64-apple-darwin/release/lantern ]; then
  exec target/aarch64-apple-darwin/release/lantern
fi
if [ -x target/release/lantern ]; then
  exec target/release/lantern
fi
exec cargo run --release --locked
