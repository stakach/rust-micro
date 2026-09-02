#!/usr/bin/env bash
# Cross-check the kernel core for the initial bare-metal AArch64 target.
set -euo pipefail

cd "$(dirname "$0")/.."

cargo +nightly check \
  -Z build-std=core \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplets/mykernel-aarch64.json \
  --no-default-features \
  --features arch-aarch64 "$@"
