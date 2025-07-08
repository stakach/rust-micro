#!/bin/bash
set -euxo pipefail

# Default features
FEATURES="spec"

# Append any additional features passed as arguments
if [ $# -gt 0 ]; then
  FEATURES="$FEATURES,$*"
fi

cargo +nightly build -Z build-std=core \
      --target triplets/mykernel-x86.json \
      --release --features "$FEATURES"

echo "Kernel built: target/mykernel-x86/release/mykernel-rust"
