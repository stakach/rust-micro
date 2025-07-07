#!/bin/bash
set -euxo pipefail

cargo +nightly build -Z build-std=core \
      --target triplets/mykernel-x86.json \
      --release --features spec

echo "Kernel built: target/mykernel-x86/release/mykernel-rust"
