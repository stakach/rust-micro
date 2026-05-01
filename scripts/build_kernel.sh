#!/usr/bin/env bash
# build_kernel.sh — compile the kernel and produce a bootable disk image.
#
# Usage:
#   ./scripts/build_kernel.sh                  # builds with the `spec` feature
#   ./scripts/build_kernel.sh paging           # extra features get appended
set -euo pipefail

cd "$(dirname "$0")/.."

# Default features always include `spec` so kernel specs run inside QEMU.
FEATURES="spec"
if [ $# -gt 0 ]; then
  FEATURES="$FEATURES,$*"
fi

# Sanity-check the toolchain. rustup is the supported install path on macOS.
if ! command -v cargo >/dev/null 2>&1; then
  cat <<'EOF' >&2
error: cargo is not on PATH.

Install rustup + the nightly toolchain (with rust-src for build-std):
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
       --default-toolchain nightly --component rust-src
  . "$HOME/.cargo/env"
EOF
  exit 1
fi

# `rust-src` is required by `-Z build-std=core` because we are building core
# from source against a custom bare-metal target.
if ! rustup +nightly component list --installed 2>/dev/null | grep -q '^rust-src'; then
  echo "installing nightly rust-src component..."
  rustup +nightly component add rust-src
fi

# Phase 29a — the kernel embeds the rootserver ELF via
# include_bytes!. Build the rootserver first so the ELF exists at
# include_bytes! resolution time.
(
  cd rootserver
  cargo +nightly build \
    -Z build-std=core \
    -Z unstable-options \
    -Z json-target-spec \
    --target triplet.json \
    --release
)
echo "rootserver built: rootserver/target/triplet/release/rootserver"

cargo +nightly build \
  -Z build-std=core \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplets/mykernel-x86.json \
  --release \
  --features "$FEATURES"

KERNEL_BIN="target/mykernel-x86/release/mykernel-rust"
echo "kernel built: $KERNEL_BIN"

./scripts/make_image.sh
