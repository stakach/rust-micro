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

# Phase 39 — the rootserver is now delivered to the kernel at
# runtime via the BOOTBOOT initrd (a USTAR tar archive packed by
# scripts/make_image.sh), not embedded via include_bytes!. Building
# the rootserver no longer triggers a kernel rebuild — it just
# stages a fresh ELF at .tmp/rootserver.elf for make_image.sh to
# bundle into the archive.
#
# Phase 34a: the `microtest` cargo feature on the kernel propagates
# to the rootserver crate so its `_start` runs the structured test
# harness instead of the legacy demos.
#
# Phase 38d: the `libsel4-hello` cargo feature swaps the chosen
# rootserver ELF to vendor/libsel4-build/out/hello.elf — a C
# program built against upstream libsel4. Validates the SYSCALL
# ABI end-to-end against the real upstream toolchain.
mkdir -p .tmp
if [[ ",${FEATURES}," == *",libsel4-hello,"* ]]; then
  ./vendor/libsel4-build/build.sh
  cp vendor/libsel4-build/out/hello.elf .tmp/rootserver.elf
  echo "rootserver staged: .tmp/rootserver.elf (libsel4 hello.elf)"
else
  ROOTSERVER_FEATURES=""
  if [[ ",${FEATURES}," == *",microtest,"* ]]; then
    ROOTSERVER_FEATURES="microtest"
  fi
  (
    cd rootserver
    cargo +nightly build \
      -Z build-std=core \
      -Z unstable-options \
      -Z json-target-spec \
      --target triplet.json \
      --release \
      ${ROOTSERVER_FEATURES:+--features "$ROOTSERVER_FEATURES"}
  )
  cp rootserver/target/triplet/release/rootserver .tmp/rootserver.elf
  echo "rootserver staged: .tmp/rootserver.elf (Rust rootserver)"
fi

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
