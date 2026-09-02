#!/usr/bin/env bash
# Build a QEMU-bootable AArch64 Linux Image while retaining the ELF for symbols.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! rustup +nightly component list --installed 2>/dev/null | grep -q '^rust-src'; then
  rustup +nightly component add rust-src
fi
if ! rustup +nightly component list --installed 2>/dev/null | grep -q '^llvm-tools'; then
  rustup +nightly component add llvm-tools-preview
fi

features=(arch-aarch64)
if [ "$#" -eq 0 ]; then
  features+=(spec smp)
else
  features+=("$@")
fi
feature_list="$(IFS=,; echo "${features[*]}")"

cargo +nightly build \
  -Z build-std=core \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplets/mykernel-aarch64.json \
  --release \
  --no-default-features \
  --features "$feature_list"

elf=target/mykernel-aarch64/release/mykernel-rust
image=target/mykernel-aarch64/release/Image
host="$(rustc +nightly -vV | sed -n 's/^host: //p')"
objcopy="$(rustc +nightly --print sysroot)/lib/rustlib/$host/bin/llvm-objcopy"
"$objcopy" -O binary "$elf" "$image"

echo "AArch64 ELF:   $elf"
echo "AArch64 Image: $image"
