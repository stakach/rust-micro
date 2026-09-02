#!/usr/bin/env bash
# Build and run generic plus AArch64 kernel specs on QEMU virt/GICv2.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
  echo "error: qemu-system-aarch64 is not on PATH" >&2
  exit 1
fi

./scripts/build_aarch64.sh spec smp
./scripts/make_aarch64_simpleboot.sh

exec qemu-system-aarch64 \
  -machine virt,secure=off,gic-version=2 \
  -cpu cortex-a53 \
  -m "${QEMU_MEMORY:-1024M}" \
  -smp 4 \
  -nographic \
  -semihosting-config enable=on,target=native \
  -kernel .tmp/aarch64-simpleboot/simpleboot-aarch64.img \
  -initrd .tmp/aarch64-simpleboot/initrd.tar \
  "$@"
