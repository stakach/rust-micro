#!/usr/bin/env bash
# run_specs.sh — boot the disk image in QEMU with serial-on-stdio and exit
# via the isa-debug-exit device once the spec runner finishes.
#
# Pass `--debug` to dump interrupts and CPU resets (useful for triple-fault
# investigations).
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 not on PATH (brew install qemu / apt install qemu-system-x86)" >&2
  exit 1
fi

# Locate UEFI firmware. Homebrew's qemu ships edk2 firmware; on Linux
# distributions OVMF lives under /usr/share. Check the well-known paths and
# fall back to letting the user override via $OVMF.
OVMF="${OVMF:-}"
if [ -z "$OVMF" ]; then
  for candidate in \
      "$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-x86_64-code.fd" \
      /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
      /usr/local/share/qemu/edk2-x86_64-code.fd \
      /usr/share/OVMF/OVMF_CODE.fd \
      /usr/share/edk2-ovmf/OVMF_CODE.fd \
      /usr/share/qemu/OVMF.fd; do
    [ -n "$candidate" ] && [ -f "$candidate" ] || continue
    OVMF="$candidate"
    break
  done
fi
if [ -z "$OVMF" ] || [ ! -f "$OVMF" ]; then
  echo "error: could not locate UEFI firmware. Set OVMF=/path/to/code.fd" >&2
  exit 1
fi

IMAGE=.tmp/disk.img
if [ ! -f "$IMAGE" ]; then
  echo "error: $IMAGE missing — run scripts/build_kernel.sh first" >&2
  exit 1
fi

DEBUG_FLAGS=()
if [ "${1:-}" = "--debug" ]; then
  DEBUG_FLAGS=(-d int,cpu_reset -no-reboot -no-shutdown)
  shift
fi

# isa-debug-exit at iobase 0x501 turns OUT-port writes from the kernel into
# QEMU exit codes (`out 0x501, n` -> qemu exits with (n<<1)|1). The kernel
# uses this to signal "specs passed" (0) or "panic" (255).
#
# The firmware is loaded as pflash rather than via -bios because the EDK2
# images shipped with Homebrew QEMU aren't padded to the 4 MiB size that
# the legacy -bios path requires.
exec qemu-system-x86_64 \
  -drive format=raw,file="$IMAGE" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF" \
  -serial stdio \
  -monitor none \
  -nographic \
  -no-reboot \
  -device isa-debug-exit,iobase=0x501,iosize=0x2 \
  "${DEBUG_FLAGS[@]}" \
  "$@"
