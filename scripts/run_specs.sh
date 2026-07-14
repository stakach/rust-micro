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
# GRAPHICS=1 (or the `--display`/`--graphics` flag) boots with a real QEMU
# display WINDOW instead of the headless `-nographic` gate, so you can SEE the
# BOOTBOOT GOP framebuffer that win32k paints (the ReactOS desktop background).
# Default stays headless so the CI/spec gate is unchanged.
GRAPHICS="${GRAPHICS:-0}"
while [ $# -gt 0 ]; do
  case "$1" in
    --debug)
      DEBUG_FLAGS=(-d int,cpu_reset -no-reboot -no-shutdown)
      shift
      ;;
    --display|--graphics|--desktop)
      GRAPHICS=1
      shift
      ;;
    *)
      break
      ;;
  esac
done

# Display vs headless. In graphics mode we (a) select a real display backend,
# (b) keep a std VGA so OVMF's GOP framebuffer is shown, (c) keep -serial stdio
# for the log, and (d) DROP the isa-debug-exit device so the kernel's final
# `out 0x501` exit-write becomes a harmless no-op (the kernel then spins in
# `loop {}`) — this leaves QEMU alive with the painted desktop on screen until
# you close the window. Headless mode keeps the original behaviour exactly.
DISPLAY_FLAGS=()
EXIT_DEVICE=(-device isa-debug-exit,iobase=0x501,iosize=0x2)
case "$GRAPHICS" in
  1|true|yes|on)
    DISP="${QEMU_DISPLAY:-}"
    if [ -z "$DISP" ]; then
      if [ "$(uname)" = "Darwin" ]; then
        DISP=cocoa
      else
        DISP=gtk
      fi
    fi
    DISPLAY_FLAGS=(-display "$DISP" -vga std -no-shutdown)
    EXIT_DEVICE=()
    echo "run_specs: graphics mode (display=$DISP) — close the QEMU window to quit" >&2
    ;;
  *)
    DISPLAY_FLAGS=(-monitor none -nographic)
    ;;
esac

# isa-debug-exit at iobase 0x501 turns OUT-port writes from the kernel into
# QEMU exit codes (`out 0x501, n` -> qemu exits with (n<<1)|1). The kernel
# uses this to signal "specs passed" (0) or "panic" (255).
#
# The firmware is loaded as pflash rather than via -bios because the EDK2
# images shipped with Homebrew QEMU aren't padded to the 4 MiB size that
# the legacy -bios path requires.
# q35 machine (not the default i440fx) is required for the Intel VT-d
# IOMMU (`-device intel-iommu`), which CONFIG_IOMMU / the IOPT tests
# need. Under q35 the boot disk lands on AHCI/SATA and OVMF won't
# auto-boot it from a bare `-drive`, so we attach it explicitly with
# `bootindex=0`. intremap=off: we only do DMA remapping, not IRQ remap.
exec qemu-system-x86_64 \
  -machine q35 \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF" \
  -drive format=raw,file="$IMAGE",if=none,id=bootdisk \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=bootdisk,bus=ahci0.0,bootindex=0 \
  -device intel-iommu,intremap=off \
  -m 1024M \
  -smp 4 \
  -serial stdio \
  -no-reboot \
  "${DISPLAY_FLAGS[@]}" \
  "${EXIT_DEVICE[@]}" \
  "${DEBUG_FLAGS[@]}" \
  "$@"
