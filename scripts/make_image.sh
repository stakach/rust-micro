#!/usr/bin/env bash
# make_image.sh — wrap the freshly built kernel in a FAT32 EFI disk image.
# Works on macOS (Homebrew dosfstools+mtools) and Linux. Tools are looked up
# on PATH; on macOS, /opt/homebrew/sbin (where dosfstools installs mkfs.vfat)
# is added if it isn't already present.
set -euo pipefail

cd "$(dirname "$0")/.."

# macOS: Homebrew installs mkfs.vfat under sbin which isn't always on PATH.
if [ "$(uname)" = "Darwin" ]; then
  for d in /opt/homebrew/sbin /usr/local/sbin; do
    case ":$PATH:" in
      *":$d:"*) ;;
      *) [ -d "$d" ] && PATH="$d:$PATH" ;;
    esac
  done
fi

# Verify required tools.
missing=()
for tool in dd mkfs.vfat mmd mcopy curl; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "error: missing required tools: ${missing[*]}" >&2
  echo "       macOS: brew install qemu mtools dosfstools" >&2
  echo "       Linux: apt install dosfstools mtools" >&2
  exit 1
fi

mkdir -p .tmp
IMAGE=.tmp/disk.img
KERNEL=target/mykernel-x86/release/mykernel-rust

if [ ! -f "$KERNEL" ]; then
  echo "error: kernel not built at $KERNEL — run scripts/build_kernel.sh first" >&2
  exit 1
fi

# Create a 64 MiB blank image and format as FAT32. macOS `dd` accepts the
# same `bs=1M count=64` syntax as GNU dd.
dd if=/dev/zero of="$IMAGE" bs=1M count=64 status=none
mkfs.vfat -F 32 "$IMAGE" >/dev/null

# mtools tries to detect floppy/cdrom devices; tell it to skip those checks
# since we're operating on a plain image file.
export MTOOLS_SKIP_CHECK=1

# Bootboot UEFI loader. Cache it under .tmp/ so repeated builds don't re-fetch.
if [ ! -f .tmp/bootboot.efi ]; then
  echo "downloading bootboot.efi..."
  curl -fL -o .tmp/bootboot.efi \
    https://gitlab.com/bztsrc/bootboot/raw/master/dist/bootboot.efi
fi

mmd -i "$IMAGE" ::efi
mmd -i "$IMAGE" ::efi/boot
mmd -i "$IMAGE" ::bootboot
mcopy -i "$IMAGE" .tmp/bootboot.efi ::efi/boot/bootx64.efi
mcopy -i "$IMAGE" "$KERNEL" ::bootboot/X86_64

echo "disk image ready: $IMAGE"
