#!/bin/bash
set -euxo pipefail

mkdir -p .tmp
IMAGE=.tmp/disk.img
SIZE=64M

# Create empty image
dd if=/dev/zero of="$IMAGE" bs=1M count=64

# Format as FAT32
mkfs.vfat -F 32 "$IMAGE"

# Create required directory structure using mtools
# mtools must be installed and MTOOLS_SKIP_CHECK=1 prevents device checking errors
export MTOOLS_SKIP_CHECK=1

# Create a temporary mtools config file to point drive letter to image
MTOOLSRC=$(mktemp)
echo "drive z: file=\"$IMAGE\"" > "$MTOOLSRC"

# Download bootboot EFI if missing
if [ ! -f bootboot.efi ]; then
  curl -L -o .tmp/bootboot.efi https://gitlab.com/bztsrc/bootboot/raw/master/dist/bootboot.efi
fi

# Create directory structure
mmd -i "$IMAGE" ::efi
mmd -i "$IMAGE" ::efi/boot
mmd -i "$IMAGE" ::bootboot

# Copy files into image
mcopy -i "$IMAGE" .tmp/bootboot.efi ::efi/boot/bootx64.efi
mcopy -i "$IMAGE" target/mykernel-x86/release/mykernel-rust ::bootboot/X86_64

# Clean up
rm "$MTOOLSRC"

echo "Disk image ready: $IMAGE"
