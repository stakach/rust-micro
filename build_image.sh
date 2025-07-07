#!/bin/bash
set -euxo pipefail

IMAGE=disk.img
MOUNT=bootmnt
SIZE=64M

# Clean up stale mount
if mountpoint -q "$MOUNT"; then
  echo "Unmounting stale mount at $MOUNT"
  sudo umount "$MOUNT"
fi

# Create empty image
dd if=/dev/zero of=$IMAGE bs=1M count=64

# Format as FAT32
mkfs.vfat -F 32 $IMAGE

# Create mount point if it doesn't exist
mkdir -p $MOUNT

# Mount image using loopback
sudo mount -o loop $IMAGE $MOUNT

# Create required directories
sudo mkdir -p $MOUNT/efi/boot
sudo mkdir -p $MOUNT/bootboot

# Download bootboot EFI if missing
if [ ! -f bootboot.efi ]; then
  curl -L -o bootboot.efi https://gitlab.com/bztsrc/bootboot/raw/master/dist/bootboot.efi
fi

# Copy files
sudo cp bootboot.efi $MOUNT/efi/boot/bootx64.efi
sudo cp target/mykernel-x86/release/mykernel-rust $MOUNT/bootboot/X86_64

# Unmount
sudo umount $MOUNT
rmdir $MOUNT

echo "Disk image ready: $IMAGE"

