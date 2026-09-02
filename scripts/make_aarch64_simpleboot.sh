#!/usr/bin/env bash
# Build the QEMU-virt AArch64 Simpleboot stage and its module archive.
set -euo pipefail

cd "$(dirname "$0")/.."

KERNEL=target/mykernel-aarch64/release/mykernel-rust
OUT=.tmp/aarch64-simpleboot
STAGE="$OUT/initrd"
ARCHIVE="$OUT/initrd.tar"
LOADER_ELF="$OUT/simpleboot-aarch64.elf"
LOADER_IMAGE="$OUT/simpleboot-aarch64.img"

if [ ! -f "$KERNEL" ]; then
  echo "error: AArch64 kernel missing at $KERNEL; run scripts/build_aarch64.sh first" >&2
  exit 1
fi

mkdir -p "$STAGE/boot"
cp "$KERNEL" "$STAGE/boot/kernel"
if [ -f .tmp/rootserver.elf ]; then
  cp .tmp/rootserver.elf "$STAGE/boot/rootserver"
else
  rm -f "$STAGE/boot/rootserver"
fi

tar --format=ustar -C "$STAGE" -cf "$ARCHIVE" boot

CC="${AARCH64_CC:-clang}"
RUST_LLD="$(rustc +nightly --print sysroot)/lib/rustlib/$(rustc +nightly -vV | sed -n 's/^host: //p')/bin/rust-lld"
OBJCOPY="${LLVM_OBJCOPY:-/opt/homebrew/opt/llvm/bin/llvm-objcopy}"
if [ ! -x "$OBJCOPY" ]; then
  OBJCOPY="$(rustc +nightly --print sysroot)/lib/rustlib/$(rustc +nightly -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
fi

COMMON_FLAGS=(--target=aarch64-none-elf -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -O2 -Wall -Wextra -Werror)
"$CC" "${COMMON_FLAGS[@]}" -c boot/aarch64-simpleboot/entry.S -o "$OUT/entry.o"
"$CC" "${COMMON_FLAGS[@]}" -mgeneral-regs-only -std=c11 -c boot/aarch64-simpleboot/loader.c -o "$OUT/loader.o"
"$RUST_LLD" -flavor gnu -T boot/aarch64-simpleboot/link.ld -nostdlib -static \
  "$OUT/entry.o" "$OUT/loader.o" -o "$LOADER_ELF"
"$OBJCOPY" -O binary "$LOADER_ELF" "$LOADER_IMAGE"

echo "AArch64 Simpleboot ELF:    $LOADER_ELF"
echo "AArch64 Simpleboot image:  $LOADER_IMAGE"
echo "AArch64 Simpleboot initrd: $ARCHIVE"
