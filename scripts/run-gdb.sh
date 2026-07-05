#!/usr/bin/env bash
# run-gdb.sh — boot the disk image in QEMU with a gdb stub (-s -S, halted at start),
# then drive lldb in batch mode to break at $BRK and dump registers + stack.
set -euo pipefail
cd "$(dirname "$0")/.."

OVMF="${OVMF:-}"
if [ -z "$OVMF" ]; then
  for c in /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
           /usr/local/share/qemu/edk2-x86_64-code.fd \
           /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2-ovmf/OVMF_CODE.fd; do
    [ -f "$c" ] && OVMF="$c" && break
  done
fi
IMAGE=.tmp/disk.img
BRK="${BRK:-0x78e8c966}"

qemu-system-x86_64 \
  -machine q35 \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF" \
  -drive format=raw,file="$IMAGE",if=none,id=bootdisk \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=bootdisk,bus=ahci0.0,bootindex=0 \
  -m 1024M -smp 1 \
  -serial file:/tmp/gdb-serial.log -monitor none -nographic -no-reboot \
  -device isa-debug-exit,iobase=0x501,iosize=0x2 \
  -s -S &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null || true' EXIT
sleep 1

lldb --batch \
  -o "gdb-remote localhost:1234" \
  -o "breakpoint set --address $BRK" \
  -o "continue" \
  -o "register read rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15" \
  -o "memory read --size 8 --count 12 --format x \$rsp" \
  -o "disassemble --start-address $BRK --count 6" \
  -o "quit" 2>&1 | grep -vE "^\(lldb\)|warning:|Kernel|kernel"
