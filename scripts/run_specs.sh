#!/bin/bash
set -euxo pipefail

# add -d int,cpu_reset
# if we need to debug a triple fault
qemu-system-x86_64 \
  -drive format=raw,file=.tmp/disk.img \
  -bios /usr/share/OVMF/OVMF_CODE.fd \
  -serial stdio \
  -monitor none \
  -nographic \
  -no-reboot \
  -device isa-debug-exit,iobase=0x501,iosize=0x2
