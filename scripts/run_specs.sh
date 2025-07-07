#!/bin/bash
set -euxo pipefail

qemu-system-x86_64 \
  -drive format=raw,file=.tmp/disk.img \
  -bios /usr/share/OVMF/OVMF_CODE.fd \
  -serial stdio \
  -monitor none \
  -nographic \
  -device isa-debug-exit,iobase=0x501,iosize=0x2
