# Microkernel

## Prerequisites

sudo apt install lld
sudo apt install dosfstools
sudo apt install ovmf
sudo apt install qemu-system-x86

## Building

1. cargo +nightly build -Z build-std=core --target triplets/mykernel-x86.json --release --features spec
2. ./build_image.sh

## Running

### AMD64

```shell
qemu-system-x86_64 \
  -drive format=raw,file=disk.img \
  -bios /usr/share/OVMF/OVMF_CODE.fd \
  -serial stdio \
  -monitor none \
  -nographic \
  -device isa-debug-exit,iobase=0x501,iosize=0x2
```
