# Microkernel

A Rust microkernel project. Boots via [BOOTBOOT](https://gitlab.com/bztsrc/bootboot)
on UEFI, runs in QEMU, and uses an `isa-debug-exit` device so the in-kernel
spec runner can return a pass/fail exit code to the host.

## Prerequisites

### macOS (Apple Silicon or Intel)

```sh
# Image-building & emulation tools.
brew install qemu mtools dosfstools

# Rust nightly with rust-src (needed for `-Z build-std=core`).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
     --default-toolchain nightly --component rust-src
. "$HOME/.cargo/env"
```

The build scripts auto-locate the UEFI firmware shipped with `brew install
qemu` (`edk2-x86_64-code.fd`). To override, export `OVMF=/path/to/code.fd`.

### Linux

```sh
sudo apt install lld dosfstools mtools ovmf qemu-system-x86
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
     --default-toolchain nightly --component rust-src
```

## Build & test

```sh
./scripts/build_kernel.sh           # compile + bake disk.img with `spec` enabled
./scripts/build_kernel.sh paging    # add extra cargo features
./scripts/run_specs.sh              # boot the image in QEMU, run specs, exit
./scripts/run_specs.sh --debug      # also log interrupts and CPU resets
```

`build_kernel.sh` always passes the `spec` feature so kernel-internal tests
run on boot. The QEMU launch script exits with the code the kernel writes to
`isa-debug-exit` (`0` = all specs passed, `255` = panic).
