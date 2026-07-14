# Rust Micro Kernel

A high-performance, memory-safe microkernel written in Rust — a from-scratch
reimplementation of the [seL4](https://sel4.systems/) microkernel (the C
reference lives in [`seL4/`](seL4/)). It boots via
[BOOTBOOT](https://gitlab.com/bztsrc/bootboot) on UEFI, runs in QEMU, and uses
an `isa-debug-exit` device so an in-kernel (or userspace) test runner can return
a pass/fail exit code straight to the host shell. No external crates — the
kernel depends only on `core`.

> Looking for the full **ReactOS-hosting desktop demo** (this kernel booting
> real ReactOS `smss`/`csrss`/`winlogon`/`win32k` to a painted Windows desktop)?
> That lives in the parent [`userspace-ntos`](https://github.com/stakach/userspace-ntos)
> repo — run its `./run.sh`. This README covers the kernel + its specs in isolation.

There are **two** ways to validate the kernel, both covered below:

1. **Kernel specs** — kernel-internal tests behind the `spec` feature, run on
   boot. Fast inner loop for developing a subsystem.
2. **sel4test conformance suite** — the upstream seL4 test suite (170+ tests)
   built against our kernel ABI and run as the rootserver. The real
   correctness bar.

## Repository layout

```
src/                  the kernel (arch code under src/arch/<arch>/)
rootserver/           the default Rust rootserver (custom JSON target)
seL4/                 the C seL4 reference, also reused as sel4test's kernel
vendor/
  sel4test/           upstream sel4test + its build.sh (pinned SHAs)
  libsel4-build/      C "hello" built against upstream libsel4 (ABI check)
triplets/             custom bare-metal target specs (mykernel-x86.json, …)
scripts/              build_kernel.sh, make_image.sh, run_specs.sh
tasks/                todo.md / lessons.md working notes
.tmp/                 build artifacts: rootserver.elf, disk.img, initrd, OVMF
```

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

The scripts auto-locate the UEFI firmware shipped with `brew install qemu`
(`edk2-x86_64-code.fd`). Override with `export OVMF=/path/to/code.fd`.

### Linux

```sh
sudo apt install lld dosfstools mtools ovmf qemu-system-x86 cmake ninja-build
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
     --default-toolchain nightly --component rust-src
```

(`cmake`/`ninja` are only needed for the sel4test suite, not the kernel itself.)

## Quick start

```sh
./scripts/build_kernel.sh        # compile kernel + rootserver, bake .tmp/disk.img
./scripts/run_specs.sh           # boot in QEMU, run specs, exit with pass/fail
echo $?                          # 0 = all specs passed, 255 = panic
```

## Building the kernel

`build_kernel.sh` is the single entry point. It:

1. builds the **rootserver** ELF and stages it at `.tmp/rootserver.elf`
   (the default Rust rootserver, or a variant — see features below),
2. builds the **kernel** with `-Z build-std=core` against
   `triplets/mykernel-x86.json` (always with the `spec` feature),
3. chains **`make_image.sh`**, which packs `kernel` + `rootserver` into a USTAR
   initrd and writes a FAT32 EFI image to `.tmp/disk.img` (fetching
   `bootboot.efi` once into `.tmp/`).

```sh
./scripts/build_kernel.sh                 # default build (spec)
./scripts/build_kernel.sh smp             # extra cargo features are appended
./scripts/build_kernel.sh smp fastpath    # multiple features
```

You can re-run the stages individually:

```sh
./scripts/make_image.sh                   # repack image from existing artifacts
```

### Build options (cargo features)

Passed positionally to `build_kernel.sh`; `spec` is always included.

| Feature         | Effect |
|-----------------|--------|
| `spec`          | (always on) compile + run kernel-internal specs; enable `qemu_exit`. |
| `smp`           | Multi-CPU: per-CPU state, IPI dispatch, eager per-core FPU. Needed for the MULTICORE / SCHED_CONTEXT_0014 / FPU0002 sel4test families. |
| `fastpath`      | Hot-path IPC that bypasses the slowpath. |
| `fpu`           | Lazy FPU state-switch (single-node model). |
| `vmx`           | Hardware-virtualisation (VT-x) extensions. |
| `microtest`     | Also build the rootserver with its structured test harness instead of the legacy demos. |
| `libsel4-hello` | Swap the rootserver for `vendor/libsel4-build/out/hello.elf` (C built against upstream libsel4) — validates the SYSCALL ABI end-to-end. |
| `surt-demo`     | Swap the rootserver for `vendor/surt-demo/` — a root task that consumes the published [`surt-sel4`](https://crates.io/crates/surt-sel4) crate and runs the SURT ring-transport scenarios on the kernel. See `vendor/surt-demo/README.md`. |
| `arch-x86_64`   | (default) architecture selector. `arch-aarch64` exists in-tree, but the build scripts target x86_64 (`triplets/mykernel-x86.json`); AArch64 needs its own triplet. |
| `mcs`           | No-op (retained for compatibility); MCS is always on. |

> Specs are scoped to the `spec` namespace so they can be compiled out of a
> production kernel. Write specs against public subsystem interfaces so they run
> across architectures; a subsystem's specs can sit behind its own feature flag
> for focused testing.

## Running kernel specs

```sh
./scripts/run_specs.sh            # boot, run specs, exit via isa-debug-exit
./scripts/run_specs.sh --debug    # also log interrupts and CPU resets (-d int,cpu_reset)
```

`run_specs.sh` boots `.tmp/disk.img` with serial on stdio and exits with the
code the kernel writes to `isa-debug-exit` (iobase `0x501`): **`0` = all specs
passed, `255` = panic**. Any trailing arguments are forwarded to QEMU, e.g.:

```sh
./scripts/run_specs.sh -s -S      # wait for a gdb attach on :1234
```

## Running the sel4test conformance suite

This builds the **upstream** sel4test against our kernel ABI and runs its
`sel4test-driver` as the rootserver. The kernel itself is unchanged — only the
staged rootserver swaps.

```sh
# 1. Build the kernel (use `smp` for the multicore/FPU/SC families).
./scripts/build_kernel.sh smp

# 2. Build sel4test-driver (first run fetches pinned SHAs + a Python venv;
#    CMake + ninja). Emits the ELF and copies it to .tmp/rootserver.elf.
./vendor/sel4test/build.sh

# 3. Repack the image with the sel4test rootserver, then boot.
./scripts/make_image.sh
./scripts/run_specs.sh
```

Notes:

- **Scoping which tests run:** sel4test's `gen_config.h` carries a
  `CONFIG_TESTPRINTER_REGEX`. Narrow it (e.g. `"^(FPU0002|TRIVIAL)"`) to run a
  focused subset, then **rebuild** — after editing the regex you must
  `touch sel4test-driver/src/main.c` and re-run ninja, then verify with
  `strings <driver> | grep <regex>` (ninja's dep tracking misses the header).
- **Multicore tests** (MULTICORE\*, FPU0002, SCHED_CONTEXT_0014) require the
  `smp` kernel **and** sel4test configured with `MAX_NUM_NODES=4`
  (`cmake -DKernelMaxNumNodes=4 .` in the build dir if a stale `CMakeCache.txt`
  pins it to 1).
- `build_kernel.sh` rewrites `.tmp/disk.img`; don't run it while a QEMU spec run
  is live, and confirm the kernel binary's mtime is newer than your sources
  (a failed `cargo` build can silently leave a stale kernel staged).

## QEMU environment

`run_specs.sh` launches `qemu-system-x86_64` with:

- **`-machine q35`** + **`-device intel-iommu,intremap=off`** — the VT-d IOMMU
  the IOPT/CONFIG_IOMMU tests need (DMA remapping only, no IRQ remap). Under q35
  the boot disk is attached over AHCI/SATA with an explicit `bootindex=0`.
- **`-smp 4`**, **`-m 1024M`**, **`-serial stdio`**, **`-nographic`**,
  **`-no-reboot`**.
- Firmware is loaded as `pflash` (the Homebrew EDK2 image isn't padded to the
  4 MiB the legacy `-bios` path needs).

This is a TCG (software-emulated) environment on Apple Silicon: PCID/INVPCID and
VT-x/EPT are not implemented by QEMU's TCG, so the VCPU/EPT and PCID-dependent
paths can't be exercised here (KVM-only).
