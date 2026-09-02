# Rust Micro Kernel

A high-performance, memory-safe microkernel written in Rust — a from-scratch
reimplementation of the [seL4](https://sel4.systems/) microkernel (the C
reference lives in [`seL4/`](seL4/)). It boots via
[Simpleboot](https://gitlab.com/bztsrc/simpleboot) on UEFI, runs in QEMU, and uses
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
   `triplets/mykernel-x86.json`,
3. chains **`make_image.sh`**, which packs `rootserver` into a USTAR initrd
   module and asks Simpleboot to write a GPT/ESP image to `.tmp/disk.img`
   (fetching and compiling the Simpleboot image creator once into `.tmp/`).

```sh
./scripts/build_kernel.sh                 # default build (spec)
./scripts/build_kernel.sh smp             # extra cargo features are appended
./scripts/build_kernel.sh smp fastpath    # multiple features
./scripts/build_kernel.sh extern-rootserver # hosted rootserver build, specs off by default
KERNEL_SPECS=1 ./scripts/build_kernel.sh extern-rootserver # hosted build with specs
```

You can re-run the stages individually:

```sh
./scripts/make_image.sh                   # repack image from existing artifacts
```

### AArch64 build and boot

The AArch64 port boots QEMU `virt` through a Simpleboot-compatible first stage.
That stage consumes QEMU's FDT, loads the kernel and rootserver, starts all four
CPUs with PSCI, and presents the same Multiboot2 tag ABI used by amd64. Build
and run the kernel and userspace specs with:

```sh
./scripts/check_aarch64.sh
./vendor/sel4test/build.sh aarch64 smp
./scripts/run_aarch64_specs.sh
```

The pinned upstream Simpleboot release only supplies an AArch64 loader for
Raspberry Pi, not QEMU `virt`. The repository therefore carries the small
QEMU-platform first stage under `boot/aarch64-simpleboot/`; the kernel-facing
Simpleboot ABI remains architecture-independent.

### Build options (cargo features)

Passed positionally to `build_kernel.sh`. Standalone builds include `spec` by
default; `extern-rootserver` builds omit it unless you pass `spec` explicitly or
set `KERNEL_SPECS=1`.

| Feature         | Effect |
|-----------------|--------|
| `spec`          | Compile + run kernel-internal specs. Standalone builds enable it by default; `extern-rootserver` builds do not. |
| `smp`           | Multi-CPU: per-CPU state, IPI dispatch, eager per-core FPU. Needed for the MULTICORE / SCHED_CONTEXT_0014 / FPU0002 sel4test families. |
| `fastpath`      | Hot-path IPC that bypasses the slowpath. |
| `fpu`           | Lazy FPU state-switch (single-node model). |
| `vmx`           | Hardware-virtualisation (VT-x) extensions. |
| `microtest`     | Also build the rootserver with its structured test harness instead of the legacy demos. |
| `libsel4-hello` | Swap the rootserver for `vendor/libsel4-build/out/hello.elf` (C built against upstream libsel4) — validates the SYSCALL ABI end-to-end. |
| `surt-demo`     | Swap the rootserver for `vendor/surt-demo/` — a root task that consumes the published [`surt-sel4`](https://crates.io/crates/surt-sel4) crate and runs the SURT ring-transport scenarios on the kernel. See `vendor/surt-demo/README.md`. |
| `arch-x86_64`   | (default) x86_64 architecture selector. |
| `arch-aarch64`  | AArch64 architecture selector. Use with `--no-default-features` and `triplets/mykernel-aarch64.json`. |
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
`sel4test-driver` as the rootserver. The `smp` profile uses four CPUs and one
domain. The `domains` profile uses one CPU and four domains because upstream
seL4 does not permit `KernelMaxNumNodes > 1` with `KernelNumDomains > 1`.

```sh
# amd64 SMP: generic + x86 kernel specs, then the four-core userspace suite.
./vendor/sel4test/build.sh x86_64 smp
KERNEL_SPECS=1 ./scripts/build_kernel.sh smp extern-rootserver
QEMU_CPUS=4 ./scripts/run_specs.sh

# amd64 domains: generic + x86 kernel specs, then the four-domain suite.
./vendor/sel4test/build.sh x86_64 domains
KERNEL_SPECS=1 ./scripts/build_kernel.sh extern-rootserver
./scripts/make_image.sh
QEMU_CPUS=1 ./scripts/run_specs.sh

# AArch64 SMP through the same Simpleboot contract.
./scripts/build_aarch64.sh spec smp
./vendor/sel4test/build.sh aarch64 smp
KERNEL_SMP=1 QEMU_CPUS=4 ./scripts/run_aarch64_specs.sh

# AArch64 domains.
./vendor/sel4test/build.sh aarch64 domains
KERNEL_SMP=0 QEMU_CPUS=1 ./scripts/run_aarch64_specs.sh
```

Notes:

- **Scoping which tests run:** set `SEL4TEST_REGEX`, for example
  `SEL4TEST_REGEX='^(FPU0002|TRIVIAL)' ./vendor/sel4test/build.sh aarch64 smp`.
  The build script updates the generated configuration and rebuilds the driver.
- **Multicore tests** (MULTICORE\*, FPU0002, SCHED_CONTEXT_0014) require the
  `smp` profile. Domain schedule configuration and migration coverage require
  the `domains` profile.
- **Remaining disabled tests are configuration exclusions, not unclassified
  architecture gaps:** `SYSCALL0003`, `CNODEOP0009`, and `SCHED0006` test the
  legacy non-MCS ABI; `BREAKPOINT_002` and `SCHED0021` are disabled by upstream
  under simulation; cache-alias tests require hardware cache behaviour that QEMU
  TCG does not model; EPT and `UNKNOWN_SYSCALL_001` require VT-x; and the SMP or
  multi-domain families are enabled only in their matching profile.
- `build_kernel.sh` rewrites `.tmp/disk.img`; don't run it while a QEMU spec run
  is live, and confirm the kernel binary's mtime is newer than your sources
  (a failed `cargo` build can silently leave a stale kernel staged).

## QEMU environment

`run_specs.sh` launches `qemu-system-x86_64` with:

- **`-machine q35`** + **`-device intel-iommu,intremap=off`** — the VT-d IOMMU
  the IOPT/CONFIG_IOMMU tests need (DMA remapping only, no IRQ remap). Under q35
  the boot disk is attached over AHCI/SATA with an explicit `bootindex=0`.
- **`-smp 4`**, **`-m ${QEMU_MEMORY:-2048M}`**, **`-serial stdio`**,
  **`-nographic`**, **`-no-reboot`**. The 2 GiB default gives the rootserver
  Untyped allocator enough aligned RAM for the ReactOS desktop service wave; set
  `QEMU_MEMORY=1024M` when reproducing older tight-memory runs.
- Firmware is loaded as `pflash` (the Homebrew EDK2 image isn't padded to the
  4 MiB the legacy `-bios` path needs).

This is a TCG (software-emulated) environment on Apple Silicon: PCID/INVPCID and
VT-x/EPT are not implemented by QEMU's TCG, so the VCPU/EPT and PCID-dependent
paths can't be exercised here (KVM-only).
