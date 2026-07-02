#!/usr/bin/env bash
# build.sh — compile the SURT demo rootserver and stage it as the kernel's
# rootserver ELF (.tmp/rootserver.elf) for scripts/make_image.sh to bundle.
#
# The demo is a standalone seL4 root task that depends on the PUBLISHED
# `surt-sel4` crate from crates.io (fetched on first build), implements the
# two-syscall Sel4Env for this kernel, and runs the SURT ring scenarios.
#
# Usually invoked indirectly:  ./scripts/build_kernel.sh surt-demo
# but can be run on its own to just (re)stage the ELF.
set -euo pipefail

cd "$(dirname "$0")"

# `compiler-builtins-mem` is required here (unlike the plain kernel rootserver):
# surt-core's `init_ring` emits memcpy/memset for its header initialisation.
cargo +nightly build \
  -Z build-std=core \
  -Z build-std-features=compiler-builtins-mem \
  -Z unstable-options \
  -Z json-target-spec \
  --target triplet.json \
  --release

mkdir -p ../../.tmp
cp target/triplet/release/surt-demo ../../.tmp/rootserver.elf
echo "surt-demo staged: .tmp/rootserver.elf (published surt-sel4 crate)"
