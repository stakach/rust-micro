#!/usr/bin/env bash
# vendor/sel4test/build.sh — build upstream sel4test against our kernel ABI.
#
# Phase 40 — moving toward Tier B of the sel4test bring-up plan
# (`tasks/sel4test_bringup_plan.md`). On first run this script fetches
# the components from sel4test-manifest at their pinned SHAs:
#
#   https://github.com/seL4/sel4test-manifest/blob/master/default.xml
#
# The kernel checkout (`seL4/` at repo root) doubles as
# `vendor/sel4test/kernel` via a symlink so we don't fetch the same
# source twice. After fetching, we run upstream's CMake +
# ninja-based build pipeline with options that match our kernel:
# CONFIG_KERNEL_MCS=ON, x86_64, 4-core SMP, debug + printing.
#
# The build emits `vendor/sel4test/build/sel4test-driver/sel4test-
# driver` — the ELF that sel4test-driver runs as the rootserver.
# We copy it to `.tmp/rootserver.elf` so `scripts/make_image.sh`
# packs it into the BOOTBOOT initrd alongside our kernel; from
# there it's just `scripts/run_specs.sh` to boot.
#
# This script does not rebuild our kernel — that's
# `scripts/build_kernel.sh`'s job. Run that first to leave a fresh
# `target/mykernel-x86/release/mykernel-rust` in place.
set -euo pipefail

cd "$(dirname "$0")"
HERE="$PWD"

# Pinned SHAs from sel4test-manifest @ master (May 2026 snapshot).
SEL4_SHA=daa0dfb1470c5ffbf13b3778f93111679574e80c
SEL4TEST_SHA=6979c40390f0c7d6771bcf1be1dd6ec09c156fc4
SEL4_LIBS_SHA=4072cc43dc0d717dad5922373a9ea464c9279874
UTIL_LIBS_SHA=c8f9ea7c0ea390e3d82049de4125fe553a76ed1e
SEL4_TOOLS_SHA=03454f909f58aa1e0de363b92954be72c65b8c64
SEL4_PROJECTS_LIBS_SHA=0e06bebf4a3f0c21317c6877e0079f637e021562
SEL4RUNTIME_SHA=86489cf6efab9f314964e79468c036e9035394c7
MUSLLIBC_SHA=b0005f86fecbd6d0257b15363a5b013446914265
NANOPB_SHA=cad3c18ef15a663e30e3e43e3a752b66378adec1

# fetch_pinned <git-url> <sha> <dest-path>
# Clone-on-first-run, then ensure HEAD is at the requested SHA.
# Tolerates `.git` being either a directory (plain clone) or a
# gitfile (Repo-tool style — see musllibc gitfile rewrite below).
fetch_pinned() {
  local repo=$1 sha=$2 dest=$3
  if [ ! -e "$dest/.git" ]; then
    echo ">> cloning $repo -> $dest"
    git clone --quiet "$repo" "$dest"
  fi
  if [ "$(git -C "$dest" rev-parse HEAD)" != "$sha" ]; then
    echo ">> $dest: checking out $sha"
    git -C "$dest" fetch --quiet origin
    git -C "$dest" checkout --quiet "$sha"
  fi
}

mkdir -p projects tools

# Set up a Python venv with the modules sel4test's CMake codegen
# expects (PyYAML, jinja2, ply, future, six, lxml). Putting it
# first on PATH means cmake's `python3` resolves here.
VENV="$HERE/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  echo ">> creating venv at $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet \
    pyyaml jinja2 ply future six lxml \
    protobuf
fi
PATH="$VENV/bin:$PATH"
export PATH

# Homebrew installs GNU cpio as keg-only (to avoid shadowing
# macOS's BSD cpio), so /opt/homebrew/bin/cpio doesn't exist.
# sel4test's CMake invokes `cpio --append` which BSD cpio doesn't
# support — surface GNU cpio's bin on PATH explicitly.
GCPIO=$(ls -d /opt/homebrew/Cellar/cpio/*/bin 2>/dev/null | head -1)
if [ -n "$GCPIO" ] && [ -x "$GCPIO/cpio" ]; then
  PATH="$GCPIO:$PATH"
  export PATH
fi

fetch_pinned https://github.com/seL4/sel4test.git           "$SEL4TEST_SHA"           projects/sel4test
fetch_pinned https://github.com/seL4/seL4_libs.git          "$SEL4_LIBS_SHA"          projects/seL4_libs
fetch_pinned https://github.com/seL4/util_libs.git          "$UTIL_LIBS_SHA"          projects/util_libs
fetch_pinned https://github.com/seL4/seL4_tools.git         "$SEL4_TOOLS_SHA"         tools/seL4
fetch_pinned https://github.com/seL4/sel4_projects_libs.git "$SEL4_PROJECTS_LIBS_SHA" projects/sel4_projects_libs
fetch_pinned https://github.com/seL4/sel4runtime.git        "$SEL4RUNTIME_SHA"        projects/sel4runtime
fetch_pinned https://github.com/seL4/musllibc.git           "$MUSLLIBC_SHA"           projects/musllibc
fetch_pinned https://github.com/nanopb/nanopb.git           "$NANOPB_SHA"             tools/nanopb

# musllibc's CMake assumes the Google Repo tool layout where each
# repo's `.git` is a *file* (gitdir pointer), not a directory. It
# does `cp -a <src> build-temp/src/ && rm -f build-temp/src/.git`,
# which fails on our plain `git clone` where `.git` is a dir.
# Convert to a gitfile pointing at a sibling `.git-keep` — git
# still resolves correctly, and the upstream `rm -f` succeeds on
# the file in the cp-ed copy.
if [ -d projects/musllibc/.git ] && [ ! -e projects/musllibc/.git-keep ]; then
  mv projects/musllibc/.git projects/musllibc/.git-keep
  echo "gitdir: ./.git-keep" > projects/musllibc/.git
fi

# Reuse the seL4 kernel reference checkout at the repo root — it's
# already at the manifest's pinned SHA. sel4test's CMake expects
# the kernel source at ./kernel relative to the project root.
if [ ! -e kernel ]; then
  ln -sfn ../../seL4 kernel
fi
# Sanity check the reused kernel checkout is at the right SHA.
SEL4_HEAD=$(git -C "$HERE/../../seL4" rev-parse HEAD 2>/dev/null || echo none)
if [ "$SEL4_HEAD" != "$SEL4_SHA" ]; then
  echo "warn: ../../seL4 is at $SEL4_HEAD but manifest pins $SEL4_SHA" >&2
  echo "      sel4test build may diverge — consider:" >&2
  echo "      git -C ../../seL4 checkout $SEL4_SHA" >&2
fi

# Linkfiles per the manifest. These let init-build.sh / griddle /
# easy-settings.cmake be invoked from the project root.
ln -sfn tools/seL4/cmake-tool/init-build.sh init-build.sh
ln -sfn tools/seL4/cmake-tool/griddle       griddle
ln -sfn projects/sel4test/easy-settings.cmake easy-settings.cmake

# Configure with CMake + build with ninja. Options match our kernel:
#   x86_64, MCS scheduler, 4 cores, debug+printing build.
mkdir -p build
cd build
if [ ! -f CMakeCache.txt ]; then
  echo ">> configuring sel4test build"
  # Use upstream's LLVM toolchain file (kernel/llvm.cmake) so the
  # build picks clang + lld instead of gcc — matches the toolchain
  # we use for vendor/libsel4-build/. TRIPLE selects the target
  # for clang's `-target` flag.
  ../init-build.sh \
    -DPLATFORM=x86_64 \
    -DSIMULATION=ON \
    -DMCS=ON \
    -DKernelIsMCS=ON \
    -DKernelMaxNumNodes=4 \
    -DKernelPrinting=ON \
    -DKernelDebugBuild=ON \
    -DKernelMaxNumBootinfoUntypedCaps=230 \
    -DKernelSetTLSBaseSelf=ON \
    -DTRIPLE=x86_64-elf \
    -DCMAKE_TOOLCHAIN_FILE=../kernel/llvm.cmake \
    -DCMAKE_AR=/opt/homebrew/bin/x86_64-elf-ar \
    -DCMAKE_RANLIB=/opt/homebrew/bin/x86_64-elf-ranlib \
    -DCMAKE_NM=/opt/homebrew/bin/x86_64-elf-nm \
    -DCMAKE_OBJCOPY=/opt/homebrew/bin/x86_64-elf-objcopy \
    -DCMAKE_STRIP=/opt/homebrew/bin/x86_64-elf-strip
fi

echo ">> building sel4test-driver"
ninja sel4test-driver

# Stage the rootserver ELF where scripts/make_image.sh expects it.
DRIVER_ELF="$HERE/build/apps/sel4test-driver/sel4test-driver"
if [ ! -f "$DRIVER_ELF" ]; then
  echo "error: expected sel4test-driver ELF at $DRIVER_ELF" >&2
  exit 1
fi

DEST="$HERE/../../.tmp/rootserver.elf"
mkdir -p "$(dirname "$DEST")"
cp "$DRIVER_ELF" "$DEST"
echo "OK: sel4test-driver staged at $DEST"
ls -la "$DEST"
