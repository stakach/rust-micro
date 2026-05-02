#!/usr/bin/env bash
# Build a standalone libsel4.a against our kernel's ABI (Phase 38b).
#
# Mirrors what libsel4's CMakeLists does, but invokes the Python
# generator tools directly rather than going through CMake. Output:
#
#     vendor/libsel4-build/out/libsel4.a
#     vendor/libsel4-build/out/include/...        — generated headers
#     vendor/libsel4-build/out/include/sel4/...   — manual config headers

set -euo pipefail

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$BUILD_DIR/../.." && pwd)"
SEL4_SRC="$REPO_DIR/seL4"
LIBSEL4_SRC="$SEL4_SRC/libsel4"
TOOLS="$LIBSEL4_SRC/tools"

OUT="$BUILD_DIR/out"
GEN="$OUT/include"
mkdir -p "$GEN/sel4" "$GEN/interfaces"
mkdir -p "$OUT/arch_include/x86/sel4/arch"
mkdir -p "$OUT/sel4_arch_include/x86_64/sel4/sel4_arch"

# Set up venv on first run.
VENV="$BUILD_DIR/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  echo ">> creating venv at $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet lxml jinja2 pyyaml ply
fi
PY="$VENV/bin/python"

ARCH=x86
SEL4_ARCH=x86_64
WORD_SIZE=64

INTERFACE_XMLS=(
  "$LIBSEL4_SRC/sel4_arch_include/$SEL4_ARCH/interfaces/object-api-sel4-arch.xml"
  "$LIBSEL4_SRC/arch_include/$ARCH/interfaces/object-api-arch.xml"
  "$LIBSEL4_SRC/include/interfaces/object-api.xml"
)

echo ">> generating sel4_client.h (per-invocation C wrappers)"
"$PY" "$TOOLS/syscall_stub_gen.py" \
  --mcs -a "$SEL4_ARCH" \
  -o "$GEN/interfaces/sel4_client.h" \
  "${INTERFACE_XMLS[@]}"

echo ">> generating syscall.h"
"$PY" "$TOOLS/syscall_header_gen.py" \
  --xml "$LIBSEL4_SRC/include/api/syscall.xml" \
  --libsel4_header "$GEN/sel4/syscall.h" \
  --mcs

echo ">> generating invocation.h (common labels)"
"$PY" "$TOOLS/invocation_header_gen.py" \
  --xml "$LIBSEL4_SRC/include/interfaces/sel4.xml" \
  --dest "$GEN/sel4/invocation.h" --libsel4

echo ">> generating arch invocation.h (x86)"
"$PY" "$TOOLS/invocation_header_gen.py" \
  --xml "$LIBSEL4_SRC/arch_include/$ARCH/interfaces/sel4arch.xml" \
  --dest "$OUT/arch_include/$ARCH/sel4/arch/invocation.h" --libsel4 --arch

echo ">> generating sel4_arch invocation.h (x86_64)"
"$PY" "$TOOLS/invocation_header_gen.py" \
  --xml "$LIBSEL4_SRC/sel4_arch_include/$SEL4_ARCH/interfaces/sel4arch.xml" \
  --dest "$OUT/sel4_arch_include/$SEL4_ARCH/sel4/sel4_arch/invocation.h" \
  --libsel4 --sel4_arch

# bitfield_gen wants a .pbf (preprocessed .bf). cpp -P expands the
# `#include <sel4/config.h>` directives etc. then bitfield_gen
# parses the resulting Type definitions and emits inline accessors.
CPP=( "${CLANG:-clang}" -E -P -x c )
PBF_DIR="$OUT/pbf"
mkdir -p "$PBF_DIR"

CPP_DEFS=(-DCONFIG_KERNEL_MCS=1 -DCONFIG_PRINTING=1 -DCONFIG_DEBUG_BUILD=1
          -DCONFIG_WORD_SIZE=64 -DCONFIG_MAX_NUM_NODES=4
          -DCONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS=230
          -DCONFIG_X86_64=1 -DCONFIG_ARCH_X86=1 -DCONFIG_ARCH_X86_64=1)
CPP_INCS=(-I "$BUILD_DIR/config"
          -I "$LIBSEL4_SRC/include"
          -I "$LIBSEL4_SRC/arch_include/$ARCH"
          -I "$LIBSEL4_SRC/sel4_arch_include/$SEL4_ARCH"
          -I "$LIBSEL4_SRC/mode_include/$WORD_SIZE"
          -I "$LIBSEL4_SRC/sel4_plat_include/pc99")

echo ">> preprocessing shared_types.bf"
"${CPP[@]}" "${CPP_DEFS[@]}" "${CPP_INCS[@]}" \
  -o "$PBF_DIR/shared_types.pbf" \
  "$LIBSEL4_SRC/mode_include/$WORD_SIZE/sel4/shared_types.bf"

echo ">> generating shared_types_gen.h"
( cd "$PBF_DIR" && "$PY" "$TOOLS/bitfield_gen.py" \
  --environment libsel4 \
  --from_file "$LIBSEL4_SRC/mode_include/$WORD_SIZE/sel4/shared_types.bf" \
  "$PBF_DIR/shared_types.pbf" \
  "$GEN/sel4/shared_types_gen.h" )

echo ">> preprocessing sel4_arch types.bf"
"${CPP[@]}" "${CPP_DEFS[@]}" "${CPP_INCS[@]}" \
  -o "$PBF_DIR/types.pbf" \
  "$LIBSEL4_SRC/sel4_arch_include/$SEL4_ARCH/sel4/sel4_arch/types.bf"

echo ">> generating sel4_arch types_gen.h"
( cd "$PBF_DIR" && "$PY" "$TOOLS/bitfield_gen.py" \
  --environment libsel4 \
  --from_file "$LIBSEL4_SRC/sel4_arch_include/$SEL4_ARCH/sel4/sel4_arch/types.bf" \
  "$PBF_DIR/types.pbf" \
  "$OUT/sel4_arch_include/$SEL4_ARCH/sel4/sel4_arch/types_gen.h" )

# Compile sel4_bootinfo.c into a .o + archive into libsel4.a.
# Cross-compile from the host (likely macOS arm64) to bare-metal
# x86_64; we don't link against any libc.
echo ">> compiling sel4_bootinfo.c"
CLANG="${CLANG:-clang}"
"$CLANG" -c \
  -target x86_64-unknown-none-elf \
  -ffreestanding -mno-red-zone -mcmodel=large -fno-stack-protector \
  -nostdlib -nostdinc -fno-builtin \
  -DCONFIG_KERNEL_MCS=1 -DCONFIG_PRINTING=1 -DCONFIG_DEBUG_BUILD=1 \
  -DCONFIG_WORD_SIZE=64 -DCONFIG_MAX_NUM_NODES=4 \
  -DCONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS=230 \
  -I "$BUILD_DIR/config" \
  -I "$LIBSEL4_SRC/include" \
  -I "$LIBSEL4_SRC/arch_include/$ARCH" \
  -I "$LIBSEL4_SRC/sel4_arch_include/$SEL4_ARCH" \
  -I "$LIBSEL4_SRC/mode_include/$WORD_SIZE" \
  -I "$LIBSEL4_SRC/sel4_plat_include/pc99" \
  -I "$GEN" -I "$OUT/arch_include/$ARCH" -I "$OUT/sel4_arch_include/$SEL4_ARCH" \
  -o "$OUT/sel4_bootinfo.o" \
  "$LIBSEL4_SRC/src/sel4_bootinfo.c"

echo ">> archiving libsel4.a"
# Use llvm-ar so the archive index matches our cross-compiled ELF
# object (macOS's default ar/ranlib expects Mach-O).
AR="${AR:-/opt/homebrew/opt/llvm/bin/llvm-ar}"
"$AR" rcs "$OUT/libsel4.a" "$OUT/sel4_bootinfo.o"

echo "OK: $OUT/libsel4.a built"
ls -la "$OUT/libsel4.a"

# ---------------------------------------------------------------------------
# Phase 38d — hello-world C user program linked against libsel4.a.
# Mirrors rootserver/link.ld so the kernel's existing ELF loader can
# place its PT_LOAD segments at PML4[2].
# ---------------------------------------------------------------------------

echo ">> compiling hello.c"
"$CLANG" -c \
  -target x86_64-unknown-none-elf \
  -ffreestanding -mno-red-zone -mcmodel=large -fno-stack-protector \
  -nostdlib -nostdinc -fno-builtin \
  -ffunction-sections -fdata-sections \
  -Os \
  -DCONFIG_KERNEL_MCS=1 -DCONFIG_PRINTING=1 -DCONFIG_DEBUG_BUILD=1 \
  -DCONFIG_WORD_SIZE=64 -DCONFIG_MAX_NUM_NODES=4 \
  -DCONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS=230 \
  -I "$BUILD_DIR/config" \
  -I "$LIBSEL4_SRC/include" \
  -I "$LIBSEL4_SRC/arch_include/$ARCH" \
  -I "$LIBSEL4_SRC/sel4_arch_include/$SEL4_ARCH" \
  -I "$LIBSEL4_SRC/mode_include/$WORD_SIZE" \
  -I "$LIBSEL4_SRC/sel4_plat_include/pc99" \
  -I "$GEN" -I "$OUT/arch_include/$ARCH" -I "$OUT/sel4_arch_include/$SEL4_ARCH" \
  -o "$OUT/hello.o" \
  "$BUILD_DIR/src/hello.c"

echo ">> linking hello.elf"
# rust-lld ships with the rustup toolchain; invoke it in ld.lld flavor.
RUST_LLD="$(ls -t "$HOME"/.rustup/toolchains/*/lib/rustlib/*/bin/rust-lld 2>/dev/null | head -1)"
LD="${LD:-$RUST_LLD}"
if [ -z "$LD" ] || [ ! -x "$LD" ]; then
  echo "error: cannot find ld.lld / rust-lld in expected locations" >&2
  exit 1
fi
"$LD" -flavor ld.lld \
  --gc-sections \
  -T "$BUILD_DIR/src/hello.ld" \
  -o "$OUT/hello.elf" \
  "$OUT/hello.o" \
  "$OUT/libsel4.a"

echo "OK: $OUT/hello.elf built"
ls -la "$OUT/hello.elf"
