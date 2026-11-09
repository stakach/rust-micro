#!/usr/bin/env bash
# The pinned image creator must build without fetching source during a boot build.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
SIMPLEBOOT_SRC_DIR="$tmp/src"
SIMPLEBOOT_BIN="$tmp/simpleboot"
SIMPLEBOOT_VENDOR_DIR="$PWD/vendor/simpleboot"
SIMPLEBOOT_RAW_BASE=https://invalid.example/simpleboot/src
curl() { echo 'unexpected Simpleboot network fetch' >&2; return 22; }

function_source=$(sed -n '/^ensure_simpleboot() {/,/^}/p' scripts/make_image.sh)
test -n "$function_source"
eval "$function_source"
tool=$(ensure_simpleboot)
test "$tool" = "$SIMPLEBOOT_BIN"
test -x "$tool"
test -s "$SIMPLEBOOT_SRC_DIR/simpleboot.c"
test -s "$SIMPLEBOOT_SRC_DIR/loader.h"
test -s "$SIMPLEBOOT_SRC_DIR/data.h"
grep -q LIBERNT_FAST_FAT_ALLOC "$SIMPLEBOOT_SRC_DIR/simpleboot.c"

cp -R "$SIMPLEBOOT_VENDOR_DIR" "$tmp/corrupt-source"
printf '\ncorrupt\n' >> "$tmp/corrupt-source/loader.h"
SIMPLEBOOT_VENDOR_DIR="$tmp/corrupt-source"
SIMPLEBOOT_BIN="$tmp/invalid-simpleboot"
if ensure_simpleboot > "$tmp/invalid-path" 2> "$tmp/invalid-error"; then
  echo 'corrupt pinned Simpleboot source was accepted' >&2
  exit 1
fi
grep -q 'failed SHA-256' "$tmp/invalid-error"
test ! -e "$SIMPLEBOOT_BIN"
