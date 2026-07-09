#!/usr/bin/env bash
# fetch_reactos.sh — fetch a ReactOS x64 livecd and extract its ntdll.dll + smss.exe so the
# ntos-executive can load a REAL, redistributable (GPL) ReactOS binary via SEC_IMAGE. Everything
# is cached under .tmp/reactos/ so it runs once; make_image.sh mcopies the staged binaries onto
# the disk image (guarded — a fresh clone that hasn't run this simply omits them).
#
# ReactOS is GPL, so its binaries are freely redistributable — unlike references/ (proprietary,
# gitignored). The x64 (amd64) build gives PE32+/machine-0x8664 binaries our loader accepts;
# the stable x86 releases would be PE32 (rejected by nt-pe-loader).
#
# Needs: curl + bsdtar (libarchive reads both .7z and ISO9660). No 7z/cabextract needed for this
# livecd — the binaries sit directly in reactos/system32/ (no reactos.cab).
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=.tmp/reactos
mkdir -p "$OUT"

URL="https://iso.reactos.org/livecd/reactos-livecd-0.4.17-dev-457-g63deca5-x64-msvc-win-dbg.7z"

if [ -f "$OUT/ros-ntdll.dll" ] && [ -f "$OUT/ros-smss.exe" ]; then
  echo "ReactOS binaries already staged: $OUT/ros-ntdll.dll, $OUT/ros-smss.exe"
  exit 0
fi

if [ ! -f "$OUT/reactos-x64.7z" ]; then
  echo "downloading ReactOS x64 livecd (~29 MiB)..."
  curl -fL --retry 3 -o "$OUT/reactos-x64.7z" "$URL"
fi

# .7z -> ISO (bsdtar reads 7-Zip), then ISO -> the two binaries (bsdtar reads ISO9660).
( cd "$OUT" && bsdtar -xf reactos-x64.7z )
ISO="$OUT/$(cd "$OUT" && ls *.iso | head -1)"
echo "extracting ntdll.dll + smss.exe from $ISO ..."
bsdtar -xf "$ISO" -C "$OUT" reactos/system32/ntdll.dll reactos/system32/smss.exe
cp "$OUT/reactos/system32/ntdll.dll" "$OUT/ros-ntdll.dll"
cp "$OUT/reactos/system32/smss.exe"  "$OUT/ros-smss.exe"

echo "staged: $OUT/ros-ntdll.dll ($(stat -f%z "$OUT/ros-ntdll.dll") bytes), $OUT/ros-smss.exe ($(stat -f%z "$OUT/ros-smss.exe") bytes)"
