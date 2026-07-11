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

if [ -f "$OUT/ros-ntdll.dll" ] && [ -f "$OUT/ros-smss.exe" ] && [ -f "$OUT/ros-csrss.exe" ] \
   && [ -f "$OUT/imports.bin" ] \
   && [ -f "$OUT/ros-c1252.nls" ] && [ -f "$OUT/ros-c437.nls" ] && [ -f "$OUT/ros-lintl.nls" ]; then
  echo "ReactOS binaries + import table + NLS tables already staged in $OUT/"
  exit 0
fi

if [ ! -f "$OUT/ros-ntdll.dll" ] || [ ! -f "$OUT/ros-smss.exe" ] || [ ! -f "$OUT/ros-csrss.exe" ] \
   || [ ! -f "$OUT/ros-c1252.nls" ] || [ ! -f "$OUT/ros-c437.nls" ] || [ ! -f "$OUT/ros-lintl.nls" ]; then
  if [ ! -f "$OUT/reactos-x64.7z" ]; then
    echo "downloading ReactOS x64 livecd (~29 MiB)..."
    curl -fL --retry 3 -o "$OUT/reactos-x64.7z" "$URL"
  fi
  # .7z -> ISO (bsdtar reads 7-Zip), then ISO -> the binaries + NLS tables (bsdtar reads ISO9660).
  ( cd "$OUT" && bsdtar -xf reactos-x64.7z )
  ISO="$OUT/$(cd "$OUT" && ls *.iso | head -1)"
  echo "extracting ntdll.dll + smss.exe + NLS tables + SYSTEM hive from $ISO ..."
  bsdtar -xf "$ISO" -C "$OUT" \
    reactos/system32/ntdll.dll reactos/system32/smss.exe reactos/system32/csrss.exe \
    reactos/system32/c_1252.nls reactos/system32/c_437.nls reactos/system32/l_intl.nls \
    reactos/system32/config/system
  cp -f "$OUT/reactos/system32/ntdll.dll" "$OUT/ros-ntdll.dll"
  cp -f "$OUT/reactos/system32/smss.exe"  "$OUT/ros-smss.exe"
  # csrss.exe — the Win32 subsystem launcher smss starts (SmpLoadSubSystem). A thin PE (~7 KiB)
  # whose real work is in its ServerDlls (csrsrv/basesrv/winsrv).
  cp -f "$OUT/reactos/system32/csrss.exe" "$OUT/ros-csrss.exe"
  # The real regf SYSTEM registry hive — nt-hive-regf parses it so the NT registry serves smss's
  # real \Registry\Machine\System\...\Session Manager config (not a synthesized key).
  cp -f "$OUT/reactos/system32/config/system" "$OUT/ros-system.hiv"
  # NLS: c_1252 = ANSI (CP1252) MB<->WideChar tables, c_437 = OEM (CP437), l_intl = Unicode case
  # table. LdrpInitializeProcess needs these via PEB->{Ansi,Oem,UnicodeCaseTable}CodePageData for
  # RtlInitNlsTables / RtlUnicodeToMultiByteN.
  cp -f "$OUT/reactos/system32/c_1252.nls" "$OUT/ros-c1252.nls"
  cp -f "$OUT/reactos/system32/c_437.nls"  "$OUT/ros-c437.nls"
  cp -f "$OUT/reactos/system32/l_intl.nls" "$OUT/ros-lintl.nls"
fi

# Resolve smss's ntdll imports against ntdll's export table -> imports.bin (the executive
# applies this patch table to smss's IAT at runtime).
python3 "$(dirname "$0")/gen_reactos_imports.py" "$OUT/ros-smss.exe" "$OUT/ros-ntdll.dll" "$OUT/imports.bin"

echo "staged: ros-ntdll.dll ($(stat -f%z "$OUT/ros-ntdll.dll") bytes), ros-smss.exe ($(stat -f%z "$OUT/ros-smss.exe") bytes), imports.bin"
