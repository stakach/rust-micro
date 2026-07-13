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
   && [ -f "$OUT/ros-csrsrv.dll" ] && [ -f "$OUT/ros-basesrv.dll" ] && [ -f "$OUT/ros-winsrv.dll" ] \
   && [ -f "$OUT/ros-gdi32.dll" ] && [ -f "$OUT/ros-user32.dll" ] && [ -f "$OUT/ros-kernel32.dll" ] \
   && [ -f "$OUT/ros-rpcrt4.dll" ] && [ -f "$OUT/ros-msvcrt.dll" ] && [ -f "$OUT/ros-advapi32.dll" ] \
   && [ -f "$OUT/ros-ws2_32.dll" ] && [ -f "$OUT/ros-kernel32_vista.dll" ] \
   && [ -f "$OUT/ros-advapi32_vista.dll" ] && [ -f "$OUT/ros-ws2help.dll" ] \
   && [ -f "$OUT/ros-ntdll_vista.dll" ] \
   && [ -f "$OUT/imports.bin" ] \
   && [ -f "$OUT/ros-c1252.nls" ] && [ -f "$OUT/ros-c437.nls" ] && [ -f "$OUT/ros-lintl.nls" ] \
   && [ -f "$OUT/ros-c20127.nls" ] && [ -f "$OUT/ros-win32k.sys" ] \
   && [ -f "$OUT/ros-dxg.sys" ] && [ -f "$OUT/ros-dxgthk.sys" ] \
   && [ -f "$OUT/ros-ftfd.dll" ] && [ -f "$OUT/ros-framebuf.dll" ] \
   && [ -f "$OUT/ros-winlogon.exe" ] \
   && [ -f "$OUT/ros-arial.ttf" ]; then
  echo "ReactOS binaries + import table + NLS tables already staged in $OUT/"
  exit 0
fi

if [ ! -f "$OUT/ros-ntdll.dll" ] || [ ! -f "$OUT/ros-smss.exe" ] || [ ! -f "$OUT/ros-csrss.exe" ] \
   || [ ! -f "$OUT/ros-csrsrv.dll" ] || [ ! -f "$OUT/ros-basesrv.dll" ] || [ ! -f "$OUT/ros-winsrv.dll" ] \
   || [ ! -f "$OUT/ros-gdi32.dll" ] || [ ! -f "$OUT/ros-user32.dll" ] || [ ! -f "$OUT/ros-kernel32.dll" ] \
   || [ ! -f "$OUT/ros-rpcrt4.dll" ] || [ ! -f "$OUT/ros-msvcrt.dll" ] || [ ! -f "$OUT/ros-advapi32.dll" ] \
   || [ ! -f "$OUT/ros-ws2_32.dll" ] || [ ! -f "$OUT/ros-kernel32_vista.dll" ] \
   || [ ! -f "$OUT/ros-advapi32_vista.dll" ] || [ ! -f "$OUT/ros-ws2help.dll" ] \
   || [ ! -f "$OUT/ros-ntdll_vista.dll" ] \
   || [ ! -f "$OUT/ros-c1252.nls" ] || [ ! -f "$OUT/ros-c437.nls" ] || [ ! -f "$OUT/ros-lintl.nls" ] \
   || [ ! -f "$OUT/ros-c20127.nls" ]; then
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
    reactos/system32/csrsrv.dll reactos/system32/basesrv.dll reactos/system32/winsrv.dll \
    reactos/system32/gdi32.dll reactos/system32/user32.dll reactos/system32/kernel32.dll \
    reactos/system32/rpcrt4.dll reactos/system32/msvcrt.dll reactos/system32/advapi32.dll \
    reactos/system32/ws2_32.dll reactos/system32/kernel32_vista.dll \
    reactos/system32/advapi32_vista.dll reactos/system32/ws2help.dll \
    reactos/system32/ntdll_vista.dll \
    reactos/system32/c_1252.nls reactos/system32/c_437.nls reactos/system32/l_intl.nls \
    reactos/system32/c_20127.nls \
    reactos/system32/config/system
  cp -f "$OUT/reactos/system32/ntdll.dll" "$OUT/ros-ntdll.dll"
  cp -f "$OUT/reactos/system32/smss.exe"  "$OUT/ros-smss.exe"
  # csrss.exe — the Win32 subsystem launcher smss starts (SmpLoadSubSystem). A thin PE (~7 KiB)
  # whose real work is in its ServerDlls (csrsrv/basesrv/winsrv).
  cp -f "$OUT/reactos/system32/csrss.exe" "$OUT/ros-csrss.exe"
  # csrsrv.dll — csrss.exe's static-import Server DLL (the Client-Server Runtime core, ~65 KiB).
  # The loader (LdrpWalkImportDescriptor) needs it or raises STATUS_DLL_NOT_FOUND.
  cp -f "$OUT/reactos/system32/csrsrv.dll" "$OUT/ros-csrsrv.dll"
  # basesrv.dll (~50 KiB) + winsrv.dll (~400 KiB) — csrss's dynamically-loaded ServerDlls
  # (CsrLoadServerDll, from its command line ServerDll=basesrv/winsrv). Needed or csrsrv raises
  # STATUS_DLL_NOT_FOUND during CsrServerInitialization.
  cp -f "$OUT/reactos/system32/basesrv.dll" "$OUT/ros-basesrv.dll"
  cp -f "$OUT/reactos/system32/winsrv.dll" "$OUT/ros-winsrv.dll"
  # gdi32.dll (~326 KiB) + user32.dll (~1.12 MiB) + kernel32.dll (~2.66 MiB) — the Win32 client
  # stack that winsrv.dll statically imports. Staged so csrss's loader can resolve + demand-page them.
  cp -f "$OUT/reactos/system32/gdi32.dll" "$OUT/ros-gdi32.dll"
  cp -f "$OUT/reactos/system32/user32.dll" "$OUT/ros-user32.dll"
  cp -f "$OUT/reactos/system32/kernel32.dll" "$OUT/ros-kernel32.dll"
  # winsrv's transitive import closure (7 DLLs, ~1.77 MiB): rpcrt4/msvcrt/advapi32/ws2_32 +
  # the vista API-set forwarders (kernel32_vista/advapi32_vista) + ws2help. Staged so csrss's
  # loader can resolve + demand-page the whole Win32 client-stack import graph.
  cp -f "$OUT/reactos/system32/rpcrt4.dll" "$OUT/ros-rpcrt4.dll"
  cp -f "$OUT/reactos/system32/msvcrt.dll" "$OUT/ros-msvcrt.dll"
  cp -f "$OUT/reactos/system32/advapi32.dll" "$OUT/ros-advapi32.dll"
  cp -f "$OUT/reactos/system32/ws2_32.dll" "$OUT/ros-ws2_32.dll"
  cp -f "$OUT/reactos/system32/kernel32_vista.dll" "$OUT/ros-kernel32_vista.dll"
  cp -f "$OUT/reactos/system32/advapi32_vista.dll" "$OUT/ros-advapi32_vista.dll"
  cp -f "$OUT/reactos/system32/ws2help.dll" "$OUT/ros-ws2help.dll"
  # ntdll_vista.dll (~57 KiB) — ReactOS's Vista-ntdll-API shim; csrss's init dynamically loads it
  # (or fails with STATUS_DLL_INIT_FAILED). Imports only ntdll (already staged).
  cp -f "$OUT/reactos/system32/ntdll_vista.dll" "$OUT/ros-ntdll_vista.dll"
  # The real regf SYSTEM registry hive — nt-hive-regf parses it so the NT registry serves smss's
  # real \Registry\Machine\System\...\Session Manager config (not a synthesized key).
  cp -f "$OUT/reactos/system32/config/system" "$OUT/ros-system.hiv"
  # NLS: c_1252 = ANSI (CP1252) MB<->WideChar tables, c_437 = OEM (CP437), l_intl = Unicode case
  # table. LdrpInitializeProcess needs these via PEB->{Ansi,Oem,UnicodeCaseTable}CodePageData for
  # RtlInitNlsTables / RtlUnicodeToMultiByteN.
  cp -f "$OUT/reactos/system32/c_1252.nls" "$OUT/ros-c1252.nls"
  cp -f "$OUT/reactos/system32/c_437.nls"  "$OUT/ros-c437.nls"
  cp -f "$OUT/reactos/system32/l_intl.nls" "$OUT/ros-lintl.nls"
  # c_20127 = US-ASCII (CP20127) MB<->WideChar table. csrss's Win32 client stack maps the named
  # section \Nls\NlsSectionCP20127 during a DllMain; missing it → STATUS_DLL_INIT_FAILED.
  cp -f "$OUT/reactos/system32/c_20127.nls" "$OUT/ros-c20127.nls"
fi

# win32k.sys (~2.1 MiB, PE32+) — the ReactOS GUI subsystem kernel driver. The ntos-executive
# loads it via the driver-host PE path (nt-pe-loader + nt-compat-exports) to run its DriverEntry
# and record its NtUser/NtGdi SSDT (Phase 2 of the graphics-subsystem plan). Extracted separately
# + idempotently so an ALREADY-cached staging (the guard above short-circuits) still gains it on
# the next run — no re-download needed (the ISO stays cached under $OUT/).
if [ ! -f "$OUT/ros-win32k.sys" ]; then
  W32K_ISO="$OUT/$(cd "$OUT" && ls *.iso 2>/dev/null | head -1)"
  if [ -f "$W32K_ISO" ]; then
    echo "extracting win32k.sys from $W32K_ISO ..."
    bsdtar -xf "$W32K_ISO" -C "$OUT" reactos/system32/win32k.sys
    cp -f "$OUT/reactos/system32/win32k.sys" "$OUT/ros-win32k.sys"
    echo "staged: ros-win32k.sys ($(stat -f%z "$OUT/ros-win32k.sys") bytes)"
  else
    echo "note: no cached ISO — win32k.sys not staged (the executive skips its win32k load)"
  fi
fi

# dxg.sys + dxgthk.sys — the DirectX kernel graphics driver + its thunk table. win32k's
# InitializeGreCSRSS -> DxDdStartupDxGraphics loads dxg.sys (EngLoadImage -> ZwSetSystemInformation
# SystemLoadGdiDriverInformation), which the executive hosts into win32k's VSpace; dxg imports
# dxgthk's Eng* thunks. Under system32/drivers/ (unlike win32k which is directly in system32/).
# ftfd.dll — the FreeType font driver. win32k STATICALLY imports 34 FT_* functions from it
# (win32k's import DLLs = ntoskrnl + hal + ftfd.dll); InitFontSupport → FT_Init_FreeType needs the
# real ftfd or the font subsystem stays uninitialized. Unlike dxg (dynamic, via ZwSetSystemInformation)
# ftfd is a static win32k import: the executive loads it at win32k bring-up + patches win32k's own IAT
# for the FT_* entries against ftfd's export table. Directly in system32/ (like win32k.sys).
if [ ! -f "$OUT/ros-ftfd.dll" ]; then
  FTFD_ISO="$OUT/$(cd "$OUT" && ls *.iso 2>/dev/null | head -1)"
  if [ -f "$FTFD_ISO" ]; then
    echo "extracting ftfd.dll from $FTFD_ISO ..."
    bsdtar -xf "$FTFD_ISO" -C "$OUT" reactos/system32/ftfd.dll
    cp -f "$OUT/reactos/system32/ftfd.dll" "$OUT/ros-ftfd.dll"
    echo "staged: ros-ftfd.dll ($(stat -f%z "$OUT/ros-ftfd.dll") bytes)"
  else
    echo "note: no cached ISO — ftfd.dll not staged"
  fi
fi

# framebuf.dll — the generic linear-framebuffer DISPLAY driver (12 KiB). win32k's desktop-graphics
# init (co_IntInitializeDesktopGraphics → PDEVOBJ_Create) loads it via LDEVOBJ_pLoadDriver →
# ZwSetSystemInformation(SystemLoadGdiDriverInformation), which the executive hosts into win32k's
# VSpace (like dxg.sys). framebuf imports 11 Eng*/PALOBJ from win32k.sys and queries the video
# miniport over EngDeviceIoControl; the executive intercepts those IOCTLs to feed it the BOOTBOOT
# framebuffer, so framebuf enables the primary surface → PIXELS. Directly in system32/.
if [ ! -f "$OUT/ros-framebuf.dll" ]; then
  FB_ISO="$OUT/$(cd "$OUT" && ls *.iso 2>/dev/null | head -1)"
  if [ -f "$FB_ISO" ]; then
    echo "extracting framebuf.dll from $FB_ISO ..."
    bsdtar -xf "$FB_ISO" -C "$OUT" reactos/system32/framebuf.dll
    cp -f "$OUT/reactos/system32/framebuf.dll" "$OUT/ros-framebuf.dll"
    echo "staged: ros-framebuf.dll ($(stat -f%z "$OUT/ros-framebuf.dll") bytes)"
  else
    echo "note: no cached ISO — framebuf.dll not staged"
  fi
fi

for drv in dxg dxgthk; do
  if [ ! -f "$OUT/ros-$drv.sys" ]; then
    DRV_ISO="$OUT/$(cd "$OUT" && ls *.iso 2>/dev/null | head -1)"
    if [ -f "$DRV_ISO" ]; then
      echo "extracting $drv.sys from $DRV_ISO ..."
      bsdtar -xf "$DRV_ISO" -C "$OUT" "reactos/system32/drivers/$drv.sys"
      cp -f "$OUT/reactos/system32/drivers/$drv.sys" "$OUT/ros-$drv.sys"
      echo "staged: ros-$drv.sys ($(stat -f%z "$OUT/ros-$drv.sys") bytes)"
    else
      echo "note: no cached ISO — $drv.sys not staged"
    fi
  fi
done

# winlogon.exe (~225 KiB, PE32+) — the Session Manager's initial command (SmpExecuteInitialCommand).
# smss's SmpParseCommandLine probes it (RtlDosSearchPath_U ×N); staged so smss can launch it as the
# 3rd hosted process + run its ntdll loader (the winlogon bring-up). Extracted idempotently (like
# win32k.sys) so an already-cached staging gains it on the next run without a re-download.
if [ ! -f "$OUT/ros-winlogon.exe" ]; then
  WL_ISO="$OUT/$(cd "$OUT" && ls *.iso 2>/dev/null | head -1)"
  if [ -f "$WL_ISO" ]; then
    echo "extracting winlogon.exe from $WL_ISO ..."
    bsdtar -xf "$WL_ISO" -C "$OUT" reactos/system32/winlogon.exe
    cp -f "$OUT/reactos/system32/winlogon.exe" "$OUT/ros-winlogon.exe"
    echo "staged: ros-winlogon.exe ($(stat -f%z "$OUT/ros-winlogon.exe") bytes)"
  else
    echo "note: no cached ISO — winlogon.exe not staged"
  fi
fi

# arial.ttf — a system font. win32k's desktop-graphics init font realize (TextIntRealizeFont) needs
# at least one loaded font or it null-derefs ("no fonts loaded at all"). The registry Fonts key is
# empty + \SystemRoot\Fonts doesn't exist in this host, so the executive feeds these bytes to
# win32k's IntGdiAddFontMemResource at bring-up. On the ISO at reactos/Fonts/arial.ttf.
if [ ! -f "$OUT/ros-arial.ttf" ]; then
  FONT_ISO="$OUT/$(cd "$OUT" && ls *.iso 2>/dev/null | head -1)"
  if [ -f "$FONT_ISO" ]; then
    echo "extracting arial.ttf from $FONT_ISO ..."
    bsdtar -xf "$FONT_ISO" -C "$OUT" reactos/Fonts/arial.ttf
    cp -f "$OUT/reactos/Fonts/arial.ttf" "$OUT/ros-arial.ttf"
    echo "staged: ros-arial.ttf ($(stat -f%z "$OUT/ros-arial.ttf") bytes)"
  else
    echo "note: no cached ISO — arial.ttf not staged"
  fi
fi

# Resolve smss's ntdll imports against ntdll's export table -> imports.bin (the executive
# applies this patch table to smss's IAT at runtime).
python3 "$(dirname "$0")/gen_reactos_imports.py" "$OUT/ros-smss.exe" "$OUT/ros-ntdll.dll" "$OUT/imports.bin"

echo "staged: ros-ntdll.dll ($(stat -f%z "$OUT/ros-ntdll.dll") bytes), ros-smss.exe ($(stat -f%z "$OUT/ros-smss.exe") bytes), imports.bin"
