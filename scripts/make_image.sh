#!/usr/bin/env bash
# make_image.sh — wrap the freshly built kernel in a FAT32 EFI disk image.
# Works on macOS (Homebrew dosfstools+mtools) and Linux. Tools are looked up
# on PATH; on macOS, /opt/homebrew/sbin (where dosfstools installs mkfs.vfat)
# is added if it isn't already present.
set -euo pipefail

cd "$(dirname "$0")/.."

# macOS: Homebrew installs mkfs.vfat under sbin which isn't always on PATH.
if [ "$(uname)" = "Darwin" ]; then
  for d in /opt/homebrew/sbin /usr/local/sbin; do
    case ":$PATH:" in
      *":$d:"*) ;;
      *) [ -d "$d" ] && PATH="$d:$PATH" ;;
    esac
  done
fi

# Verify required tools.
missing=()
for tool in dd mkfs.vfat mmd mcopy curl; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "error: missing required tools: ${missing[*]}" >&2
  echo "       macOS: brew install qemu mtools dosfstools" >&2
  echo "       Linux: apt install dosfstools mtools" >&2
  exit 1
fi

mkdir -p .tmp
IMAGE=.tmp/disk.img
KERNEL=target/mykernel-x86/release/mykernel-rust
ROOTSERVER=.tmp/rootserver.elf

if [ ! -f "$KERNEL" ]; then
  echo "error: kernel not built at $KERNEL — run scripts/build_kernel.sh first" >&2
  exit 1
fi
if [ ! -f "$ROOTSERVER" ]; then
  echo "error: rootserver not staged at $ROOTSERVER — run scripts/build_kernel.sh first" >&2
  exit 1
fi

# Create a 64 MiB blank image and format as FAT32. macOS `dd` accepts the
# same `bs=1M count=64` syntax as GNU dd.
dd if=/dev/zero of="$IMAGE" bs=1M count=64 status=none
mkfs.vfat -F 32 "$IMAGE" >/dev/null

# mtools tries to detect floppy/cdrom devices; tell it to skip those checks
# since we're operating on a plain image file.
export MTOOLS_SKIP_CHECK=1

# Bootboot UEFI loader. Cache it under .tmp/ so repeated builds don't re-fetch.
if [ ! -f .tmp/bootboot.efi ]; then
  echo "downloading bootboot.efi..."
  curl -fL -o .tmp/bootboot.efi \
    https://gitlab.com/bztsrc/bootboot/raw/master/dist/bootboot.efi
fi

mmd -i "$IMAGE" ::efi
mmd -i "$IMAGE" ::efi/boot
mmd -i "$IMAGE" ::bootboot
mcopy -i "$IMAGE" .tmp/bootboot.efi ::efi/boot/bootx64.efi

# Phase 39 — pack kernel + rootserver into a USTAR tar archive at
# ::bootboot/INITRD. BOOTBOOT loads it into RAM, extracts sys/core
# as the kernel, and exposes the whole archive's physical address
# to the kernel via `bootboot.initrd_ptr` so userspace ELFs can be
# located at runtime (see src/initrd.rs).
INITRD_STAGE=.tmp/initrd
rm -rf "$INITRD_STAGE"
mkdir -p "$INITRD_STAGE/sys" "$INITRD_STAGE/boot"
cp "$KERNEL"     "$INITRD_STAGE/sys/core"
cp "$ROOTSERVER" "$INITRD_STAGE/boot/rootserver"

# Use a deterministic mtime so reproducible builds produce
# byte-identical archives. macOS bsdtar and GNU tar both support
# --format=ustar.
tar --format=ustar \
    -C "$INITRD_STAGE" \
    -cf .tmp/initrd.tar \
    sys/core boot/rootserver

mcopy -i "$IMAGE" .tmp/initrd.tar ::bootboot/INITRD

# P2: a real registry hive (nt-hive-core image) at ::SYSTEM.DAT for the Config Manager to
# read off the FS. Guarded so builds without a staged hive still succeed.
if [ -f .tmp/hive.dat ]; then
  mcopy -i "$IMAGE" .tmp/hive.dat ::SYSTEM.DAT
  echo "registry hive added: ::SYSTEM.DAT"
fi

# P3: real ReactOS x64 binaries (GPL, redistributable) for the executive to load via SEC_IMAGE.
# Staged by scripts/fetch_reactos.sh; guarded so a fresh clone that hasn't fetched still builds.
if [ -f .tmp/reactos/ros-csrss.exe ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-csrss.exe ::CSRSS.EXE
  echo "ReactOS csrss added: ::CSRSS.EXE"
fi
if [ -f .tmp/reactos/ros-csrsrv.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-csrsrv.dll ::CSRSRV.DLL
  echo "ReactOS csrsrv added: ::CSRSRV.DLL"
fi
if [ -f .tmp/reactos/ros-basesrv.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-basesrv.dll ::BASESRV.DLL
  echo "ReactOS basesrv added: ::BASESRV.DLL"
fi
if [ -f .tmp/reactos/ros-winsrv.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-winsrv.dll ::WINSRV.DLL
  echo "ReactOS winsrv added: ::WINSRV.DLL"
fi
# win32k.sys — the ReactOS GUI subsystem kernel driver (~2.1 MiB). Staged so the isolated
# win32k-service component can load it + run its DriverEntry (Phase 2b).
if [ -f .tmp/reactos/ros-win32k.sys ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-win32k.sys ::WIN32K.SYS
  echo "ReactOS win32k added: ::WIN32K.SYS"
fi
# dxg.sys + dxgthk.sys — DirectX kernel graphics driver + thunk table. win32k's InitializeGreCSRSS
# loads dxg.sys (the executive hosts it into win32k's VSpace at DxDdStartupDxGraphics time).
if [ -f .tmp/reactos/ros-dxg.sys ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-dxg.sys ::DXG.SYS
  echo "ReactOS dxg added: ::DXG.SYS"
fi
if [ -f .tmp/reactos/ros-dxgthk.sys ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-dxgthk.sys ::DXGTHK.SYS
  echo "ReactOS dxgthk added: ::DXGTHK.SYS"
fi
# ftfd.dll — FreeType font driver. win32k statically imports 34 FT_* from it; the executive hosts it
# into win32k's VSpace at bring-up + patches win32k's IAT (InitFontSupport → FT_Init_FreeType).
if [ -f .tmp/reactos/ros-ftfd.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-ftfd.dll ::FTFD.DLL
  echo "ReactOS ftfd added: ::FTFD.DLL"
fi
# framebuf.dll — generic linear-framebuffer display driver. win32k's desktop-graphics init loads it
# via ZwSetSystemInformation; the executive hosts it into win32k's VSpace + feeds it the framebuffer.
if [ -f .tmp/reactos/ros-framebuf.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-framebuf.dll ::FRAMEBUF.DLL
  echo "ReactOS framebuf added: ::FRAMEBUF.DLL"
fi
# arial.ttf — a system font. The executive feeds it to win32k's IntGdiAddFontMemResource at bring-up
# so the desktop-graphics font realize finds a real font (no registry Fonts / \SystemRoot\Fonts here).
if [ -f .tmp/reactos/ros-arial.ttf ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-arial.ttf ::ARIAL.TTF
  echo "ReactOS arial font added: ::ARIAL.TTF"
fi
# The Win32 client stack (gdi32/user32/kernel32) — winsrv.dll's static imports. Staged so csrss's
# loader can resolve + demand-page them.
if [ -f .tmp/reactos/ros-gdi32.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-gdi32.dll ::GDI32.DLL
  echo "ReactOS gdi32 added: ::GDI32.DLL"
fi
if [ -f .tmp/reactos/ros-user32.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-user32.dll ::USER32.DLL
  echo "ReactOS user32 added: ::USER32.DLL"
fi
if [ -f .tmp/reactos/ros-kernel32.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-kernel32.dll ::KERNEL32.DLL
  echo "ReactOS kernel32 added: ::KERNEL32.DLL"
fi
# winsrv's transitive import closure (rpcrt4/msvcrt/advapi32/ws2_32 + the vista forwarders +
# ws2help) — the disk 8.3 names are what storage_probe's dir_find reads; they can differ from the
# real DLL name (the loader never touches the disk — the executive fakes the file by registry stem).
if [ -f .tmp/reactos/ros-rpcrt4.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-rpcrt4.dll ::RPCRT4.DLL
  echo "ReactOS rpcrt4 added: ::RPCRT4.DLL"
fi
if [ -f .tmp/reactos/ros-msvcrt.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-msvcrt.dll ::MSVCRT.DLL
  echo "ReactOS msvcrt added: ::MSVCRT.DLL"
fi
if [ -f .tmp/reactos/ros-advapi32.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-advapi32.dll ::ADVAPI32.DLL
  echo "ReactOS advapi32 added: ::ADVAPI32.DLL"
fi
if [ -f .tmp/reactos/ros-ws2_32.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-ws2_32.dll ::WS2_32.DLL
  echo "ReactOS ws2_32 added: ::WS2_32.DLL"
fi
if [ -f .tmp/reactos/ros-kernel32_vista.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-kernel32_vista.dll ::K32VISTA.DLL
  echo "ReactOS kernel32_vista added: ::K32VISTA.DLL"
fi
if [ -f .tmp/reactos/ros-advapi32_vista.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-advapi32_vista.dll ::A32VISTA.DLL
  echo "ReactOS advapi32_vista added: ::A32VISTA.DLL"
fi
if [ -f .tmp/reactos/ros-ws2help.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-ws2help.dll ::WS2HELP.DLL
  echo "ReactOS ws2help added: ::WS2HELP.DLL"
fi
if [ -f .tmp/reactos/ros-ntdll_vista.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-ntdll_vista.dll ::NTDLLVIS.DLL
  echo "ReactOS ntdll_vista added: ::NTDLLVIS.DLL"
fi
if [ -f .tmp/reactos/ros-smss.exe ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-smss.exe ::SMSS.EXE
  echo "ReactOS smss added: ::SMSS.EXE"
fi
# winlogon.exe — the Session Manager's initial command. Staged so smss's SmpExecuteInitialCommand
# can find + launch it as the 3rd hosted process (the executive parses it PE32+ + spawns it).
if [ -f .tmp/reactos/ros-winlogon.exe ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-winlogon.exe ::WINLOGON.EXE
  echo "ReactOS winlogon added: ::WINLOGON.EXE"
fi
# userenv.dll + mpr.dll — two of winlogon.exe's static imports (the rest are already staged for
# csrss). Staged so winlogon's loader resolves its full import graph instead of DLL_NOT_FOUND.
if [ -f .tmp/reactos/ros-userenv.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-userenv.dll ::USERENV.DLL
  echo "ReactOS userenv added: ::USERENV.DLL"
fi
if [ -f .tmp/reactos/ros-mpr.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-mpr.dll ::MPR.DLL
  echo "ReactOS mpr added: ::MPR.DLL"
fi
if [ -f .tmp/reactos/ros-ntdll.dll ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-ntdll.dll ::NTDLL.DLL
  echo "ReactOS ntdll added: ::NTDLL.DLL"
  # P7 FS-backed-by-path proof: ALSO lay down the real install-tree path
  # \reactos\system32\ntdll.dll so the storage host can resolve + read it BY PATH
  # (a nested-directory walk), not just the flat root-level ::NTDLL.DLL. This is the
  # first brick of hosting the complete \reactos tree from a real FS. Hybrid: the flat
  # staged copy above remains as the fallback, so the boot stays green either way.
  mmd -i "$IMAGE" ::reactos 2>/dev/null || true
  mmd -i "$IMAGE" ::reactos/system32 2>/dev/null || true
  mcopy -i "$IMAGE" .tmp/reactos/ros-ntdll.dll ::reactos/system32/ntdll.dll
  echo "ReactOS ntdll staged BY PATH: ::reactos/system32/ntdll.dll"
fi
if [ -f .tmp/reactos/ros-system.hiv ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-system.hiv ::ROSSYS.HIV
  echo "ReactOS SYSTEM hive added: ::ROSSYS.HIV"
fi
if [ -f .tmp/reactos/imports.bin ]; then
  mcopy -i "$IMAGE" .tmp/reactos/imports.bin ::IMPORTS.BIN
  echo "ReactOS import table added: ::IMPORTS.BIN"
fi
# NLS code-page tables — LdrpInitializeProcess builds RtlUnicodeToMultiByteN's tables from these
# via PEB->{Ansi,Oem,UnicodeCaseTable}CodePageData.
if [ -f .tmp/reactos/ros-c1252.nls ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-c1252.nls ::C_1252.NLS
  echo "ReactOS ANSI NLS added: ::C_1252.NLS"
fi
if [ -f .tmp/reactos/ros-c437.nls ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-c437.nls ::C_437.NLS
  echo "ReactOS OEM NLS added: ::C_437.NLS"
fi
if [ -f .tmp/reactos/ros-lintl.nls ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-lintl.nls ::L_INTL.NLS
  echo "ReactOS case NLS added: ::L_INTL.NLS"
fi
if [ -f .tmp/reactos/ros-c20127.nls ]; then
  mcopy -i "$IMAGE" .tmp/reactos/ros-c20127.nls ::C_20127.NLS
  echo "ReactOS US-ASCII NLS added: ::C_20127.NLS"
fi

echo "disk image ready: $IMAGE"
