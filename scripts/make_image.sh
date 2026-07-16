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

# Create a 256 MiB blank image and format as FAT32. macOS `dd` accepts the same
# `bs=1M count=256` syntax as GNU dd. P7-A: grown 64->256 MiB to hold the COMPLETE
# \reactos install tree (~171 MiB) so the executive loads ANY binary BY PATH from the
# real FS. It stays a superfloppy (no partition table — the storage host reads FAT32
# from LBA 0); BOOTBOOT (UEFI) + our LBA48 AHCI reader both handle the larger volume.
IMAGE_MIB="${IMAGE_MIB:-256}"
dd if=/dev/zero of="$IMAGE" bs=1M count="$IMAGE_MIB" status=none
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

# P7-A: the ReactOS binaries are NO LONGER staged as flat ::NAME files. The executive's storage
# host reads every one of them BY PATH from the real \reactos install tree laid down below (smss,
# csrss, csrsrv, basesrv, winsrv, ntdll, the Win32 client stack, the vista forwarders, NLS tables,
# win32k/dxg/dxgthk/ftfd/framebuf, arial.ttf, winlogon, userenv, mpr, and the SYSTEM hive at
# system32\config\system) — proven by the exec_full_stack_from_fs spec (verdict 0x200, zero flat
# fallbacks). Only the two NON-tree, build-generated artifacts stay flat at the root: the synthetic
# Config-Manager hive ::SYSTEM.DAT (above) and the smss import-resolution table ::IMPORTS.BIN.
# (Set STAGE_FLAT_REACTOS=1 to also re-stage the flat ::NAME copies for A/B debugging.)
if [ -f .tmp/reactos/imports.bin ]; then
  mcopy -i "$IMAGE" .tmp/reactos/imports.bin ::IMPORTS.BIN
  echo "ReactOS import table added: ::IMPORTS.BIN"
fi
if [ "${STAGE_FLAT_REACTOS:-0}" = "1" ]; then
  echo "STAGE_FLAT_REACTOS=1: also staging the legacy flat ::NAME ReactOS copies (debug)"
  for pair in \
    ros-csrss.exe:CSRSS.EXE ros-csrsrv.dll:CSRSRV.DLL ros-basesrv.dll:BASESRV.DLL \
    ros-winsrv.dll:WINSRV.DLL ros-win32k.sys:WIN32K.SYS ros-dxg.sys:DXG.SYS \
    ros-dxgthk.sys:DXGTHK.SYS ros-ftfd.dll:FTFD.DLL ros-framebuf.dll:FRAMEBUF.DLL \
    ros-arial.ttf:ARIAL.TTF ros-gdi32.dll:GDI32.DLL ros-user32.dll:USER32.DLL \
    ros-kernel32.dll:KERNEL32.DLL ros-rpcrt4.dll:RPCRT4.DLL ros-msvcrt.dll:MSVCRT.DLL \
    ros-advapi32.dll:ADVAPI32.DLL ros-ws2_32.dll:WS2_32.DLL ros-kernel32_vista.dll:K32VISTA.DLL \
    ros-advapi32_vista.dll:A32VISTA.DLL ros-ws2help.dll:WS2HELP.DLL ros-ntdll_vista.dll:NTDLLVIS.DLL \
    ros-smss.exe:SMSS.EXE ros-winlogon.exe:WINLOGON.EXE ros-userenv.dll:USERENV.DLL \
    ros-mpr.dll:MPR.DLL ros-ntdll.dll:NTDLL.DLL ros-system.hiv:ROSSYS.HIV \
    ros-c1252.nls:C_1252.NLS ros-c437.nls:C_437.NLS ros-lintl.nls:L_INTL.NLS ros-c20127.nls:C_20127.NLS; do
    src=".tmp/reactos/${pair%%:*}"; dst="::${pair##*:}"
    [ -f "$src" ] && mcopy -i "$IMAGE" "$src" "$dst"
  done
fi

# P7-A: lay down the COMPLETE \reactos install tree so the executive resolves + reads ANY
# binary BY PATH (\reactos\system32\X.dll) from the real FS via fat_open_path — not just the
# curated flat ::NAME files above. Recursive mcopy of the whole tree (~171 MiB, ~1000 files;
# adds a few seconds to the image build). The flat ::NAME files above remain during the loader
# migration (hybrid), so the boot stays green if the tree is absent. Idempotent: fetch_reactos.sh
# stages it under .tmp/reactos/reactos with a .fulltree-ok marker.
if [ -f .tmp/reactos/.fulltree-ok ] && [ -d .tmp/reactos/reactos ]; then
  echo "staging the full \\reactos tree onto the image (recursive; ~171 MiB)..."
  t0=$(date +%s)
  mcopy -s -i "$IMAGE" .tmp/reactos/reactos ::
  t1=$(date +%s)
  echo "full \\reactos tree added: ::reactos ($(find .tmp/reactos/reactos -type f | wc -l | tr -d ' ') files, $((t1 - t0))s)"
else
  echo "note: full \\reactos tree not staged (.tmp/reactos/.fulltree-ok absent) — flat ::NAME files only"
fi

# Driver-model migration: stage the synthetic driver test fixtures (nt-driver-test-fixtures)
# BY-PATH under \reactos\system32\drivers so the executive launches them via the general dynamic
# `load_driver(fs, path, class)` path (like npfs.sys) — NOT baked in via include_bytes!. These are
# test drivers (PnP/MMIO NIC + KMDF lifecycle), not real ReactOS binaries, so they aren't in the
# fetched \reactos tree. Ensure the drivers dir exists (in case the tree wasn't staged), then copy.
FIXTURES=../crates/nt-driver-test-fixtures/fixtures
# When the full \reactos tree is staged, ::reactos/system32/drivers ALREADY exists (from the
# recursive mcopy above) — re-creating it with `mmd` is redundant AND has been observed to WEDGE
# mtools (a lock/race on the freshly written 256 MiB image → the build hangs for minutes at `mmd`,
# holding disk.img open). So only hand-create the dir when the tree was NOT staged, and run it once
# (it was previously inside the per-fixture loop, i.e. twice).
if [ ! -f .tmp/reactos/.fulltree-ok ] || [ ! -d .tmp/reactos/reactos ]; then
  mmd -i "$IMAGE" ::reactos ::reactos/system32 ::reactos/system32/drivers 2>/dev/null || true
fi
for fx in PnpMmioInterruptTest.sys KmdfBasicTest.sys; do
  if [ -f "$FIXTURES/$fx" ]; then
    mcopy -o -i "$IMAGE" "$FIXTURES/$fx" "::reactos/system32/drivers/$fx"
    echo "driver test fixture added: ::reactos/system32/drivers/$fx"
  fi
done

# ntdll_plan.md Step 4.A: stage OUR Rust ntdll (crates/nt-ntdll-dll, built to ../.tmp/nt-ntdll.dll
# by scripts/build_ntdll_dll.sh) BY PATH at \reactos\system32\nt-ntdll.dll — a distinct leaf so the
# real ReactOS ntdll.dll stays the pi>=1 fallback. The executive, when SMSS_USE_OUR_NTDLL is set,
# load_dll_from_fs's THIS file (not ntdll.dll) for smss (pi 0). Scripts-only; the executive picks it
# up purely via the FS-by-path loader. Absent (DLL not built) → the executive's OFF/miss fallback
# keeps the boot on the real ntdll, so the image build never fails on it.
OUR_NTDLL="../.tmp/nt-ntdll.dll"
if [ -f "$OUR_NTDLL" ]; then
  # The dir exists from the recursive \reactos tree mcopy (or the mmd above); -o overwrites.
  mmd -i "$IMAGE" ::reactos ::reactos/system32 2>/dev/null || true
  mcopy -o -i "$IMAGE" "$OUR_NTDLL" "::reactos/system32/nt-ntdll.dll"
  echo "Step 4.A: our Rust ntdll staged: ::reactos/system32/nt-ntdll.dll ($(wc -c < "$OUR_NTDLL" | tr -d ' ') bytes)"
else
  echo "note: our Rust ntdll ($OUR_NTDLL) not built — Step 4.A substitution unavailable (build_ntdll_dll.sh)"
fi

echo "disk image ready: $IMAGE ($IMAGE_MIB MiB)"
