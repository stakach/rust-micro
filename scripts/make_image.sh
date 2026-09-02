#!/usr/bin/env bash
# make_image.sh — build a Simpleboot GPT/ESP disk image containing the kernel
# and the rootserver initrd module.
set -euo pipefail

cd "$(dirname "$0")/.."

missing=()
for tool in cc curl cp dd find mkdir mv rm tar wc; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "error: missing required tools: ${missing[*]}" >&2
  echo "       macOS: xcode-select --install; brew install qemu" >&2
  echo "       Linux: apt install build-essential qemu-system-x86" >&2
  exit 1
fi

mkdir -p .tmp
IMAGE=.tmp/disk.img
KERNEL=target/mykernel-x86/release/mykernel-rust
ROOTSERVER=.tmp/rootserver.elf
INITRD_STAGE=.tmp/initrd
ESP_STAGE=.tmp/simpleboot-esp
SIMPLEBOOT_SRC_DIR=.tmp/simpleboot-src
SIMPLEBOOT_BIN=.tmp/simpleboot
SIMPLEBOOT_REF="${SIMPLEBOOT_REF:-f5fa29fe6613dc20b3729e769c68f9435daa15d1}"
SIMPLEBOOT_RAW_BASE="${SIMPLEBOOT_RAW_BASE:-https://gitlab.com/bztsrc/simpleboot/-/raw/${SIMPLEBOOT_REF}/src}"
IMAGE_PROFILE_MARKER=.tmp/image-profile

if [ ! -f "$KERNEL" ]; then
  echo "error: kernel not built at $KERNEL — run scripts/build_kernel.sh first" >&2
  exit 1
fi
if [ ! -f "$ROOTSERVER" ]; then
  echo "error: rootserver not staged at $ROOTSERVER — run scripts/build_kernel.sh first" >&2
  exit 1
fi

IMAGE_PROFILE=production
if [ -f .tmp/hive.dat ]; then
  if [ ! -f "$IMAGE_PROFILE_MARKER" ]; then
    echo "error: image profile marker missing at $IMAGE_PROFILE_MARKER — rebuild the NT rootserver" >&2
    exit 1
  fi
  IMAGE_PROFILE=$(tr -d '\r\n' < "$IMAGE_PROFILE_MARKER")
  case "$IMAGE_PROFILE" in
    production|pending-start|live-device-action) ;;
    *)
      echo "error: unsupported staged image profile: $IMAGE_PROFILE" >&2
      exit 1
      ;;
  esac
  if [ "${NTOS_IMAGE_PROFILE:-production}" != "$IMAGE_PROFILE" ]; then
    echo "error: staged hive profile '$IMAGE_PROFILE' does not match requested '${NTOS_IMAGE_PROFILE:-production}'" >&2
    exit 1
  fi
fi

find_elf_strip() {
  if [ -n "${ELF_STRIP:-}" ]; then
    command -v "$ELF_STRIP" >/dev/null 2>&1 && {
      printf '%s\n' "$ELF_STRIP"
      return 0
    }
    echo "error: ELF_STRIP is set but not executable: $ELF_STRIP" >&2
    exit 1
  fi
  for tool in \
    x86_64-elf-strip \
    /opt/homebrew/opt/llvm/bin/llvm-strip \
    /usr/local/opt/llvm/bin/llvm-strip \
    llvm-strip \
    x86_64-linux-gnu-strip; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '%s\n' "$tool"
      return 0
    fi
  done
  if [ "$(uname)" != "Darwin" ] && command -v strip >/dev/null 2>&1; then
    printf '%s\n' strip
    return 0
  fi
  return 1
}

strip_elf_copy() {
  local path="$1"
  local strip_tool="$2"
  [ -n "$strip_tool" ] || return 0
  "$strip_tool" --strip-all "$path"
}

ensure_simpleboot() {
  if [ -n "${SIMPLEBOOT:-}" ]; then
    if command -v "$SIMPLEBOOT" >/dev/null 2>&1; then
      command -v "$SIMPLEBOOT"
      return 0
    fi
    if [ -x "$SIMPLEBOOT" ]; then
      printf '%s\n' "$SIMPLEBOOT"
      return 0
    fi
    echo "error: SIMPLEBOOT is set but not executable: $SIMPLEBOOT" >&2
    exit 1
  fi

  mkdir -p "$SIMPLEBOOT_SRC_DIR"
  for file in simpleboot.c loader.h data.h; do
    if [ ! -f "$SIMPLEBOOT_SRC_DIR/$file" ]; then
      echo "downloading Simpleboot $file..." >&2
      curl -fL -o "$SIMPLEBOOT_SRC_DIR/$file" "$SIMPLEBOOT_RAW_BASE/$file"
    fi
  done

  if [ ! -x "$SIMPLEBOOT_BIN" ] || [ "$SIMPLEBOOT_BIN" -ot "$SIMPLEBOOT_SRC_DIR/simpleboot.c" ]; then
    echo "building Simpleboot image creator..." >&2
    (
      cd "$SIMPLEBOOT_SRC_DIR"
      cc -ansi -Wall -Wextra simpleboot.c -o ../simpleboot
    )
  fi
  printf '%s\n' "$SIMPLEBOOT_BIN"
}

stage_file() {
  local src="$1"
  local dst="$2"
  local staged="${dst}.stage.$$"
  mkdir -p "$(dirname "$dst")"
  rm -f "$staged"
  cp "$src" "$staged"
  mv -f "$staged" "$dst"
}

IMAGE_MIB="${IMAGE_MIB:-256}"
PERSIST_IMAGE_MIB="${PERSIST_IMAGE_MIB:-16}"
if [ "$IMAGE_MIB" -lt 35 ]; then
  echo "error: IMAGE_MIB must be at least 35 for Simpleboot FAT32 images" >&2
  exit 1
fi
BOOT_PARTITION_MIB="${BOOT_PARTITION_MIB:-$((IMAGE_MIB - 2))}"
if [ "$BOOT_PARTITION_MIB" -lt 33 ] || [ "$BOOT_PARTITION_MIB" -ge "$IMAGE_MIB" ]; then
  echo "error: BOOT_PARTITION_MIB must be at least 33 and smaller than IMAGE_MIB" >&2
  exit 1
fi

rm -rf "$INITRD_STAGE" "$ESP_STAGE"
mkdir -p "$INITRD_STAGE/boot" "$ESP_STAGE"
cp "$KERNEL" "$ESP_STAGE/kernel"
cp "$ROOTSERVER" "$INITRD_STAGE/boot/rootserver"

if STRIP_TOOL="$(find_elf_strip)"; then
  strip_elf_copy "$ESP_STAGE/kernel" "$STRIP_TOOL"
  strip_elf_copy "$INITRD_STAGE/boot/rootserver" "$STRIP_TOOL"
else
  echo "warning: no ELF strip tool found; boot payloads will be larger" >&2
fi

tar --format=ustar \
    -C "$INITRD_STAGE" \
    -cf .tmp/initrd.tar \
    boot/rootserver
cp .tmp/initrd.tar "$ESP_STAGE/initrd.tar"

cat > "$ESP_STAGE/simpleboot.cfg" <<EOF
kernel kernel
module initrd.tar
framebuffer ${SIMPLEBOOT_FB_WIDTH:-1024} ${SIMPLEBOOT_FB_HEIGHT:-768} ${SIMPLEBOOT_FB_BPP:-32}
multicore ${SIMPLEBOOT_SMP_STACK:-65536}
verbose ${SIMPLEBOOT_BOOT_VERBOSE:-0}
EOF

if [ -f .tmp/hive.dat ]; then
  stage_file .tmp/hive.dat "$ESP_STAGE/SYSTEM.DAT"
  echo "registry hive added: SYSTEM.DAT"
fi

if [ -f .tmp/reactos/imports.bin ]; then
  stage_file .tmp/reactos/imports.bin "$ESP_STAGE/IMPORTS.BIN"
  echo "ReactOS import table added: IMPORTS.BIN"
fi

if [ "${STAGE_FLAT_REACTOS:-0}" = "1" ]; then
  echo "STAGE_FLAT_REACTOS=1: also staging the legacy flat ReactOS copies (debug)"
  for pair in \
    ros-csrss.exe:CSRSS.EXE ros-csrsrv.dll:CSRSRV.DLL ros-basesrv.dll:BASESRV.DLL \
    ros-winsrv.dll:WINSRV.DLL ros-win32k.sys:WIN32K.SYS ros-dxg.sys:DXG.SYS \
    ros-dxgthk.sys:DXGTHK.SYS ros-ftfd.dll:FTFD.DLL ros-framebuf.dll:FRAMEBUF.DLL \
    ros-arial.ttf:ARIAL.TTF ros-gdi32.dll:GDI32.DLL ros-user32.dll:USER32.DLL \
    ros-kernel32.dll:KERNEL32.DLL ros-rpcrt4.dll:RPCRT4.DLL ros-msvcrt.dll:MSVCRT.DLL \
    ros-advapi32.dll:ADVAPI32.DLL ros-ws2_32.dll:WS2_32.DLL ros-kernel32_vista.dll:K32VISTA.DLL \
    ros-advapi32_vista.dll:A32VISTA.DLL ros-ws2help.dll:WS2HELP.DLL ros-ntdll_vista.dll:NTDLLVIS.DLL \
    ros-smss.exe:SMSS.EXE ros-winlogon.exe:WINLOGON.EXE ros-userenv.dll:USERENV.DLL \
    ros-mpr.dll:MPR.DLL ros-system.hiv:ROSSYS.HIV \
    ros-c1252.nls:C_1252.NLS ros-c437.nls:C_437.NLS ros-lintl.nls:L_INTL.NLS ros-c20127.nls:C_20127.NLS; do
    src=".tmp/reactos/${pair%%:*}"
    dst="$ESP_STAGE/${pair##*:}"
    [ -f "$src" ] && stage_file "$src" "$dst"
  done
fi

REACTOS_TREE_STAGED=0
if [ -f .tmp/reactos/.fulltree-ok ] && [ -d .tmp/reactos/reactos ]; then
  echo "staging the full \\reactos tree into the Simpleboot ESP..."
  t0=$(date +%s)
  cp -R .tmp/reactos/reactos "$ESP_STAGE/"
  t1=$(date +%s)
  echo "full \\reactos tree staged ($(find .tmp/reactos/reactos -type f | wc -l | tr -d ' ') files, $((t1 - t0))s)"
  REACTOS_TREE_STAGED=1
else
  echo "note: full \\reactos tree not staged (.tmp/reactos/.fulltree-ok absent)"
fi

if [ -f .tmp/reactos/.profiles-ok ] && [ -d .tmp/reactos/Profiles ]; then
  cp -R .tmp/reactos/Profiles "$ESP_STAGE/"
  echo "user-profile tree staged: Profiles ($(find .tmp/reactos/Profiles -mindepth 1 | wc -l | tr -d ' ') entries)"
  mkdir -p "$ESP_STAGE/Profiles/Default User/Local Settings/Temp"
  echo "setup profile dir ensured: Profiles/Default User/Local Settings/Temp"
else
  echo "note: user-profile tree not staged (.tmp/reactos/.profiles-ok absent)"
fi

FIXTURES=../crates/nt-driver-test-fixtures/fixtures
OUR_NTDLL="../.tmp/nt-ntdll.dll"
if [ "$REACTOS_TREE_STAGED" = "1" ] || [ -f "$OUR_NTDLL" ] || [ -d "$FIXTURES" ]; then
  mkdir -p "$ESP_STAGE/reactos/system32/drivers"

  ACPI_PROVIDER=vendor/reactos-acpi/acpi.sys
  ./scripts/verify_reactos_acpi_provider.sh "$ACPI_PROVIDER"
  stage_file "$ACPI_PROVIDER" "$ESP_STAGE/reactos/system32/drivers/acpi.sys"
  ./scripts/verify_reactos_acpi_provider.sh "$ESP_STAGE/reactos/system32/drivers/acpi.sys"
  echo "patched ReactOS ACPI provider staged: reactos/system32/drivers/acpi.sys"

  for fixture_path in "$FIXTURES"/*.sys; do
    [ -f "$fixture_path" ] || continue
    fx=$(basename "$fixture_path")
    if [ "$fx" = "PendingStartTest.sys" ] && [ "$IMAGE_PROFILE" != "pending-start" ]; then
      continue
    fi
    stage_file "$fixture_path" "$ESP_STAGE/reactos/system32/drivers/$fx"
    echo "driver test fixture staged: reactos/system32/drivers/$fx"
  done

  if [ -f "$OUR_NTDLL" ]; then
    stage_file "$OUR_NTDLL" "$ESP_STAGE/reactos/system32/ntdll.dll"
    echo "our Rust ntdll staged AS reactos/system32/ntdll.dll ($(wc -c < "$OUR_NTDLL" | tr -d ' ') bytes)"
  elif [ "$REACTOS_TREE_STAGED" = "1" ]; then
    echo "ERROR: our Rust ntdll ($OUR_NTDLL) not built — run scripts/build_ntdll_dll.sh" >&2
    exit 1
  else
    echo "note: Rust ntdll not staged (ReactOS tree absent)"
  fi
fi

SIMPLEBOOT_TOOL="$(ensure_simpleboot)"
rm -f "$IMAGE"
"$SIMPLEBOOT_TOOL" -c -vv -s "$IMAGE_MIB" -b "$BOOT_PARTITION_MIB" "$ESP_STAGE" "$IMAGE"

if [ "$PERSIST_IMAGE_MIB" -gt 0 ]; then
  dd if=/dev/zero bs=1M count="$PERSIST_IMAGE_MIB" status=none >> "$IMAGE"
  echo "persistent snapshot reserve appended: ${PERSIST_IMAGE_MIB} MiB after Simpleboot image"
fi

echo "disk image ready: $IMAGE ($((IMAGE_MIB + PERSIST_IMAGE_MIB)) MiB; ESP ${BOOT_PARTITION_MIB} MiB)"
