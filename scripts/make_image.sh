#!/usr/bin/env bash
# make_image.sh — build a Simpleboot GPT/ESP disk image containing the kernel
# and the rootserver initrd module.
set -euo pipefail

cd "$(dirname "$0")/.."

missing=()
for tool in cc cmp curl cp dd find mkdir mv patch python3 rm tar wc; do
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
SEH_LINKAGE=.tmp/nt-seh-linkage.dll

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
    production|pending-start|live-device-action|seh-driver|seh-terminal-unhandled|seh-terminal-exit|mup-provider|source-irp-integration|file-acceptance|font-cleanup) ;;
    *)
      echo "error: unsupported staged image profile: $IMAGE_PROFILE" >&2
      exit 1
      ;;
  esac
  if [ "${NTOS_IMAGE_PROFILE:-production}" != "$IMAGE_PROFILE" ]; then
    echo "error: staged hive profile '$IMAGE_PROFILE' does not match requested '${NTOS_IMAGE_PROFILE:-production}'" >&2
    exit 1
  fi
  if [ ! -s "$SEH_LINKAGE" ]; then
    echo "error: verified SEH linkage missing at $SEH_LINKAGE — rebuild the NT rootserver" >&2
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

  # Simpleboot's upstream FAT allocator rescans from cluster 3 for every
  # 512-byte block. The pinned LiberNT tree includes large DLLs, so apply our
  # checked source patch before building the host image creator.
  if ! grep -q 'LIBERNT_FAST_FAT_ALLOC' "$SIMPLEBOOT_SRC_DIR/simpleboot.c"; then
    patch -d "$SIMPLEBOOT_SRC_DIR" -p0 < scripts/patches/simpleboot-fat-allocation.patch >&2
  fi

  if [ ! -x "$SIMPLEBOOT_BIN" ] || [ "$SIMPLEBOOT_BIN" -ot "$SIMPLEBOOT_SRC_DIR/simpleboot.c" ]; then
    echo "building Simpleboot image creator..." >&2
    (
      cd "$SIMPLEBOOT_SRC_DIR"
      cc -O2 -ansi -Wall -Wextra simpleboot.c -o ../simpleboot
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

IMAGE_MIB="${IMAGE_MIB:-1024}"
PERSIST_IMAGE_MIB="${PERSIST_IMAGE_MIB:-32}"
if [ "$PERSIST_IMAGE_MIB" -ne 0 ] && [ "$PERSIST_IMAGE_MIB" -ne 16 ] && [ "$PERSIST_IMAGE_MIB" -lt 32 ]; then
  echo "error: PERSIST_IMAGE_MIB must be 0, 16 (legacy snapshots), or at least 32 (snapshots plus append area)" >&2
  exit 1
fi
if [ "$IMAGE_MIB" -lt 35 ]; then
  echo "error: IMAGE_MIB must be at least 35 for Simpleboot FAT32 images" >&2
  exit 1
fi
BOOT_PARTITION_MIB="${BOOT_PARTITION_MIB:-$((IMAGE_MIB - 2))}"
if [ "$BOOT_PARTITION_MIB" -lt 33 ] || [ "$BOOT_PARTITION_MIB" -ge "$IMAGE_MIB" ]; then
  echo "error: BOOT_PARTITION_MIB must be at least 33 and smaller than IMAGE_MIB" >&2
  exit 1
fi

python3 scripts/verify_elf_layout.py validate "$KERNEL" "$ROOTSERVER"

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

python3 scripts/verify_elf_layout.py compare "$KERNEL" "$ESP_STAGE/kernel"
python3 scripts/verify_elf_layout.py compare "$ROOTSERVER" "$INITRD_STAGE/boot/rootserver"

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

if [ ! -f .tmp/libernt/.image-sha256 ] || [ ! -d .tmp/libernt/tree/Windows ]; then
  echo "error: verified LiberNT userspace absent; run scripts/fetch_libernt.sh" >&2
  exit 1
fi
OUR_NTDLL=../.tmp/nt-ntdll.dll
if [ ! -s "$OUR_NTDLL" ]; then
  echo "error: source-built ntdll absent at $OUR_NTDLL — run scripts/build_ntdll_dll.sh" >&2
  exit 1
fi
cargo run -q --manifest-path ../Cargo.toml -p ntdll-dll-verify -- --compare-exports \
  .tmp/libernt/tree/Windows/system32/ntdll.dll \
  "$OUR_NTDLL"
python3 scripts/gen_reactos_imports.py \
  .tmp/libernt/tree/Windows/system32/smss.exe \
  "$OUR_NTDLL" \
  .tmp/libernt/imports.bin
stage_file .tmp/libernt/imports.bin "$ESP_STAGE/IMPORTS.BIN"
echo "staging the installed LiberNT tree into the Simpleboot ESP..."
t0=$(date +%s)
cp -R .tmp/libernt/tree/. "$ESP_STAGE/"
t1=$(date +%s)
echo "LiberNT tree staged ($(find .tmp/libernt/tree -type f | wc -l | tr -d ' ') files, $((t1 - t0))s)"
stage_file "$OUR_NTDLL" "$ESP_STAGE/Windows/system32/ntdll.dll"
echo "source-built ntdll staged: Windows/system32/ntdll.dll"

if [ -f .tmp/hive.dat ]; then
  stage_file "$SEH_LINKAGE" "$ESP_STAGE/Windows/system32/nt-seh-linkage.dll"
  echo "SEH linkage added: Windows/system32/nt-seh-linkage.dll"
fi

FIXTURES=../crates/nt-driver-test-fixtures/fixtures
if [ -d "$FIXTURES" ]; then
  mkdir -p "$ESP_STAGE/Windows/system32/drivers"

  for fixture_path in "$FIXTURES"/*.sys; do
    [ -f "$fixture_path" ] || continue
    fx=$(basename "$fixture_path")
    if [ "$fx" = "PendingStartTest.sys" ] && [ "$IMAGE_PROFILE" != "pending-start" ]; then
      continue
    fi
    stage_file "$fixture_path" "$ESP_STAGE/Windows/system32/drivers/$fx"
    echo "driver test fixture staged: Windows/system32/drivers/$fx"
  done

  if [ "$IMAGE_PROFILE" = "seh-driver" ] || \
     [ "$IMAGE_PROFILE" = "seh-terminal-unhandled" ] || \
     [ "$IMAGE_PROFILE" = "seh-terminal-exit" ]; then
    case "$IMAGE_PROFILE" in
      seh-driver) SEH_DRIVER=../.tmp/native-driver-seh/driver_seh.sys ;;
      seh-terminal-unhandled) SEH_DRIVER=../.tmp/native-driver-seh-terminal-unhandled/driver_seh.sys ;;
      seh-terminal-exit) SEH_DRIVER=../.tmp/native-driver-seh-terminal-exit/driver_seh.sys ;;
    esac
    if [ ! -s "$SEH_DRIVER" ]; then
      echo "error: verified native SEH driver missing at $SEH_DRIVER — run tests/native/driver_seh/build.sh" >&2
      exit 1
    fi
    stage_file "$SEH_DRIVER" "$ESP_STAGE/Windows/system32/drivers/driver_seh.sys"
    echo "native SEH driver staged: Windows/system32/drivers/driver_seh.sys"
  fi

  if [ "$IMAGE_PROFILE" = "mup-provider" ]; then
    MUP_PROVIDER=../.tmp/native-mup-provider/mup_provider.sys
    READ_FORWARD=../.tmp/native-mup-provider/read_forward.sys
    if [ ! -s "$MUP_PROVIDER" ]; then
      echo "error: native Mup provider missing at $MUP_PROVIDER — run tests/native/mup_provider/build.sh" >&2
      exit 1
    fi
    stage_file "$MUP_PROVIDER" "$ESP_STAGE/Windows/system32/drivers/mup_provider.sys"
    echo "native Mup provider staged: Windows/system32/drivers/mup_provider.sys"
    if [ ! -s "$READ_FORWARD" ]; then
      echo "error: native READ source missing at $READ_FORWARD — run tests/native/mup_provider/build.sh" >&2
      exit 1
    fi
    stage_file "$READ_FORWARD" "$ESP_STAGE/Windows/system32/drivers/read_forward.sys"
    echo "native READ source staged: Windows/system32/drivers/read_forward.sys"
  fi

  if [ "$IMAGE_PROFILE" = source-irp-integration ]; then
    for name in source_irp_target source_irp_probe; do
      SOURCE_IRP=../.tmp/native-source-irp/$name.sys
      if [ ! -s "$SOURCE_IRP" ]; then
        echo "error: native source IRP fixture missing at $SOURCE_IRP - run tests/native/source_irp/build.sh" >&2
        exit 1
      fi
      stage_file "$SOURCE_IRP" "$ESP_STAGE/Windows/system32/drivers/$name.sys"
    done
  fi

  if [ "$IMAGE_PROFILE" = file-acceptance ]; then
    FILE_ACCEPTANCE=../.tmp/native-file-acceptance/file_acceptance.exe
    if [ ! -s "$FILE_ACCEPTANCE" ]; then
      echo "error: native file fixture missing at $FILE_ACCEPTANCE - run tests/native/file_acceptance/build.sh" >&2
      exit 1
    fi
    stage_file "$FILE_ACCEPTANCE" "$ESP_STAGE/Windows/system32/file_acceptance.exe"
  fi

  if [ "$IMAGE_PROFILE" = font-cleanup ]; then
    for name in font_run_setup font_acceptance; do
      FONT_CLEANUP=../.tmp/native-font-cleanup/$name.exe
      if [ ! -s "$FONT_CLEANUP" ]; then
        echo "error: native font fixture missing at $FONT_CLEANUP - run tests/native/font_cleanup/build.sh" >&2
        exit 1
      fi
    done
    for name in font_run_setup font_acceptance; do
      stage_file "../.tmp/native-font-cleanup/$name.exe" "$ESP_STAGE/Windows/system32/$name.exe"
    done
  fi

fi

cmp .tmp/libernt/tree/Windows/system32/drivers/acpi.sys \
  "$ESP_STAGE/Windows/system32/drivers/acpi.sys"
cmp "$OUR_NTDLL" "$ESP_STAGE/Windows/system32/ntdll.dll"

SIMPLEBOOT_TOOL="$(ensure_simpleboot)"
rm -f "$IMAGE"
"$SIMPLEBOOT_TOOL" -c -vv -s "$IMAGE_MIB" -b "$BOOT_PARTITION_MIB" "$ESP_STAGE" "$IMAGE"

if [ "$PERSIST_IMAGE_MIB" -gt 0 ]; then
  dd if=/dev/zero bs=1M count="$PERSIST_IMAGE_MIB" status=none >> "$IMAGE"
  echo "persistent reserve appended: ${PERSIST_IMAGE_MIB} MiB after Simpleboot image (first 16 MiB snapshots; next 16 MiB reserved for append when present)"
fi

echo "disk image ready: $IMAGE ($((IMAGE_MIB + PERSIST_IMAGE_MIB)) MiB; ESP ${BOOT_PARTITION_MIB} MiB)"
