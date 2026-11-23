#!/usr/bin/env bash
# Stage files from a verified installed LiberNT image without changing the release image.
set -euo pipefail

cd "$(dirname "$0")/.."
manifest=vendor/libernt/manifest.txt
out=.tmp/libernt

value() {
  awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2); found = 1 } END { if (!found) exit 1 }' "$manifest"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify_sha256() {
  local actual
  actual="$(sha256_file "$1")"
  if [ "$actual" != "$2" ]; then
    echo "error: SHA-256 mismatch for $1: expected $2, got $actual" >&2
    exit 1
  fi
}

verify_tree() {
  local actual
  actual="$(python3 scripts/hash_libernt_tree.py "$1")"
  if [ "$actual" != "$tree_sha" ]; then
    echo "error: installed tree SHA-256 mismatch: expected $tree_sha, got $actual" >&2
    exit 1
  fi
}

for tool in awk curl 7zz mktemp mv python3 rm; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: $tool is required to stage the installed LiberNT image" >&2
    exit 1
  }
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "error: sha256sum or shasum is required" >&2
  exit 1
fi

release="$(value release)"
archive="$(value archive)"
archive_sha="$(value archive_sha256)"
image="$(value image)"
image_sha="$(value image_sha256)"
tree_sha="$(value tree_sha256)"
ntdll_sha="$(value ntdll_sha256)"
acpi_sha="$(value acpi_sha256)"
smss_sha="$(value smss_sha256)"
revision="$(value source_revision)"
bochs_inf_path="$(value bochs_inf_path)"
bochs_inf_sha="$(value bochs_inf_sha256)"
url="https://github.com/ahmedarif193/LiberNT/releases/download/$release/$archive"
mkdir -p "$out"
if [ ! -f "$out/bochsmp.inf" ]; then
  curl -fL --retry 3 \
    -o "$out/bochsmp.inf.part" \
    "https://raw.githubusercontent.com/ahmedarif193/LiberNT/$revision/$bochs_inf_path"
  verify_sha256 "$out/bochsmp.inf.part" "$bochs_inf_sha"
  mv "$out/bochsmp.inf.part" "$out/bochsmp.inf"
fi
verify_sha256 "$out/bochsmp.inf" "$bochs_inf_sha"
archive_path="${LIBERNT_ARCHIVE_PATH:-$out/$archive}"

required=(
  Windows/explorer.exe
  Windows/system32/ntdll.dll
  Windows/system32/smss.exe
  Windows/system32/winlogon.exe
  Windows/system32/win32k.sys
  Windows/system32/config/system
  Windows/system32/config/software
  Windows/system32/config/security
  Windows/system32/config/sam
  Windows/system32/config/default
  Users/Default
)
complete=1
[ "$(cat "$out/.image-sha256" 2>/dev/null || true)" = "$image_sha" ] || complete=0
for path in "${required[@]}"; do
  [ -e "$out/tree/$path" ] || complete=0
done
if [ "$complete" = 1 ]; then
  verify_tree "$out/tree"
  verify_sha256 "$out/tree/Windows/system32/ntdll.dll" "$ntdll_sha"
  verify_sha256 "$out/tree/Windows/system32/drivers/acpi.sys" "$acpi_sha"
  verify_sha256 "$out/tree/Windows/system32/smss.exe" "$smss_sha"
  echo "verified LiberNT userspace already staged in $out/tree"
  exit 0
fi

if [ -z "${LIBERNT_ARCHIVE_PATH:-}" ] && [ ! -f "$archive_path" ]; then
  echo "downloading pinned LiberNT installed AMD64 image..."
  curl -fL --retry 3 -o "$out/$archive.part" "$url"
  verify_sha256 "$out/$archive.part" "$archive_sha"
  mv "$out/$archive.part" "$out/$archive"
fi
verify_sha256 "$archive_path" "$archive_sha"

work="$(mktemp -d "$out/extract.XXXXXX")"
trap 'rm -rf "$work"' EXIT
7zz x -y -o"$work" "$archive_path" "$image" >/dev/null
verify_sha256 "$work/$image" "$image_sha"
7zz x -y -o"$work/partitions" "$work/$image" 1.ntfs >/dev/null
mkdir -p "$work/tree"
7zz x -y -o"$work/tree" "$work/partitions/1.ntfs" >/dev/null
for path in "${required[@]}"; do
  [ -e "$work/tree/$path" ] || {
    echo "error: LiberNT image is missing $path" >&2
    exit 1
  }
done
verify_tree "$work/tree"
verify_sha256 "$work/tree/Windows/system32/ntdll.dll" "$ntdll_sha"
verify_sha256 "$work/tree/Windows/system32/drivers/acpi.sys" "$acpi_sha"
verify_sha256 "$work/tree/Windows/system32/smss.exe" "$smss_sha"
rm -rf "$out/tree"
mv "$work/tree" "$out/tree"
printf '%s\n' "$image_sha" > "$out/.image-sha256"
echo "staged verified LiberNT userspace in $out/tree"
