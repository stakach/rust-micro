#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/vendor/reactos-acpi/manifest.txt"
PATCH="$ROOT/vendor/reactos-acpi/0001-ACPI-enumerate-provider-namespace-PDOs.patch"
ARTIFACT="${1:-$ROOT/vendor/reactos-acpi/acpi.sys}"

manifest_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); found = 1 } END { if (!found) exit 1 }' "$MANIFEST"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "error: sha256sum or shasum is required" >&2
    exit 1
  fi
}

verify_hash() {
  local path="$1"
  local expected="$2"
  local actual
  [ -f "$path" ] || {
    echo "error: required ReactOS ACPI provider artifact is missing: $path" >&2
    exit 1
  }
  actual="$(sha256_file "$path")"
  [ "$actual" = "$expected" ] || {
    echo "error: ReactOS ACPI provider hash mismatch for $path" >&2
    echo "       expected $expected" >&2
    echo "       actual   $actual" >&2
    exit 1
  }
}

verify_hash "$PATCH" "$(manifest_value provider_patch_sha256)"
verify_hash "$ARTIFACT" "$(manifest_value provider_acpi_sys_sha256)"

expected_bytes="$(manifest_value provider_acpi_sys_bytes)"
actual_bytes="$(wc -c < "$ARTIFACT" | tr -d ' ')"
[ "$actual_bytes" = "$expected_bytes" ] || {
  echo "error: ReactOS ACPI provider size mismatch for $ARTIFACT" >&2
  echo "       expected $expected_bytes bytes, actual $actual_bytes bytes" >&2
  exit 1
}

echo "verified ReactOS ACPI provider: $ARTIFACT ($actual_bytes bytes)"
