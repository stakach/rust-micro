#!/usr/bin/env bash
# Refresh codegen/ from the seL4/ submodule. Run after bumping seL4.
set -euo pipefail

cd "$(dirname "$0")/.."

cp seL4/include/object/structures_64.bf                              codegen/structures_64.bf
cp seL4/libsel4/include/api/syscall.xml                              codegen/syscall.xml
cp seL4/libsel4/include/interfaces/object-api.xml                    codegen/object-api.xml
cp seL4/libsel4/arch_include/x86/interfaces/object-api-arch.xml      codegen/object-api-arch.xml
cp seL4/libsel4/sel4_arch_include/x86_64/interfaces/object-api-sel4-arch.xml \
                                                                     codegen/object-api-sel4-arch.xml
cp seL4/include/arch/arm/arch/64/mode/object/structures.bf           codegen/structures_aarch64.bf
cp seL4/libsel4/arch_include/arm/interfaces/object-api-arch.xml      codegen/object-api-arm.xml
cp seL4/libsel4/sel4_arch_include/aarch64/interfaces/object-api-sel4-arch.xml \
                                                                     codegen/object-api-aarch64.xml

REV=$(git -C seL4 rev-parse HEAD 2>/dev/null || echo "unknown")
echo "refreshed codegen/ from seL4 @ $REV"
echo "remember to update the pinned revision in codegen/README.md"
