# Codegen inputs

The files in this directory are pinned snapshots from the seL4 source tree
under `seL4/`. They are the *input* to `build.rs`, which emits Rust at
compile time. We treat `seL4/` as a read-only reference; never edit it
in place. When tracking a new seL4 release, regenerate the snapshots
with `./refresh.sh` and commit the diff.

| File | Source path under `seL4/` |
|---|---|
| `structures_64.bf` | `include/object/structures_64.bf` |
| `syscall.xml` | `libsel4/include/api/syscall.xml` |
| `object-api.xml` | `libsel4/include/interfaces/object-api.xml` |
| `object-api-arch.xml` | `libsel4/arch_include/x86/interfaces/object-api-arch.xml` |
| `object-api-sel4-arch.xml` | `libsel4/sel4_arch_include/x86_64/interfaces/object-api-sel4-arch.xml` |

Pinned upstream revision:

- repo: <https://github.com/seL4/seL4>
- commit: `daa0dfb1470c5ffbf13b3778f93111679574e80c`
- date: 2026-04-21
- VERSION: 15.0.0-dev
