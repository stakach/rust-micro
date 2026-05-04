# sel4test bring-up plan

## What we know after Phase 38a

`libsel4`'s build is split between **codegen** (Python scripts that
materialise C headers from XML) and **a single C source file**.

* `libsel4/src/sel4_bootinfo.c` — only ~30 lines, defines `__sel4_ipc_buffer` (the per-thread IPC buffer pointer), `bootinfo`, and the `seL4_GetBootInfo` / `seL4_InitBootInfo` accessors. Everything else in libsel4 is inline functions in headers.
* `libsel4/tools/`:
  - `invocation_header_gen.py` — produces `invocation.h` with the `enum invocation_label` (numbered to match our `InvocationLabel`).
  - `syscall_header_gen.py` — produces `syscall.h` with the `enum seL4_Syscall` and `seL4_DebugPutChar` etc. inline syscall stubs.
  - `syscall_stub_gen.py` — produces per-invocation C wrappers (`seL4_TCB_Configure`, `seL4_Untyped_Retype`, …).
  - `bitfield_gen.py` — produces struct accessors (`seL4_MessageInfo_get_label`, etc.) from `.bf` files.
* Same XML inputs we already use in `codegen/`, so numbers + bit layouts already match (modulo the smaller follow-ups noted in the audit doc).
* All Python scripts depend on `lxml` (and `jinja2` / `pyyaml` for the bitfield generator). Easiest path: a Python venv (`/tmp/sel4venv` works).

## Stage 1 — produce `libsel4.a`

1. Set up the venv once: `python3 -m venv .sel4venv && .sel4venv/bin/pip install lxml jinja2 pyyaml`.
2. Add a kernel-config header (`autoconf.h`) to drive libsel4's `#if defined(CONFIG_KERNEL_MCS)` etc. Need at least:
   * `CONFIG_KERNEL_MCS = 1`
   * `CONFIG_PRINTING = 1`
   * `CONFIG_DEBUG_BUILD = 1`
   * `CONFIG_WORD_SIZE = 64`
   * `CONFIG_X86_64`, `CONFIG_ARCH_X86`, `CONFIG_ARCH_X86_64` (or the modern names — check the headers).
   * `CONFIG_MAX_NUM_NODES`, `CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS` to match our values.
3. Run each Python script with the right `--xml` / `--dest` args to produce `<gen>/sel4/{invocation.h, syscall.h, types_gen.h, ...}`.
4. Compile `sel4_bootinfo.c` against `libsel4/include + arch_include/x86 + sel4_arch_include/x86_64 + <gen>` with `clang -ffreestanding -m64 -mno-sse -nostdlib`.
5. `ar rcs libsel4.a sel4_bootinfo.o`.

## Stage 2 — `hello, world` user ELF

Tiny C program (one file) that uses libsel4 to:
1. Read the bootinfo pointer from `rdi` (System V passing of `bootinfo` to `_start`).
2. Call `seL4_DebugPutChar('H')` … `seL4_DebugPutChar('\n')`.
3. Loop on `seL4_Yield()`.

Linker script: similar to `rootserver/link.ld`. Image starts at PML4[2] like our existing rootserver. Build a position-independent ELF.

Embed the resulting ELF as a byte array (replacing our current `rootserver_image::ROOTSERVER_ELF`) and let the existing rootserver loader run it. The kernel sees a different ELF — same boot path.

## Stage 3 — bring in one sel4test test

Two main flavours of sel4test:
* The **driver** harness (rootserver-side) — heavyweight, loads tests as separate threads from a CPIO archive, and runs hundreds of them.
* The **embedded** flavour — a single test binary with a hard-coded run-list.

Easier first target: pick the simplest test from `sel4test-tests/src/tests/`, say `tc_test_smallcaps` or `BASIC_001` (TCB lifecycle).

Compile it standalone against our `libsel4.a`. Each test is one C file + a few helpers. Build into a single ELF.

This stage is where the real iteration happens — every test that fails surfaces a concrete kernel gap. We've already closed the audit's six big gaps and four follow-ups, so the remaining ones should be small.

## Stage 4 — full sel4test driver + CPIO

Fold in `libsel4_platsupport`, `libsel4utils`, the CPIO loader, and the full `sel4test-driver`. This is the multi-week part.

## Realistic scoping

* Stages 1 + 2 are ~2–3 days of careful work.
* Stage 3 is open-ended; first test passing is ~1 week, then steady iteration.
* Stage 4 is months.

If the goal is "validate our kernel against seL4's tests", the higher-leverage move may be **continuing to expand microtest in Rust** with sel4test-equivalent coverage. Each microtest case is ~50 lines and runs in seconds; a comparable C-side test through real libsel4 + sel4test is much more friction.

Recommended path:
1. **Continue microtest** for a few more iterations covering the patterns we know sel4test exercises: badged endpoints, multi-recv queues, scheduler priority, fault delivery, IRQ ack/rearm, CSpace ops (Copy, Mint, Move, Revoke, Delete), VSpace ops (PT/PD/PDPT/PML4 retype + map + unmap), MCS budget exhaustion + refill.
2. Once microtest reaches ~25–30 cases covering all major subsystems, **start Stage 1** of the libsel4 build to validate end-to-end against the reference toolchain.
