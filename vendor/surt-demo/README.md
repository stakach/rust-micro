# surt-demo — SURT on the rust-micro kernel

A standalone seL4 **root task** that runs the [SURT](https://github.com/stakach/surt)
ring-transport scenarios on this kernel using the **published `surt-sel4` crate**
from crates.io. It is both a usage showcase ("how do I use SURT on my seL4?") and
a smoke-test (each scenario prints `PASS`/`FAIL`).

It is *not* part of the kernel build — `build.sh` compiles it separately and stages
its ELF as `.tmp/rootserver.elf`, mirroring how `vendor/sel4test/` is bootstrapped.
Only the source + scripts are tracked; `target/` is gitignored.

## What it demonstrates

The only kernel-specific code is `KernelEnv`, which implements `surt_sel4::Sel4Env`
in two syscalls (`signal` = Send-len-0, `wait` = Recv). Everything else drives the
published crate: `Sel4Notify` (the `Notify` adapter) and `drain_blocking` (the
coalesced consumer loop). Scenarios, in order:

1. **single_thread** — the ring runs unchanged on the real kernel ABI.
2. **two_thread_notify** — coalesced wakeup between two threads over a Notification.
3. **multiprocess** — producer + consumer in separate address spaces, shared ring frame.
4. **connect** — two isolated components discover + connect at runtime over a control endpoint.
5. **cap_transfer** — the flagship: two components with their own CSpaces; the ring frame
   + notification capabilities are transferred between the CSpaces over IPC. The consumer
   drains via `surt_sel4::drain_blocking`.

## Run it

```sh
# from the repo root — builds the demo, stages its ELF, builds the kernel, images it:
./scripts/build_kernel.sh surt-demo
# boot in QEMU (serial shows each scenario's PASS/FAIL, then the kernel exits):
./scripts/run_specs.sh
```

Expected tail:
```
[surt-demo] SURT ring transport on rust-micro via the published surt-sel4 crate
  PASS single_thread
  PASS two_thread_notify
  PASS multiprocess
  PASS connect
  PASS cap_transfer
[surt-demo summary: 5 passed, 0 failed]
```

## Layout

```
Cargo.toml     # depends on surt-sel4 = "0.1" (crates.io); own workspace root
triplet.json   # bare-metal x86-64 target (large code model, rust-lld, link.ld)
link.ld        # fixed load at 0x100000400000 + large-model sections
build.sh       # builds + stages .tmp/rootserver.elf
src/main.rs    # seL4 bootstrap (syscalls, invocation helpers, BootInfo, _start)
src/scenarios.rs # KernelEnv (Sel4Env impl) + the five scenarios
```
