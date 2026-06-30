# sel4-user-ring (SURT)

An io_uring/virtqueue-inspired **shared-memory ring transport** for fast,
asynchronous communication between isolated seL4 user-space components.

SURT is *not* a Linux io_uring clone and needs no kernel support beyond normal
seL4 mechanisms (endpoints, notifications, capability transfer, shared frames).
It is domain-neutral: no driver/filesystem/network/device semantics live in the
transport — higher-level protocols layer their own opcodes on top.

## Design pillars

- **Policy out of the kernel** — all queue management is user-space code.
- **Shared memory for data, endpoints for authority** — fast-path request and
  completion data move through shared rings; grants/teardown move through seL4
  IPC + capabilities.
- **Descriptors, not pointers** — cross-domain entries use ids and offsets, never
  raw pointers, references, or `usize`.
- **No hot-path allocation** — setup may allocate; push/pop must not.
- **Untrusted-peer safe** — each peer validates the other's queue metadata,
  descriptor lengths, buffer ids, and generation counters.
- **Small, audited `unsafe` surface** — confined to shared-memory projection and
  atomic ring manipulation; every `unsafe` block carries a `SAFETY:` comment.

## Workspace layout

```
crates/
  surt-abi/    stable shared-memory ABI (no_std, no alloc, no seL4)   [M1 ✅]
  surt-core/   SPSC ring + buffer registry + wakeups (host-testable)  [M2-M4 ✅]
  surt-sel4/   seL4 binding (frames, notifications, control endpoint) [M7]
  surt-host/   host test runtime
  surt-trace/  optional tracing
tools/
  surt-bench/  host benchmarks (throughput / latency / wakeup policy) [M5 ✅]
```

## Status

- **M1 `surt-abi` ✅** — identifiers, status, SQE/CQE, ring header (three
  cache-line-separated regions), buffer descriptor, opcodes, feature flags,
  compile-time layout assertions.
- **M2 `surt-core` ✅** — SPSC ring over caller-provided shared memory:
  `Producer`/`Consumer` with `try_push`/`push_batch`/`try_pop`/`pop_batch`,
  cached cursors, release/acquire ordering, defensive untrusted-peer cursor
  validation, `QueuePair` bundles. Verified by 2M + 1M-entry two-thread stress
  tests. `#![no_std]`, no hot-path allocation.
- **M3 buffer registry ✅** — `BufferRegistry` of registered shared buffers with
  generation counters (stale ids rejected after unregister), bounds + rights
  validation, `Ownership` modes, and `validate_sqe` checking submission entries
  against the registry. Pure safe code, no allocation.
- **M4 notification backend ✅** — backend-neutral `Notify` trait + `NoNotify`,
  and the lost-wakeup-free coalescing protocol (`Consumer::prepare_wait` ↔
  `Producer::notify_consumer`, two `SeqCst` fences). `NotifyingProducer` wrapper.
  Proven by a 20k-entry blocking stress test (slow producer + condvar backend)
  that completes without ever losing a wakeup.
- **M5 benchmarks ✅** — `surt-bench` measures one-way throughput, round-trip
  latency (percentiles), and the coalesced-vs-naive wakeup comparison. Sample on
  an Apple-Silicon host: **~410 Mops/s** (batch 64), **~125 ns** round-trip p50,
  **~59×** fewer wakeups with coalescing.
- **M6 seL4-binding design ✅** — [`docs/architecture/surt_sel4_binding.md`](docs/architecture/surt_sel4_binding.md):
  control-path handshake, capability transfer, fault/teardown, the wait loop, and
  the `surt-sel4` API + implementation order.
- **M7 binding on the kernel — PARTIAL** — `surt-core` builds into the rust-micro
  rootserver and a **single-thread ring microtest passes in QEMU** (the transport
  runs unchanged on the real seL4 ABI). `Sel4Notify` is implemented; the
  integration surfaced and fixed three real kernel-side bugs (an `ep_recv`
  register-clobber miscompile, a child stack-alignment requirement, and missing
  large-model sections in the rootserver linker script). The two-thread
  cross-thread test is implemented but disabled — an unresolved rootserver
  child-spawn interaction, independent of surt-core. See [`tasks/todo.md`](tasks/todo.md).

```sh
cargo run -p surt-bench --release   # run the host benchmarks
```

## Building / testing (host)

```sh
cargo test --workspace                              # all unit + stress tests
cargo clippy --all-targets --all-features -- -D warnings
cargo build -p surt-core                            # compiles with #![no_std] active
```
