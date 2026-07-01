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
- **M7 binding on the kernel** — `surt-core` builds into the rust-micro rootserver
  and three microtests pass in QEMU: **single-thread**, **two-thread** (one VSpace,
  coalesced-wakeup ping-pong over a real seL4 Notification), and — the real goal —
  **multiprocess**: a producer and a consumer in **separate address spaces (PML4s)**
  sharing one ring **frame**, granted by `CNode_Copy`'ing the frame cap and
  double-mapping it. The consumer runs surt-core unchanged in a fresh VSpace (the
  rootserver image mapped read-only + a private stack), proving the transport works
  cross-address-space exactly as the design doc (§4, §7, §10) specs. `Sel4Notify` is
  implemented; the integration surfaced+fixed real bugs (an `ep_recv` register
  clobber, child stack alignment, linker large-model sections) and a whole class of
  stale rootserver ABI constants (invocation labels, slot layout, register/reply
  ABI) that had drifted from the kernel. See [`tasks/todo.md`](tasks/todo.md).

```sh
cargo run -p surt-bench --release   # run the host benchmarks
```

## Building / testing (host)

```sh
cargo test --workspace                              # all unit + stress tests
cargo clippy --all-targets --all-features -- -D warnings
cargo build -p surt-core                            # compiles with #![no_std] active
```
