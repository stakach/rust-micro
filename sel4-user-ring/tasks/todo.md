# SURT implementation plan

Milestone-ordered per the SURT spec §20. Each milestone is host-verifiable
(`cargo test`) before the next; the seL4 binding lands only after the host
transport is stable.

## Milestone 1 — `surt-abi` ✅ COMPLETE
- [x] Cargo workspace (`sel4-user-ring/`)
- [x] `crates/surt-abi` (no_std, no alloc, no seL4, no domain deps)
- [x] Identifiers (RequestId/BufferId/RingId/PeerId/ObjectId/UserData) with 24/40 generation split
- [x] `SurtStatus` + required status codes
- [x] `SurtSqe` (80 B), `SurtCqe` (48 B), `SurtBufferDesc` (40 B)
- [x] `SurtRingHeader` (192 B, three 64-B cache lines; producer/consumer separated)
- [x] Opcodes (transport-reserved + domain/experimental ranges)
- [x] Feature flags (+ `REQUIRED_V0_1`, `KNOWN`), buffer rights, role/state/flag consts
- [x] Compile-time size/align/offset assertions
- [x] Unit tests (7) + clippy + fmt clean
- **Gate:** `cargo test -p surt-abi` ✅, `cargo build` (no_std) ✅, clippy ✅, fmt ✅

## Milestone 2 — `surt-core` (host-testable SPSC ring) ✅ COMPLETE
- [x] `RingView` shared-memory projection over caller-provided bytes (`unsafe` attach + validation)
- [x] `Producer`/`Consumer` views; `QueuePair`/`QueuePairPeer`; `RingEntry` marker; `init_ring`/`ring_bytes`/`RingConfig`
- [x] SPSC ring: power-of-two len, monotonic head/tail, `idx = ctr & (len-1)`, cached cursors
- [x] full/empty via wrapping arithmetic; Acquire/Release publish/observe ordering
- [x] `try_push`/`push_batch`/`try_pop`/`pop_batch`/`available_capacity`/`available_entries`/`capacity`
- [x] structural / untrusted-peer validation (geometry once at attach, cached locally; cursor-movement bounds → `PopError::PeerFaulted`)
- [x] unit tests (8): init/invalid-init/full/empty/wraparound/batch/implausible-peer/layout
- [x] stress tests (2): 2M single + 1M random-batch, two host threads, randomized yields, FIFO+payload checks
- **Gate:** `cargo test -p surt-core` ✅, no_std build ✅, clippy (`undocumented_unsafe_blocks=deny`) ✅, fmt ✅
- **Deferred to M3:** descriptor *content* validation (opcode range, buffer id/gen, offset/len) — needs the buffer registry to validate against.

## Milestone 3 — buffer registry + descriptor validation ✅ COMPLETE
- [x] `BufferRegistry<CAP>` — fixed-capacity, no-alloc; `register`/`unregister`/`lookup`/`owner`/`len`
- [x] generation counters: `unregister` bumps generation; stale ids → `BadGeneration` (gen checked before occupancy)
- [x] bounds validation (`offset + len <= buffer.len`, overflow-safe) + rights subset check
- [x] `BufferRegion` (validated sub-region) + `Ownership` modes decoded from SQE flags (`surt_abi::sqe_flags`)
- [x] `validate_sqe` against the registry (opcode-range gap + buffer existence/generation/bounds) — the M2 deferral
- [x] unit tests (7): register/lookup/unregister, recycled-slot generation, bounds, rights, full/zero-len, validate_sqe, ownership
- **Gate:** `cargo test` ✅ (core now 15 unit), clippy ✅, fmt ✅, no_std ✅. `buffer.rs` is 100% safe code (no `unsafe`).

## Milestone 4 — notification backend ✅ COMPLETE
- [x] `Notify` trait (`wake`/`arm`/`disarm`) + `NotifyError`; blanket `Notify for &T` so producer+consumer share one backend
- [x] `NoNotify` no-op backend
- [x] coalesced-wakeup state machine: `Consumer::prepare_wait` (arm + SeqCst-fence + recheck → `WaitDecision`) ↔ `Producer::notify_consumer` (SeqCst-fence + flag check + clear-on-wake)
- [x] `NotifyingProducer<E, N>` wrapper (`try_push`/`push_batch` auto-wake)
- [x] lost-wakeup proof: 20k-entry blocking stress (slow producer, condvar backend) completes — no lost wakeup; wakes asserted `> 0` (exercised) and `<= N` (coalesced)
- **Gate:** `cargo test` ✅ (core now 16 unit + notify integration), clippy ✅, fmt ✅, no_std ✅
- **Note:** host condvar backend lives in the integration test; the blocking *wait* + seL4 backend land with `surt-sel4` (M7), per spec §9.4.

## Milestone 5 — benchmark tools (`tools/surt-bench`) ✅ COMPLETE
- [x] `tools/surt-bench` bin in the workspace; `cargo run -p surt-bench --release`
- [x] one-way throughput sweep (queue_len × batch) → Mops/s, ns/op
- [x] request/completion round-trip latency → p50/p95/p99/p99.9/max ns
- [x] notification policy: coalesced vs naive → wakeups, wakes/op, Mops/s
- [x] caught + fixed a real bug along the way (producer counted `Err(Full)` batches as sent → hang)
- **Sample (Apple Silicon, TCG-free host):** batch=64 ~410 Mops/s; round-trip p50 ~125 ns; coalescing ~59× fewer wakeups
- **Deferred to M7:** seL4 comparisons (vs plain IPC / notification mailbox) + hardware counters need the binding (spec §19)

## Milestone 6 — seL4 binding design doc ✅ COMPLETE
- [x] `docs/architecture/surt_sel4_binding.md` (13 sections)
- [x] responsibilities / non-goals; component capabilities; crate structure
- [x] shared-frame → `RingMem` projection; `Sel4Notify` (Signal/Wait latching ⇒ M4-correct)
- [x] control-path handshake (HELLO/HELLO_ACK + feature negotiation), message/MR layout, sequence diagram
- [x] capability transfer (frame `CNode_Copy`, badged-notification `Mint`, `SetCapReceivePath`)
- [x] teardown (READY→DRAINING→CLOSED) + fault story (fault_ep → `state=FAULTED` → `PeerFaulted`)
- [x] wait-loop helper integrating `prepare_wait` ↔ `seL4_Wait`; cross-AS memory model; API sketch; open decisions
- [x] M7 implementation order (6 steps, each with a kernel spec)

## Milestone 7 — `surt-sel4` binding implementation (on the rust-micro kernel) — PARTIAL
Integrated into the kernel's rootserver (`rootserver/src/microtest.rs`), not a
standalone crate (the kernel's seL4 ABI is hand-rolled inline, no shareable
bindings crate).
- [x] `surt-core` builds into the rootserver under `-Z build-std=core` (+ `compiler-builtins-mem` for `memcpy`/`memset`)
- [x] **`surt_ring_single_thread` microtest PASSES in QEMU** — surt-core's ring (init/attach/push/pop, wraparound) runs unchanged on the real kernel ABI ✅
- [x] `Sel4Notify` implemented: `Notify::wake` = Signal (Send len 0), blocking `wait` = Recv on the cap
- [x] found + fixed real kernel-side bugs surfaced by the integration:
  - `ep_recv` asm didn't declare `r8/r9/r15` clobbered → the kernel's returned msg-regs corrupted a live value → NULL deref. Fixed.
  - spawned-child stack must be `rsp % 16 == 8` at entry (large-model SSE) — matched `child_send`'s `-8`.
  - `link.ld` had no rules for large-model sections (`.ltext/.lrodata/.ldata/.lbss`) → added them.
- [~] **two-thread ring + notification: implemented but DISABLED** — the spawned consumer never gets scheduled after the parent's surt-core setup; a minimal `.text` child also fails in the same context while `child_send` works. Unresolved rootserver-spawn interaction, independent of surt-core. (The `ipc_extra_cap_staging` microtest crash is pre-existing — an IPC-buffer `#PF` unrelated to surt.)
- [ ] remaining design-doc steps (control-path handshake, cap transfer, separate-VSpace components) — future work

## Notes
- Quality gates (spec §23): builds, tests, fmt, clippy, `SAFETY:` on every `unsafe`,
  no refs/pointers/usize in shared ABI, documented memory ordering, validated peer input.
- Host-first: surt-abi/core/host need no seL4; the binding is last.
