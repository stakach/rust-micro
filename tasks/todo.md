# Active phase plan — Phase 23: scheduler tick wiring

## Goal
Connect the live PIT IRQ delivery (Phase 12f) to scheduler timeslice
tracking. Each tick, decrement the current thread's `time_slice`;
on zero, mark the thread for preemption. The actual context-switch
on preempt waits for the IRQ-entry stub to be written (parallel to
the existing SYSCALL stub); for now the tick logic + a "preempt
flag" and accumulator are testable.

## Plan
- [x] 23a — `scheduler::tick()` decrements `current.time_slice`,
  returns whether budget exhausted.
- [x] 23b — Existing `pit::TICK_COUNT` already covers telemetry.
- [x] 23c — PIT ISR now calls `scheduler::tick()` after the
  TICK_COUNT increment.
- [x] 23d — Two specs: counter-decrement happy path + no-op when
  no current.

## Out of scope (defer)
* Actual context switch on preempt — needs IRQ-entry stub
  matching the SYSCALL one (Phase 24+).
* MCS sched_context refill_charge integration (Phase 25).

## Verification
* Spec count rises by 2-3.
* User-mode demo unaffected (we mask IRQ 0 before launching
  user mode currently).
* Confirm `TICK_COUNT` increments on real boot — it already
  does via Phase 12f.

## Review

* All 4 sub-tasks done.
* PIT ISR now does:
    1. `TICK_COUNT.fetch_add(1)` — telemetry counter
    2. `KERNEL.scheduler.tick()` — charges the running thread
    3. `pic::eoi(0)` — release the IRQ
* The actual preempt-on-exhaustion (saving user state + picking
  next + sysretq into next) waits for the IRQ-entry stub
  Phase 24 will write. Until then "tick" just updates the
  counter; the existing demo's threads run to completion
  syscall-by-syscall as before.
* Spec count 130 → 132. User-mode demo unchanged.
