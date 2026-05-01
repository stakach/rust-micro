# Active phase plan — Phase 22: fault delivery

## Goal
When a user thread takes a fault (page fault, unknown syscall,
user exception), the kernel must:

1. Build a fault message describing the fault.
2. Send it via IPC to the thread's fault-handler endpoint
   (the cap pointed to by `tcb.fault_handler` cptr).
3. Block the faulting thread `BlockedOnReply` so a `SysReply` from
   the handler can resume / restart it.
4. Fault handler receives, decides to either Reply (resume) or
   Restart via `TCB::Resume` after fixing the underlying issue.

Without this, user faults panic the kernel — a real seL4 system
wouldn't survive any buggy userland.

## Scope (minimum useful)
* New `src/fault.rs` module with `deliver_fault(faulting_tcb,
  fault)` that:
  - looks up the fault EP cap in the faulting thread's CSpace
  - encodes the fault into msg_regs[0..N]
  - calls `endpoint::send_ipc` with `do_call=true` so the
    faulter ends up `BlockedOnReply` and the handler's
    `reply_to` is set
  - returns `Err(KException::Fault(...))` if anything in the
    delivery itself fails (no handler, EP cap not an Endpoint,
    etc.) so the kernel can fall back to "kill the thread"
* `FaultMessage` enum with the 4 seL4 fault kinds
  (CapFault / VMFault / UnknownSyscall / UserException). Maps
  to `seL4_FaultType` constants.
* Hook page-fault and unknown-syscall paths into deliver_fault.
* Specs covering:
  - fault delivery sets msg_regs / blocks faulter
  - handler can SysReply to wake the faulter back up
  - missing fault handler returns the fault (caller decides)

## Plan
- [x] 22a — `fault.rs` with FaultMessage + deliver_fault
- [-] 22b — x86_64 page-fault hook deferred (requires user-mode
       page-table isolation first; without it any fault from the
       kernel side would corrupt the boot path)
- [-] 22c — handle_unknown_syscall hook deferred for the same
       reason
- [x] 22d — Specs prove the fault → handler → reply round-trip

## Lessons recorded
- Freeing TCBs that are still linked into the scheduler's ready
  queues causes the next `admit` to deref a stale slot (panic in
  `TcbSlab::get_mut`). Fix: `scheduler.queues = ReadyQueues::new()`
  before any test that admits TCBs into the same slab.

## Verification
* All 128 ✓ specs still pass.
* New fault delivery specs verify the round-trip.
* User-mode demo unchanged (shouldn't fault).

## Review

* `fault.rs` lands the algorithmic core of fault delivery. Its
  contract: given a TCB and a `FaultMessage`, send the message
  via the thread's fault EP, block the thread `BlockedOnReply`,
  and stamp the handler's `reply_to`.
* Spec proves the full round-trip including the handler's
  SysReply waking the faulter.
* Hooking into the actual x86_64 page-fault and unknown-syscall
  handlers is deferred. We can't pass user faults to user mode
  cleanly until per-thread page tables exist (Phase 28) — until
  then a real fault would destabilize the kernel rather than be
  delivered. The algorithmic bridge is in place; the hook is a
  ~10-line change once the prerequisite lands.
* Hit + recorded a real bug: scheduler-queue staleness across
  tests that free TCBs. Fix is one helper.
* Spec count 128 → 130. User-mode demo (`AY`) unchanged.
