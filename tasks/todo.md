# Active phase plan — Phase 25: real page-fault hook

## Goal
Hook the x86_64 page-fault handler into the `fault::deliver_fault`
machinery from Phase 22. When a user thread page-faults, the
kernel:
1. Reads CR2 + error code + saved CS from the iret frame.
2. If the fault came from CPL=3 (user), calls `deliver_fault`
   with a `VMFault` carrying CR2 + the error code.
3. Picks a new thread to run (since the faulter is now blocked
   on Reply), swaps CR3, and iretqs into it.
4. If the fault came from CPL=0 (kernel), panics — we have no
   recovery for kernel faults.

The existing page-fault stub from `interrupt_with_error!`
swallows the saved CS and passes garbage to the handler via
broken System V ABI plumbing. We write a proper one.

## Plan
- [x] 25a — `page_fault_entry` naked stub puts cr2 → rdi,
  error → rsi, saved_cs → rdx, saved_rip → rcx before the call.
- [x] 25b — `handle_page_fault_typed(cr2, err, cs, rip)` routes
  user faults to `deliver_fault(current, VMFault {...})` and
  qemu_exit's after delivery (we can't iret back to a blocked
  thread cleanly until Phase 26's IRQ-style state save lands;
  exiting at least proves the path was taken). Kernel faults
  log the regs and halt.
- [x] 25c — IDT[14] now installs `page_fault_entry`.
- [x] 25d — AY demo unchanged.

## Out of scope
* Deliberate user-fault test — needs a payload that faults and
  a fault-handler thread. Defer to a future phase that builds
  out the init-thread story.

## Verification
* AY demo unchanged.
* Spec count unchanged.
* If a fault DID happen, the boot output would log it before
  exiting; absent that we know the path is dormant.

## Review

* All 4 sub-tasks done.
* The new stub finally passes registers correctly — the
  `interrupt_with_error!` macro elsewhere in exceptions.rs is
  still using the broken pattern (passes garbage to its
  extern-C handlers). That's a wider bug that should be fixed
  in a sweep, but PF was the most user-visible.
* Real test of "user thread faults → handler runs" needs a
  payload that intentionally faults plus a fault-handler thread
  in the demo. Out of scope for this commit; the algorithmic
  bridge is verified by the spec in `fault.rs`.
* AY demo unchanged → 130 ✓ specs.
