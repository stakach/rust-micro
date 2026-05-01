# Active phase plan — Phase 18: Notification + IRQ syscalls

## Goal
Wire `Cap::Notification` and the IRQ caps (`Cap::IrqControl`, `Cap::IrqHandler`)
through the syscall path so userspace can do `Signal`/`Wait` on a notification
and bind notifications to IRQ lines for driver-style code.

## Plan

- [x] 18a — `SysSend` on `Cap::Notification` → `signal()`
- [x] 18b — `SysRecv` on `Cap::Notification` → `wait()`
- [x] 18c — `decode_invocation` for `Cap::IrqControl::IssueIRQHandler`
- [x] 18d — `decode_invocation` for `Cap::IrqHandler::Ack`,
  `SetNotification`, `Clear`
- [x] 18e — Specs for each path; existing IPC demo unchanged

## ABI notes
- `SysSend` on a Notification uses the badge from the cap; payload is
  ignored (signal merges via OR).
- `SysRecv` returns the consumed badge in `rdi` (existing IPC return
  path already populates this from `tcb.ipc_badge`).
- `IrqControl::IssueIRQHandler(irq, dest_root, dest_index, dest_depth)`:
  for our compressed ABI we take `irq` from `a2`, `dest_index` from
  `a3`. `dest_root` defaults to invoker's CSpace root.
- `IrqHandler::Ack` clears `pending` flag.
- `IrqHandler::SetNotification(ntfn_cptr)` binds a notification cap;
  `ntfn_cptr` from `a2`.

## Verification
1. Build clean (`./scripts/build_kernel.sh`).
2. Spec runner shows new ✓s.
3. Existing two-thread user-mode IPC demo (`PM`) still ends with
   `[two-thread IPC succeeded — exiting QEMU]`.

## Review

* All 6 new invocation paths land + pass spec.
* Hit a real bug — `NotificationCap::new` arg order — caught by the
  `IRQHandler::Set` spec when the looked-up cap came back as
  non-Notification. Fixed in `src/cap.rs::to_words`.
* Spec count: 124 ✓ (was 122 before phase 18). User-mode IPC demo
  still produces `PM` and exits cleanly.
* Lesson recorded: codegen `new()` arg-order convention.
