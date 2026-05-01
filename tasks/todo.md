# Active phase plan — Phase 20: TCB invocations

## Goal
Round out the TCB cap so userspace can fully configure new threads
without the kernel hand-crafting them. Adds:
* `TCB::WriteRegisters` — set the thread's saved RIP/RSP and a few
  arg regs.
* `TCB::ReadRegisters` — fan the thread's saved registers back to
  the caller via `msg_regs`.
* `TCB::SetSpace` — set the thread's CSpace root + VSpace root +
  fault-EP cap.
* `TCB::BindNotification` — bind a Notification cap to the TCB
  (signal-on-fault later).

## ABI notes
`SyscallArgs` is 6 words, so we have to pack carefully. seL4's full
ABI uses the IPC buffer for overflow; we don't have user IPC
buffers wired yet, so the invocation handlers below take the most
useful subset.

* `WriteRegisters(rip, rsp, arg0)`: a2 = rip, a3 = rsp, a4 = arg0.
* `ReadRegisters(suspend_source)`: a2 ignored. Writes msg_regs[0]
  = rip, msg_regs[1] = rsp, msg_regs[2] = rax. ipc_length = 3.
* `SetSpace(fault_ep_cptr, cnode_cptr, vspace_cptr)`: a2..a4.
  fault_ep_cptr can be 0 to mean "no fault handler". vspace
  isn't fully wired (single shared address space), so we just
  store the cap as opaque for now.
* `BindNotification(ntfn_cptr)`: a2 = cptr to a Notification cap;
  installs it as the TCB's bound notification.

## Plan
- [x] 20a — TCB::WriteRegisters / ReadRegisters
- [x] 20b — TCB::SetSpace (cspace_root + vspace_root + fault_ep)
- [x] 20c — TCB::BindNotification (+ Unbind)
- [x] 20d — specs for each

## Verification
* All previous specs pass.
* New TCB invocation specs verify:
  - WriteRegisters updates target.user_context.rcx/rsp/rdi
  - ReadRegisters fans target's saved state into invoker's
    msg_regs
  - SetSpace updates target's cspace_root + records fault_ep
  - BindNotification stamps target.bound_notification

## Review

* All 4 sub-tasks complete; 2 new specs (10 invocation total).
* Tcb gained `vspace_root: Cap` (opaque storage; per-thread CR3
  lands when ASID does) and `bound_notification: Option<u16>`.
* Existing `fault_handler: Word` reused for SetSpace's fault EP.
* User-mode IPC demo unchanged; spec count 126 → 128.
