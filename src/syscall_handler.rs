//! Syscall dispatch. This is the kernel's `handleSyscall` from
//! seL4/src/api/syscall.c, distilled down to the parts we can run
//! without an actual user thread on the CPU.
//!
//! In a fully-wired kernel, `handle_syscall` is called from the
//! arch-specific SYSCALL trap entry stub. The stub saves the user
//! register state into the current TCB's `tcbContext`, then invokes
//! us with the syscall number from `%rax` and the user args from
//! `%rdi..%r9`. Phase 5 implements only the dispatcher and one
//! representative syscall (`SysDebugPutChar`); the actual
//! SYSCALL/SYSRET wiring lands with usermode in a later phase.
//!
//! Why surface a `DebugSink` trait rather than calling `arch::log`
//! directly? It lets specs (which run before any usermode exists)
//! capture the byte stream into a buffer for assertion. The
//! production path simply implements the trait around the existing
//! serial driver.

use crate::error::{FaultKind, KException, KResult, SyscallError};
use crate::syscalls::Syscall;
use crate::types::{seL4_Error, seL4_Word as Word};

/// The six register-passed arguments userspace can supply on
/// SYSCALL entry. Mirrors the x86_64 calling convention in seL4's
/// `c_traps.c` (`%rdi..%r9`).
#[derive(Copy, Clone, Debug, Default)]
pub struct SyscallArgs {
    pub a0: Word,
    pub a1: Word,
    pub a2: Word,
    pub a3: Word,
    pub a4: Word,
    pub a5: Word,
}

impl SyscallArgs {
    pub const fn new(a0: Word) -> Self {
        Self {
            a0,
            a1: 0,
            a2: 0,
            a3: 0,
            a4: 0,
            a5: 0,
        }
    }
}

/// Sink for kernel debug bytes. The kernel implements this around
/// `arch::log`; specs implement it around an in-memory buffer so they
/// can assert the exact byte sequence emitted by `SysDebugPutChar`.
pub trait DebugSink {
    fn put_byte(&mut self, byte: u8);
}

/// Cap-type tag for `seL4_DebugCapIdentify`. Returns upstream's
/// `cap_*_cap` enum values from `structures_64.bf` so libsel4sync
/// (and other libs) can identify caps by type. Tag values mirror
/// `crate::cap::tag` — keep in sync.
#[cfg(target_arch = "x86_64")]
fn debug_cap_type_tag(cap: &crate::cap::Cap) -> u64 {
    use crate::cap::{tag, Cap};
    match cap {
        Cap::Null => tag::NULL,
        Cap::Untyped { .. } => tag::UNTYPED,
        Cap::Endpoint { .. } => tag::ENDPOINT,
        Cap::Notification { .. } => tag::NOTIFICATION,
        Cap::Reply { .. } => tag::REPLY,
        Cap::CNode { .. } => tag::CNODE,
        Cap::Thread { .. } => tag::THREAD,
        Cap::IrqControl => tag::IRQ_CONTROL,
        Cap::IrqHandler { .. } => tag::IRQ_HANDLER,
        Cap::Domain => tag::DOMAIN,
        Cap::SchedContext { .. } => tag::SCHED_CONTEXT,
        Cap::SchedControl { .. } => tag::SCHED_CONTROL,
        Cap::Frame { .. } => tag::FRAME,
        Cap::PageTable { .. } => tag::PAGE_TABLE,
        Cap::PageDirectory { .. } => tag::PAGE_DIRECTORY,
        Cap::Pdpt { .. } => tag::PDPT,
        Cap::PML4 { .. } => tag::PML4,
        Cap::AsidControl => tag::ASID_CONTROL,
        Cap::AsidPool { .. } => tag::ASID_POOL,
        Cap::IOPort { .. } => tag::IO_PORT,
        Cap::IOPortControl => tag::IO_PORT_CONTROL,
        // Catch-all for variants we don't model individually
        // (Zombie, generic Arch). Returning a non-zero non-NULL
        // value preserves the legacy "any cap = non-null" contract.
        _ => 1,
    }
}

/// Dispatcher. Mirrors `handleSyscall` in seL4 (non-MCS variant):
/// IPC syscalls route through the relevant invocation path via
/// CSpace lookup against the current thread's CTable; the debug
/// syscalls land in `handle_unknown_syscall`.
pub fn handle_syscall(
    syscall: Syscall,
    args: &SyscallArgs,
    sink: &mut dyn DebugSink,
) -> KResult<()> {
    match syscall {
        Syscall::SysSend => handle_send(
            args, /* blocking */ true, /* call */ false, /* donate */ false, false,
        ),
        Syscall::SysNBSend => handle_send(
            args, /* blocking */ false, /* call */ false, /* donate */ false, false,
        ),
        Syscall::SysCall => handle_send(
            args, /* blocking */ true, /* call */ true, /* donate */ true, false,
        ),
        Syscall::SysRecv => handle_recv(args, /* blocking */ true),
        Syscall::SysNBRecv => handle_recv(args, /* blocking */ false),
        // Phase 36b — under MCS there's no standalone Reply syscall;
        // reply is via Send on a Cap::Reply. Until the cap-based
        // reply IPC integration lands (the 34e follow-up), the
        // existing `handle_reply` path stays callable directly from
        // kernel specs but isn't reachable from userspace.
        Syscall::SysReplyRecv => {
            let invoker = unsafe { crate::kernel::KERNEL.get().scheduler.current() };
            let reply_wake = unsafe {
                let s = crate::kernel::KERNEL.get();
                invoker.and_then(|cur| s.scheduler.slab.get(cur).reply_to)
            };
            // Phase 43 — handle_reply's `make_runnable(caller)` may
            // clear `scheduler.current` via possibleSwitchTo (when
            // caller > current priority). The composite syscall still
            // has the receive part to run, and handle_recv looks up
            // `scheduler.current()` to find the receiver. Stash the
            // invoker before the reply and restore it afterwards so
            // handle_recv sees the right TCB. The actual reschedule
            // happens at the dispatcher tail once handle_recv is done.
            #[cfg(target_arch = "x86_64")]
            let saved_current = unsafe { crate::kernel::KERNEL.get().scheduler.current() };
            handle_reply(args)?;
            unsafe {
                let s = crate::kernel::KERNEL.get();
                if let (Some(invoker), Some(woken)) = (invoker, reply_wake) {
                    if s.scheduler.slab.try_get(invoker).is_some() {
                        s.scheduler.slab.get_mut(invoker).composite_reply_handoff = Some(woken);
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let s = crate::kernel::KERNEL.get();
                if s.scheduler.current().is_none() {
                    if let Some(t) = saved_current {
                        s.scheduler.set_current(Some(t));
                    }
                }
            }
            let r = handle_recv(args, /* blocking */ true);
            finish_composite_reply_handoff(invoker, r.is_ok());
            r
        }
        // Phase 36b — MCS notification-only Recv variants. Forward
        // to handle_recv; Notification targets ignore r12 because a
        // wait is not a server receive that can accept Call IPC.
        Syscall::SysWait => handle_recv(args, /* blocking */ true),
        Syscall::SysNBWait => handle_recv(args, /* blocking */ false),
        // MCS atomic non-blocking-send + blocking-recv composite.
        // Upstream's x86_64 x64_sys_nbsend_recv ABI:
        //   rdi (a0)  = src cptr           (recv source)
        //   rsi (a1)  = send msginfo
        //   r10/r8/r9/r15 (a2..a5) = send mr0..mr3
        //   r13       = dest cptr          (send target)
        //   r12       = reply cap          (offered to the Recv half)
        //
        // sel4test's IPC0002 / IPC0003 replywait_func opens with
        // an empty NBSendRecv used purely as a Recv (no actual send
        // because there's nothing to reply to yet). Implement as
        // non-blocking-send-then-blocking-recv — if the send has no
        // queued receiver it just drops, and the Recv proceeds.
        Syscall::SysNBSendRecv => {
            let invoker = unsafe { crate::kernel::KERNEL.get().scheduler.current() };
            let dest_cptr = {
                let s = unsafe { crate::kernel::KERNEL.get() };
                let cur = invoker.ok_or_else(|| {
                    crate::error::KException::SyscallError(crate::error::SyscallError::new(
                        crate::types::seL4_Error::seL4_InvalidCapability,
                    ))
                })?;
                s.scheduler.slab.get(cur).user_context.r13
            };
            let send_args = SyscallArgs {
                a0: dest_cptr,
                a1: args.a1,
                a2: args.a2,
                a3: args.a3,
                a4: args.a4,
                a5: args.a5,
            };
            // NB-send: blocking=false, call=false. A null destination means "no send half" for
            // the bootstrap ReplyRecv shape; a real nonzero bad cap should still report an error.
            if dest_cptr != 0 {
                handle_send(
                    &send_args, /* blocking */ false, /* call */ false,
                    /* donate */ true, true,
                )?;
            }
            // The NB-send may have woken a higher-priority receiver,
            // which `possibleSwitchTo` signals by clearing `current`.
            // The Recv half still needs `current` to identify the
            // receiver, so restore the invoker (same workaround as
            // SysReplyRecv). The real reschedule happens at the
            // dispatcher tail once handle_recv is done.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let s = crate::kernel::KERNEL.get();
                if s.scheduler.current().is_none() {
                    s.scheduler.set_current(invoker);
                }
            }
            let r = handle_recv(args, /* blocking */ true);
            finish_composite_reply_handoff(invoker, r.is_ok());
            r
        }
        // SysNBSendWait — same as NBSendRecv but the Recv side is a
        // notification-only Wait, so handle_recv ignores r12 after
        // resolving the target as a Notification cap.
        Syscall::SysNBSendWait => {
            let invoker = unsafe { crate::kernel::KERNEL.get().scheduler.current() };
            let dest_cptr = {
                let s = unsafe { crate::kernel::KERNEL.get() };
                let cur = invoker.ok_or_else(|| {
                    crate::error::KException::SyscallError(crate::error::SyscallError::new(
                        crate::types::seL4_Error::seL4_InvalidCapability,
                    ))
                })?;
                // NBSendWait's libsel4 stub puts the send destination in
                // the REPLY register (r12), NOT the NBSendRecv dest
                // register (r13, which it sets to 0):
                //   x64_sys_nbsend_recv(SysNBSendWait, /*dest*/0, src,
                //                       ..., /*reply*/dest)
                // Reading r13 here gave a null cptr, so the send-half
                // was silently dropped — e.g. IPC0022's worker
                // nbsend_wait failed to wake the stack spawner.
                s.scheduler.slab.get(cur).user_context.r12
            };
            let send_args = SyscallArgs {
                a0: dest_cptr,
                a1: args.a1,
                a2: args.a2,
                a3: args.a3,
                a4: args.a4,
                a5: args.a5,
            };
            if dest_cptr != 0 {
                handle_send(&send_args, false, false, /* donate */ true, true)?;
            }
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let s = crate::kernel::KERNEL.get();
                if s.scheduler.current().is_none() {
                    s.scheduler.set_current(invoker);
                }
            }
            let r = handle_recv(args, true);
            finish_composite_reply_handoff(invoker, r.is_ok());
            r
        }
        Syscall::SysYield => {
            yield_current_thread();
            Ok(())
        }
        Syscall::SysDebugPutChar | Syscall::SysDebugDumpScheduler => {
            let n = syscall as i32 as i64;
            handle_unknown_syscall(n, args, sink)
        }
        // Phase 41 — debug syscalls sel4test-driver issues during
        // init. Stubbed as no-ops (SysDebugCapIdentify returns 0
        // = CapNull). They're CONFIG_DEBUG_BUILD-only and not
        // load-bearing; full implementations are follow-ups.
        Syscall::SysDebugHalt => {
            crate::arch::log("[sel4test SysDebugHalt — exiting QEMU]\n");
            #[cfg(target_arch = "x86_64")]
            crate::arch::qemu_exit(0);
            #[cfg(not(target_arch = "x86_64"))]
            Ok(())
        }
        Syscall::SysDebugCapIdentify => {
            // libsel4's seL4_DebugCapIdentify reads the result from
            // the rdi-out of x64_sys_send_recv (= caller's user_context
            // .rdi after sysretq). We honestly identify the cap by
            // looking it up in the invoker's CSpace and returning a
            // type tag; null slots return 0 so libsel4allocman's
            // `vka_cspace_free` debug check sees them as free.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use crate::kernel::KERNEL;
                if let Some(cur) = KERNEL.get().scheduler.current() {
                    let cspace_root = KERNEL.get().scheduler.slab.get(cur).cspace_root;
                    let tag = match crate::cspace::lookup_cap(KERNEL.get(), &cspace_root, args.a0) {
                        Ok(cap) => debug_cap_type_tag(&cap),
                        Err(_) => 0,
                    };
                    let t = KERNEL.get().scheduler.slab.get_mut(cur);
                    t.user_context.rdi = tag;
                }
            }
            Ok(())
        }
        Syscall::SysDebugSnapshot | Syscall::SysDebugNameThread | Syscall::SysDebugSendIPI => {
            // Best-effort no-ops. Names would print to serial; we
            // skip for now.
            Ok(())
        }
        Syscall::SysSetTLSBase => {
            // Phase 41 — set IA32_FS_BASE for the current thread.
            // Save it on the TCB so the dispatcher can restore the
            // value next time this thread runs after a context switch
            // away (e.g. multi-threaded sel4test).
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use crate::arch::x86_64::msr::{wrmsr, IA32_FS_BASE};
                wrmsr(IA32_FS_BASE, args.a0);
                if let Some(cur) = crate::kernel::current_thread() {
                    let s = crate::kernel::KERNEL.get();
                    s.scheduler.slab.get_mut(cur).cpu_context.fs_base = args.a0;
                }
            }
            Ok(())
        }
        Syscall::SysX86DangerousWRMSR => {
            // Phase 41 — WRMSR(reg, value). Used by sel4test-driver
            // to set FS_BASE (its preferred TLS path). args.a0 = MSR
            // index, args.a1 = value.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use crate::arch::x86_64::msr::IA32_FS_BASE;
                crate::arch::x86_64::msr::wrmsr(args.a0 as u32, args.a1);
                if args.a0 as u32 == IA32_FS_BASE {
                    if let Some(cur) = crate::kernel::current_thread() {
                        let s = crate::kernel::KERNEL.get();
                        s.scheduler.slab.get_mut(cur).cpu_context.fs_base = args.a1;
                    }
                }
            }
            Ok(())
        }
        Syscall::SysX86DangerousRDMSR => {
            // RDMSR(reg) — reads an MSR and returns the value via
            // the IPC return path. args.a0 = MSR index. Result in
            // msg_regs[0] (= r10 under upstream IPC return ABI).
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let value = crate::arch::x86_64::msr::rdmsr(args.a0 as u32);
                use crate::kernel::KERNEL;
                if let Some(cur) = KERNEL.get().scheduler.current() {
                    let t = KERNEL.get().scheduler.slab.get_mut(cur);
                    t.msg_regs[0] = value;
                    t.ipc_length = 1;
                }
            }
            Ok(())
        }
    }
}

fn yield_current_thread() {
    if crate::sched_context::yield_current() {
        return;
    }
    unsafe {
        let s = crate::kernel::KERNEL.get();
        let Some(cur) = s.scheduler.current() else {
            return;
        };
        let cpu = s.scheduler.slab.get(cur).affinity as usize;
        let dom = s.scheduler.slab.get(cur).domain as usize;
        if !s.scheduler.slab.get(cur).is_runnable() {
            return;
        }
        if s.scheduler.slab.get(cur).enqueued {
            s.scheduler.nodes[cpu].queues[dom].dequeue(&mut s.scheduler.slab, cur);
        }
        s.scheduler.nodes[cpu].queues[dom].enqueue(&mut s.scheduler.slab, cur);
        if s.scheduler.nodes[cpu].current == Some(cur) {
            s.scheduler.nodes[cpu].current = None;
        }
    }
}

fn finish_composite_reply_handoff(invoker: Option<crate::tcb::TcbId>, receive_ok: bool) {
    let Some(invoker) = invoker else {
        return;
    };
    unsafe {
        let s = crate::kernel::KERNEL.get();
        if !receive_ok {
            if s.scheduler.slab.try_get(invoker).is_some() {
                s.scheduler.slab.get_mut(invoker).composite_reply_handoff = None;
            }
            return;
        }
        let Some(invoker_tcb) = s.scheduler.slab.try_get(invoker) else {
            return;
        };
        if matches!(
            invoker_tcb.state,
            crate::tcb::ThreadStateType::BlockedOnReceive
                | crate::tcb::ThreadStateType::BlockedOnNotification
        ) {
            return;
        }
        s.scheduler.handoff_composite_reply_wake(invoker);
    }
}

/// SysReply: take the current thread's `reply_to` slot, transfer
/// the in-flight message back to the original caller, and unblock
/// them. Mirrors `seL4/src/object/reply.c::doReplyTransfer` for
/// the non-MCS path.
///
/// Phase 36b — under MCS there's no standalone `SysReply` syscall.
/// This entry remains callable from kernel-side specs and from
/// `SysReplyRecv` until the 34e follow-up (cap-based Reply)
/// replaces it.
pub(crate) fn handle_reply(args: &SyscallArgs) -> KResult<()> {
    use crate::kernel::KERNEL;
    use crate::tcb::ThreadStateType;

    unsafe {
        let s = KERNEL.get();
        let current = s.scheduler.current().ok_or_else(|| {
            KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))
        })?;
        let caller = match s.scheduler.slab.get(current).reply_to {
            Some(c) => c,
            None => {
                // No one to reply to. seL4 silently no-ops here on
                // non-MCS; we surface InvalidCapability so user
                // code spots the mistake.
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )));
            }
        };
        // Stage the reply message onto the current TCB so the
        // common transfer machinery picks it up. Words 0..3 ride in
        // registers (args.a2..a5); words 4..min(length,SCRATCH) come
        // from the replier's IPC buffer (the tail is handled
        // buffer-to-buffer by `deliver_message`).
        let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
        let length = info.length() as u32;
        {
            let me = s.scheduler.slab.get_mut(current);
            me.ipc_label = info.label();
            me.ipc_length = length;
            me.msg_regs[0] = args.a2;
            me.msg_regs[1] = args.a3;
            me.msg_regs[2] = args.a4;
            me.msg_regs[3] = args.a5;
            me.reply_to = None; // consume the reply slot
            if length > 4 && me.ipc_buffer_paddr != 0 {
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    let buf = (crate::arch::x86_64::paging::phys_to_lin(me.ipc_buffer_paddr)
                        as *const u64)
                        .wrapping_add(1);
                    let max = (length as usize).min(me.msg_regs.len());
                    for i in 4..max {
                        me.msg_regs[i] = core::ptr::read_volatile(buf.add(i));
                    }
                }
            }
        }
        // Fault replies bypass the normal message transfer — see
        // `fault::apply_fault_reply` (the fan-out would stomp the
        // faulter's live registers).
        if s.scheduler.slab.get(caller).pending_fault != 0 {
            let (label, regs) = {
                let me = s.scheduler.slab.get(current);
                (me.ipc_label, me.msg_regs)
            };
            let restart = crate::fault::apply_fault_reply(s, caller, label, length as usize, &regs);
            s.scheduler.slab.get_mut(current).active_sc = None;
            // IPC0021 — a page fault donates the FAULTER's SC to a
            // passive fault handler (deliver_fault is a Call). On the
            // fault reply, move it back so the restarted faulter is
            // schedulable again (the handler goes passive).
            crate::sched_context::return_donated_sc(s, caller);
            if restart {
                s.scheduler.make_runnable(caller);
            } else {
                s.scheduler
                    .block(caller, crate::tcb::ThreadStateType::Inactive);
            }
            return Ok(());
        }
        // Normal reply: full message transfer (register range +
        // long tail) + IPC-return fan-in, shared with endpoint IPC.
        crate::endpoint::deliver_message(&mut s.scheduler, current, caller, 0);
        // Wake the caller from BlockedOnReply.
        debug_assert_eq!(
            s.scheduler.slab.get(caller).state,
            ThreadStateType::BlockedOnReply,
            "caller should be parked on Reply"
        );
        // Phase 33c — return the donated SchedContext to the
        // caller. While the call was in progress, `current` (the
        // server) ran on `current.active_sc = caller.sc`; clearing
        // it here means future `mcs_tick` charges fall back to the
        // server's own bound SC (or no SC if it has none).
        s.scheduler.slab.get_mut(current).active_sc = None;
        // Passive-server reply: move the donated SC back to the caller
        // (upstream reply_pop) so it's schedulable again.
        crate::sched_context::return_donated_sc(s, caller);
        s.scheduler.make_runnable(caller);
        Ok(())
    }
}

/// Handle a `SysSend` / `SysNBSend`. ABI:
///   rdi (a0) = CPtr to the destination endpoint cap
///   rsi (a1) = MessageInfo word (label / length / extra caps)
///   rdx (a2) = first message register
///   r10 (a3) = second message register
///   r8  (a4) = third
///   r9  (a5) = fourth
///
/// Looks up the cap in the current thread's CSpace, requires it to
/// be a `Cap::Endpoint`, then drives `endpoint::send_ipc`.
fn handle_send(
    args: &SyscallArgs,
    blocking: bool,
    call: bool,
    can_donate: bool,
    composite_reply_receive: bool,
) -> KResult<()> {
    use crate::cap::Cap;
    use crate::cspace::lookup_cap;
    use crate::endpoint::{send_ipc, SendOptions};
    use crate::kernel::KERNEL;

    unsafe {
        let s = KERNEL.get();
        let current = s.scheduler.current().ok_or_else(|| {
            KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))
        })?;
        let cspace_root = s.scheduler.slab.get(current).cspace_root;

        // Phase 42 — log every Send/Call entry so we can see the
        // failing invocation even when target lookup itself errors
        // out (which short-circuits decode_invocation's own trace).
        // Format: `<send call=B cptr=0xNN mi=0xNN>` then on failure
        // `<send-err code=N>` plus the SysCall reply path below.
        crate::invocation::handle_send_log_entry(args.a0, args.a1, call);

        let target = match lookup_cap(s, &cspace_root, args.a0) {
            Ok(c) => c,
            Err(lf) => {
                let e: KException = lf.into();
                crate::invocation::handle_send_log_lookup_err(&e);
                // For SysCall, also write a reply msginfo into rsi so
                // userspace sees the error code rather than stale rsi
                // from a prior successful invocation. LookupFault
                // maps to seL4_FailedLookup (= 6). We still return
                // Err so kernel-side specs that assert on Err continue
                // to work; the syscall_entry dispatcher discards the
                // Result, so userspace only sees what's in rsi.
                if call {
                    let label: u64 = match &e {
                        KException::SyscallError(SyscallError { code }) => *code as u64,
                        KException::LookupFault(_) => seL4_Error::seL4_FailedLookup as u64,
                        _ => 0xFFFF,
                    };
                    let inv_tcb = s.scheduler.slab.get_mut(current);
                    let mi = label << 12;
                    inv_tcb.user_context.rsi = mi;
                    inv_tcb.user_context.rdi = 0;
                }
                return Err(e);
            }
        };

        // Phase 36f — stage msg_regs + pending_extra_caps for ALL
        // SysSend / SysCall paths, not just the Endpoint branch.
        // This is what lets decode_invocation handlers (TCB::Configure
        // etc.) read message words past a5 and look up extra caps
        // the user packed into its IPC buffer's caps_or_badges[]
        // array. For Endpoint targets, downstream `send_ipc` reads
        // the same staged state; for Notifications the staging is
        // harmless since signal() doesn't touch it.
        let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
        let length = info.length() as u32;
        {
            let snd = s.scheduler.slab.get_mut(current);
            snd.ipc_label = info.label();
            snd.ipc_length = length;
            // ipc_badge gets overwritten below for Endpoint targets;
            // initialize to 0 so non-Endpoint paths see a clean
            // value.
            snd.ipc_badge = 0;
            snd.msg_regs[0] = args.a2;
            snd.msg_regs[1] = args.a3;
            snd.msg_regs[2] = args.a4;
            snd.msg_regs[3] = args.a5;
            // Phase 34c — long messages: words 4..length come from
            // the sender's IPC buffer page (tag word at offset 0,
            // msg[] starts at offset 1).
            if length > 4 && snd.ipc_buffer_paddr != 0 {
                let buf_paddr = snd.ipc_buffer_paddr;
                let buf = (crate::arch::x86_64::paging::phys_to_lin(buf_paddr) as *const u64)
                    .wrapping_add(1);
                let max = (length as usize).min(snd.msg_regs.len());
                for i in 4..max {
                    snd.msg_regs[i] = core::ptr::read_volatile(buf.add(i));
                }
            }
            snd.pending_extra_caps_count = 0;
        }
        // Phase 34d — stage caps from caps_or_badges[].
        let n_caps = info.extra_caps() as usize;
        if n_caps > 0 {
            let (buf_paddr, snd_cspace) = {
                let snd = s.scheduler.slab.get(current);
                (snd.ipc_buffer_paddr, snd.cspace_root)
            };
            if buf_paddr != 0 {
                let buf = crate::arch::x86_64::paging::phys_to_lin(buf_paddr) as *const u64;
                let mut staged: [crate::cap::Cap; 3] = [crate::cap::Cap::Null; 3];
                let mut count = 0u8;
                let n = n_caps.min(staged.len());
                for i in 0..n {
                    let cptr = core::ptr::read_volatile(
                        buf.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET + i),
                    );
                    if let Ok(c) = crate::cspace::lookup_cap(s, &snd_cspace, cptr) {
                        staged[i] = c;
                        count += 1;
                    } else {
                        break;
                    }
                }
                let snd = s.scheduler.slab.get_mut(current);
                snd.pending_extra_caps = staged;
                snd.pending_extra_caps_count = count;
            }
        }

        let composite_reply_caller = if composite_reply_receive {
            match target {
                Cap::Reply { ptr, .. } => {
                    let idx = crate::kernel::KernelState::reply_index(ptr);
                    s.replies.get(idx).and_then(|reply| reply.bound_tcb)
                }
                _ => None,
            }
        } else {
            None
        };

        let (ep_ptr, badge, ep_can_grant) = match target {
            Cap::Endpoint { ptr, badge, rights } => {
                if !rights.can_send {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                }
                // Now that staging happens up-front, write the
                // Endpoint's badge onto the sender. (Non-Endpoint
                // paths leave it at 0 from staging.)
                s.scheduler.slab.get_mut(current).ipc_badge = badge.0;
                (ptr, badge.0, rights.can_grant)
            }
            // Phase 18a: Send on a Notification cap is signal().
            Cap::Notification { ptr, badge, rights } => {
                if !rights.can_send {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                }
                let idx = crate::kernel::KernelState::ntfn_index(ptr);
                let s_ptr: *mut crate::kernel::KernelState = s;
                let ntfn = &mut (*s_ptr).notifications[idx];
                let sched = &mut (*s_ptr).scheduler;
                let _woken = crate::notification::signal(ntfn, sched, badge.0);
                return Ok(());
            }
            // Phase 16 / 42: non-IPC cap on a Send/Call → invocation
            // dispatch. Staging above already populated msg_regs +
            // pending_extra_caps, so the handler can use them.
            //
            // Phase 42 — for SysCall, encode the result as a reply
            // msginfo (label = error code, 0 = success) into the
            // caller's rsi so libsel4's `seL4_MessageInfo_get_label`
            // reads the right value. Invocations that return data
            // (ReadRegisters, DangerousRDMSR) also stage values in
            // msg_regs[0..3]; the dispatcher tail fans those into
            // r10/r8/r9/r15. Without this, sel4test's allocman saw
            // rsi unchanged from its outgoing tag (label = 1 =
            // UntypedRetype) and interpreted it as InvalidArgument.
            other => {
                // Reset ipc_length before the invocation; the
                // *reply* length is decided by the invocation
                // (ReadRegisters/RDMSR/FailedLookup with level
                // info set it explicitly). Without this, the reply
                // msginfo would carry the SENT length and userspace
                // would read garbage past the actual return data.
                s.scheduler.slab.get_mut(current).ipc_length = 0;
                let result = crate::invocation::decode_invocation(other, args, current);
                if result.is_ok() {
                    if let Some(caller) = composite_reply_caller {
                        s.scheduler.slab.get_mut(current).composite_reply_handoff = Some(caller);
                    }
                }
                if call {
                    let label: u64 = match &result {
                        Ok(()) => 0,
                        Err(KException::SyscallError(SyscallError { code })) => *code as u64,
                        Err(_) => 0xFFFF,
                    };
                    let inv_tcb = s.scheduler.slab.get_mut(current);
                    let length = inv_tcb.ipc_length as u64 & 0x7F;
                    let mi = (label << 12) | length;
                    inv_tcb.user_context.rsi = mi;
                    inv_tcb.user_context.rdi = 0; // no badge on reply
                                                  // Fan msg_regs into the IPC return registers so
                                                  // invocation results (e.g. RDMSR) reach userspace.
                    inv_tcb.user_context.r10 = inv_tcb.msg_regs[0];
                    inv_tcb.user_context.r8 = inv_tcb.msg_regs[1];
                    inv_tcb.user_context.r9 = inv_tcb.msg_regs[2];
                    inv_tcb.user_context.r15 = inv_tcb.msg_regs[3];
                    // libsel4's seL4_GetMR(i) reads from the IPC
                    // buffer (not registers), so also stage there.
                    // Buffer layout: word 0 = tag, words 1..N = msg.
                    let ipc_paddr = inv_tcb.ipc_buffer_paddr;
                    if ipc_paddr != 0 {
                        let buf = (crate::arch::x86_64::paging::phys_to_lin(ipc_paddr) as *mut u64)
                            .wrapping_add(1);
                        let n = (length as usize).min(inv_tcb.msg_regs.len());
                        for i in 0..n {
                            core::ptr::write_volatile(buf.add(i), inv_tcb.msg_regs[i]);
                        }
                    }
                }
                // SysCall + invocation always returns Ok at the
                // syscall level — the invocation error is in the
                // reply label. SysSend + invocation propagates
                // errors so kernel-side specs that assert on Err
                // still work.
                return if call { Ok(()) } else { result };
            }
        };
        let idx = crate::kernel::KernelState::endpoint_index(ep_ptr);
        let opts = SendOptions {
            blocking,
            do_call: call,
            badge,
            can_grant: ep_can_grant,
            can_donate,
        };
        // Split borrows: we need &mut endpoint AND &mut scheduler at
        // once. Take them through indexing on the same struct.
        let s_ptr: *mut crate::kernel::KernelState = s;
        let ep = &mut (*s_ptr).endpoints[idx];
        let sched = &mut (*s_ptr).scheduler;
        send_ipc(ep, sched, current, opts);
        Ok(())
    }
}

/// Handle a `SysRecv` / `SysNBRecv`. ABI:
///   rdi (a0) = CPtr to the endpoint cap
///   rax return = sender badge (the caller reads it after sysret)
fn handle_recv(args: &SyscallArgs, blocking: bool) -> KResult<()> {
    use crate::cap::Cap;
    use crate::cspace::lookup_cap;
    use crate::endpoint::{receive_ipc, EpState, RecvOptions};
    use crate::kernel::KERNEL;

    unsafe {
        let s = KERNEL.get();
        let current = s.scheduler.current().ok_or_else(|| {
            KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))
        })?;
        // Fresh Recv: clear the count of caps transferred into our
        // receive slots so it reflects only THIS receive (a sender's
        // transfer_extra_caps sets it before we return).
        s.scheduler.slab.get_mut(current).received_extra_caps = 0;
        let cspace_root = s.scheduler.slab.get(current).cspace_root;
        let target = lookup_cap(s, &cspace_root, args.a0)?;
        // A running thread must not carry a stale receive-side reply
        // offer from an earlier syscall. A valid endpoint receive
        // below installs a fresh offer after bound-notification
        // delivery has been ruled out.
        s.scheduler.slab.get_mut(current).pending_reply = None;
        // Phase 36d / 43 — MCS reply cap is in `replyRegister = R12`
        // per upstream's `registerset.h`. libsel4's `MCS_REPLY_DECL`
        // pins it via `register seL4_Word reply_reg asm("r12") = reply;`.
        // Read it from the saved `user_context.r12` (NOT args.a2 / r10
        // which is mr0). cptr 0 means "no reply" — we fall back to the
        // legacy Tcb.reply_to path that handle_reply consults.
        //
        // The offer is only committed for Endpoint receives. A bound
        // notification that satisfies Recv must not leave the reply
        // object pending, or a later unrelated Call on this TCB could
        // bind that stale reply object to the wrong caller.
        let mut endpoint_reply_idx: Option<u16> = None;
        #[cfg(target_arch = "x86_64")]
        {
            let reply_cptr = s.scheduler.slab.get(current).user_context.r12;
            if reply_cptr != 0 {
                if let Ok(Cap::Reply { ptr, .. }) = lookup_cap(s, &cspace_root, reply_cptr) {
                    endpoint_reply_idx = Some(crate::kernel::KernelState::reply_index(ptr) as u16);
                }
            }
        }
        let ep_ptr = match target {
            Cap::Endpoint { ptr, rights, .. } => {
                if !rights.can_receive {
                    // IPCRIGHTS0002 / upstream `handleRecv` —
                    // Recv on a cap without read rights is a CapFault
                    // (in_recv=true), not an inline error. The
                    // caller's fault EP gets the message; userspace
                    // sees no return.
                    let _ = crate::fault::deliver_fault(
                        current,
                        crate::fault::FaultMessage::CapFault {
                            addr: args.a0,
                            in_recv: true,
                        },
                    );
                    return Ok(());
                }
                ptr
            }
            // Phase 18a: Recv on a Notification cap is wait().
            // Non-blocking variant (NBWait / Poll) returns the
            // pending badge if Active, or 0 in rdi if Idle —
            // doesn't block.
            Cap::Notification { ptr, rights, .. } => {
                if !rights.can_receive {
                    let _ = crate::fault::deliver_fault(
                        current,
                        crate::fault::FaultMessage::CapFault {
                            addr: args.a0,
                            in_recv: true,
                        },
                    );
                    return Ok(());
                }
                let idx = crate::kernel::KernelState::ntfn_index(ptr);
                let s_ptr: *mut crate::kernel::KernelState = s;
                let ntfn = &mut (*s_ptr).notifications[idx];
                let sched = &mut (*s_ptr).scheduler;
                if !blocking && !matches!(ntfn.state, crate::notification::NtfnState::Active) {
                    // NBWait on Idle notification — return 0 badge.
                    let tcb = sched.slab.get_mut(current);
                    tcb.ipc_badge = 0;
                    #[cfg(target_arch = "x86_64")]
                    {
                        tcb.user_context.rdi = 0;
                        tcb.user_context.rsi = 0;
                    }
                    return Ok(());
                }
                let _outcome = crate::notification::wait(ntfn, sched, current);
                return Ok(());
            }
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )));
            }
        };
        let idx = crate::kernel::KernelState::endpoint_index(ep_ptr);
        let s_ptr: *mut crate::kernel::KernelState = s;
        let endpoint_has_sender = matches!((*s_ptr).endpoints[idx].state, EpState::Send);

        // Bound-notification pre-check. A queued endpoint sender wins over an active bound
        // notification; otherwise a level-triggered timer can keep satisfying Recv before a ready
        // Call is accepted, starving component/server IPC indefinitely.
        if let Some(bn_idx) = s.scheduler.slab.get(current).bound_notification {
            let ntfn = &mut (*s_ptr).notifications[bn_idx as usize];
            if matches!(ntfn.state, crate::notification::NtfnState::Active) && !endpoint_has_sender
            {
                let badge = ntfn.pending_badge;
                ntfn.pending_badge = 0;
                ntfn.state = crate::notification::NtfnState::Idle;
                {
                    let tcb = s.scheduler.slab.get_mut(current);
                    tcb.ipc_badge = badge;
                    #[cfg(target_arch = "x86_64")]
                    {
                        tcb.user_context.rdi = badge;
                        tcb.user_context.rsi = 0;
                    }
                }
                s.scheduler.rotate_current_after_bound_notification(current);
                return Ok(());
            }
        }
        let opts = RecvOptions { blocking };
        let ep = &mut (*s_ptr).endpoints[idx];
        let sched = &mut (*s_ptr).scheduler;
        if let Some(reply_idx) = endpoint_reply_idx {
            sched.slab.get_mut(current).pending_reply = Some(reply_idx);
        }
        let outcome = receive_ipc(ep, sched, current, opts);
        if !matches!(outcome, crate::endpoint::IpcOutcome::Blocked) {
            // A Call consumes the pending reply in finish_call. Plain
            // sends and skipped non-blocking receives do not, so clear
            // the unconsumed offer before returning to user mode.
            sched.slab.get_mut(current).pending_reply = None;
        }
        // For NBRecv that found nothing, mirror upstream's
        // contract: badge = 0 in rdi, msginfo = 0 in rsi. Without
        // this, userspace reads stale registers and NBWAIT0001 sees
        // a non-zero badge.
        #[cfg(target_arch = "x86_64")]
        if matches!(outcome, crate::endpoint::IpcOutcome::Skipped) {
            let tcb = s.scheduler.slab.get_mut(current);
            tcb.ipc_badge = 0;
            tcb.user_context.rdi = 0;
            tcb.user_context.rsi = 0;
        }
        Ok(())
    }
}

/// Mirrors `handleUnknownSyscall(word_t w)` in seL4. The "unknown"
/// path covers the debug syscalls and any out-of-range number.
pub fn handle_unknown_syscall(
    number: i64,
    args: &SyscallArgs,
    sink: &mut dyn DebugSink,
) -> KResult<()> {
    // Match the syscall number first so the sink receives bytes only
    // for syscalls that should produce output.
    let s = match Syscall::from_i32(number as i32) {
        Some(s) => s,
        None => {
            // Anything outside the known range becomes a
            // `seL4_Fault_UnknownSyscall` — userspace's fault handler
            // gets to decide what to do.
            return Err(KException::Fault(FaultKind::UnknownSyscall { number }));
        }
    };
    match s {
        Syscall::SysDebugPutChar => {
            sink.put_byte(args.a0 as u8);
            Ok(())
        }
        Syscall::SysDebugDumpScheduler => {
            // Stub for now. The full version walks every TCB and
            // logs scheduler state; we'll wire it once the boot
            // sequence holds a Scheduler in static memory.
            for b in b"<scheduler dump unimplemented>\n" {
                sink.put_byte(*b);
            }
            Ok(())
        }
        // IPC syscalls don't go through this entry point in the C
        // kernel; if we land here with one, treat it as an unknown
        // syscall fault.
        _ => Err(KException::Fault(FaultKind::UnknownSyscall { number })),
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    /// In-memory sink that captures every byte emitted by a syscall
    /// for spec assertion.
    struct BufferSink {
        buf: [u8; 64],
        len: usize,
    }
    impl BufferSink {
        fn new() -> Self {
            Self {
                buf: [0; 64],
                len: 0,
            }
        }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<non-utf8>")
        }
    }
    impl DebugSink for BufferSink {
        fn put_byte(&mut self, b: u8) {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }

    pub fn test_syscall_handler() {
        arch::log("Running syscall dispatcher tests...\n");
        debug_putchar_emits_byte();
        unknown_syscall_becomes_fault();
        ipc_syscalls_return_invalid_cap_in_phase5();
        sys_yield_succeeds();
        sys_yield_rotates_equal_priority_threads();
        sys_yield_requeues_nonqueued_current_before_choosing_peer();
        debug_dump_scheduler_writes_placeholder();
        sys_send_through_cspace_to_endpoint();
        sys_call_then_reply_round_trip();
        marked_reply_cap_call_hands_off_active_sc_to_lower_priority_caller();
        marked_reply_cap_call_hands_off_independent_sc_to_lower_priority_caller();
        reply_cap_fault_reply_restores_unknown_syscall_context();
        nbsendrecv_fault_reply_rearms_endpoint_receive();
        recv_bound_notification_does_not_stage_reply_cap();
        recv_bound_notification_rotates_behind_ready_peer();
        blocked_recv_bound_notification_clears_reply_offer();
        irq_bound_notification_wakes_blocked_endpoint_recv();
        recv_prefers_queued_endpoint_over_bound_notification();
        replyrecv_reply_wake_hands_off_after_bound_notification();
        nbsendrecv_reply_wake_yields_after_bound_notification();
        nbsendrecv_deferred_reply_wake_survives_later_bound_notification();
        nbsendrecv_stale_reply_handoff_does_not_starve_bound_receiver();
        nbrecv_with_reply_cap_does_not_leave_pending_offer();
        plain_send_recv_with_reply_cap_does_not_leave_pending_offer();
        arch::log("Syscall dispatcher tests completed\n");
    }

    fn debug_putchar_emits_byte() {
        let mut sink = BufferSink::new();
        let args = SyscallArgs::new(b'X' as Word);
        handle_syscall(Syscall::SysDebugPutChar, &args, &mut sink).expect("ok");
        assert_eq!(sink.as_str(), "X");
        arch::log("  ✓ SysDebugPutChar emits the requested byte\n");
    }

    fn unknown_syscall_becomes_fault() {
        let mut sink = BufferSink::new();
        // -42 is well outside the legal Syscall range.
        let res = handle_unknown_syscall(-42, &SyscallArgs::default(), &mut sink);
        match res {
            Err(KException::Fault(FaultKind::UnknownSyscall { number: -42 })) => {}
            other => panic!("expected UnknownSyscall fault, got {:?}", other),
        }
        // No bytes written for an unknown syscall.
        assert_eq!(sink.len, 0);
        arch::log("  ✓ unknown syscall numbers raise an UnknownSyscall fault\n");
    }

    fn ipc_syscalls_return_invalid_cap_in_phase5() {
        let mut sink = BufferSink::new();
        // All IPC syscalls now route through CSpace lookup. With
        // the default boot-thread cspace_root = Null, every one
        // surfaces a lookup fault (InvalidRoot) or a syscall
        // error. SysReply specifically reports InvalidCapability
        // because it skips CSpace lookup (uses tcb.reply_to) and
        // the boot thread has no caller waiting.
        for s in &[
            Syscall::SysSend,
            Syscall::SysNBSend,
            Syscall::SysCall,
            Syscall::SysRecv,
            Syscall::SysNBRecv,
            // Phase 36b — SysReply removed under MCS; SysReplyRecv
            // still goes through the dispatcher.
            Syscall::SysReplyRecv,
        ] {
            let res = handle_syscall(*s, &SyscallArgs::default(), &mut sink);
            match res {
                Err(KException::LookupFault(_)) => {}
                Err(KException::SyscallError(_)) => {}
                other => panic!("expected fault for {:?}, got {:?}", s, other),
            }
        }
        arch::log("  ✓ IPC syscall handlers route through CSpace lookup\n");
    }

    fn sys_yield_succeeds() {
        let mut sink = BufferSink::new();
        handle_syscall(Syscall::SysYield, &SyscallArgs::default(), &mut sink).unwrap();
        assert_eq!(sink.len, 0);
        arch::log("  ✓ SysYield succeeds without debug output\n");
    }

    fn sys_yield_rotates_equal_priority_threads() {
        use crate::kernel::KERNEL;
        use crate::tcb::{Tcb, ThreadStateType};

        let (a, b) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let mut first = Tcb::default();
            first.priority = 80;
            first.state = ThreadStateType::Running;
            let mut second = Tcb::default();
            second.priority = 80;
            second.state = ThreadStateType::Running;
            let a = s.scheduler.admit(first);
            let b = s.scheduler.admit(second);
            s.scheduler.set_current(Some(a));
            (a, b)
        };

        let mut sink = BufferSink::new();
        handle_syscall(Syscall::SysYield, &SyscallArgs::default(), &mut sink).unwrap();
        assert_eq!(sink.len, 0);
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.current(), None);
            assert_eq!(s.scheduler.choose_thread(), Some(b));
            free_temp_tcb(a);
            free_temp_tcb(b);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ SysYield rotates a queued peer in the normal path\n");
    }

    fn sys_yield_requeues_nonqueued_current_before_choosing_peer() {
        use crate::kernel::KERNEL;
        use crate::tcb::{Tcb, ThreadStateType};

        let (current, peer) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let mut current_tcb = Tcb::default();
            current_tcb.priority = 80;
            current_tcb.state = ThreadStateType::Running;
            let current = s
                .scheduler
                .slab
                .alloc(current_tcb)
                .expect("temporary current TCB");

            let mut peer_tcb = Tcb::default();
            peer_tcb.priority = 80;
            peer_tcb.state = ThreadStateType::Running;
            let peer = s.scheduler.admit(peer_tcb);
            s.scheduler.set_current(Some(current));
            (current, peer)
        };

        let mut sink = BufferSink::new();
        handle_syscall(Syscall::SysYield, &SyscallArgs::default(), &mut sink).unwrap();
        assert_eq!(sink.len, 0);
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.current(), None);
            assert!(s.scheduler.slab.get(current).enqueued);
            assert_eq!(s.scheduler.choose_thread(), Some(peer));
            free_temp_tcb(current);
            free_temp_tcb(peer);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ SysYield requeues a nonqueued current before choosing a peer\n");
    }

    /// Phase 14c integration spec: stage an endpoint cap in slot 1
    /// of a CNode, point the current TCB's cspace_root at that
    /// CNode, then issue SysSend with cap_ptr = 1. The dispatcher
    /// looks the cap up, finds an Endpoint with no waiter, and
    /// blocks the sender.
    #[inline(never)]
    fn sys_send_through_cspace_to_endpoint() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::kernel::{KernelState, KERNEL};
        use crate::tcb::ThreadStateType;

        unsafe {
            let s = KERNEL.get();
            let current = s.scheduler.current().expect("boot thread");

            // Plant an Endpoint cap in CNode 0, slot 1.
            let ep_ptr = KernelState::endpoint_ptr(0);
            let cnode_ptr = KernelState::cnode_ptr(0);
            let ep_cap = Cap::Endpoint {
                ptr: ep_ptr,
                badge: Badge(0xBEEF),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: false,
                    can_grant_reply: false,
                },
            };
            s.cnodes[0].0[1] = Cte::with_cap(&ep_cap);

            // Wire the current TCB's CSpace to that CNode (radix 5,
            // guard_size = 64 - 5 = 59, guard 0).
            let cnode_cap = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            s.scheduler.slab.get_mut(current).cspace_root = cnode_cap;
        }

        // Capture the boot thread id before SysSend (which blocks
        // the caller and clears scheduler.current).
        let boot_tcb = unsafe { KERNEL.get().scheduler.current().unwrap() };

        // Issue SysSend on cap_ptr=1.
        let mut sink = BufferSink::new();
        let args = SyscallArgs {
            a0: 1,    // CPtr to slot 1
            a1: 0,    // empty MessageInfo
            a2: 0xAA, // first message reg
            ..Default::default()
        };
        let r = handle_syscall(Syscall::SysSend, &args, &mut sink);
        // Blocking send to an idle endpoint with no waiter parks
        // the sender; the syscall surfaces success.
        assert!(r.is_ok(), "SysSend should not fault");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.scheduler.slab.get(boot_tcb).state,
                ThreadStateType::BlockedOnSend
            );
            assert_eq!(s.endpoints[0].state, crate::endpoint::EpState::Send);
            // Restore the boot thread for downstream specs.
            crate::endpoint::cancel_ipc(&mut s.endpoints[0], &mut s.scheduler, boot_tcb);
            s.scheduler.slab.get_mut(boot_tcb).state = ThreadStateType::Running;
            s.scheduler.set_current(Some(boot_tcb));
            s.scheduler.slab.get_mut(boot_tcb).cspace_root = Cap::Null;
        }
        arch::log("  ✓ SysSend looks up endpoint via CSpace + blocks sender\n");
    }

    /// Phase 15b: full Call → Recv → Reply round-trip without user
    /// mode. Sets up two TCBs (caller + server), a shared
    /// endpoint, and walks the dispatcher through SysCall on
    /// caller, then SysRecv + SysReply impersonating the server.
    #[inline(never)]
    fn sys_call_then_reply_round_trip() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::tcb::{Tcb, ThreadStateType};
        use crate::types::seL4_Word as Word;

        // Set up two TCBs in the slab and a shared endpoint cap
        // in CNode 3 slot 1. Both TCBs cspace-root that CNode.
        let (caller, server, ep_idx) = unsafe {
            let s = KERNEL.get();
            let cn = 3;
            let ep_idx = 1; // endpoint slot 1 (avoid the endpoint
                            // already wired up by the prior spec).
            let ep_ptr = KernelState::endpoint_ptr(ep_idx);
            let cnode_ptr = KernelState::cnode_ptr(cn);
            let ep_cap = Cap::Endpoint {
                ptr: ep_ptr,
                badge: Badge(0xC0DE),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: false,
                    can_grant_reply: true,
                },
            };
            s.cnodes[cn].0[1] = Cte::with_cap(&ep_cap);
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();

            let mk_tcb = || {
                let mut t = Tcb::default();
                t.priority = 50;
                t.state = ThreadStateType::Running;
                t.cspace_root = Cap::CNode {
                    ptr: cnode_ptr,
                    radix: 5,
                    guard_size: 59,
                    guard: 0,
                };
                t
            };
            let caller = s.scheduler.admit(mk_tcb());
            let server = s.scheduler.admit(mk_tcb());
            (caller, server, ep_idx)
        };

        let mut sink = BufferSink::new();

        // Server arrives first → blocks on Recv.
        unsafe {
            KERNEL.get().scheduler.set_current(Some(server));
        }
        let r = handle_syscall(
            Syscall::SysRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.scheduler.slab.get(server).state,
                ThreadStateType::BlockedOnReceive
            );
            assert_eq!(s.endpoints[ep_idx].state, EpState::Recv);
        }

        // Caller does SysCall (a Send + auto-block-on-Reply).
        // Sender stages 'X' as msg_regs[0], length=1.
        unsafe {
            KERNEL.get().scheduler.set_current(Some(caller));
        }
        let r = handle_syscall(
            Syscall::SysCall,
            &SyscallArgs {
                a0: 1,
                a1: 1,
                a2: b'X' as Word,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            // Caller is parked on Reply; server is runnable with
            // the message + caller in its reply_to slot.
            assert_eq!(
                s.scheduler.slab.get(caller).state,
                ThreadStateType::BlockedOnReply
            );
            assert_eq!(s.scheduler.slab.get(server).reply_to, Some(caller));
            assert_eq!(s.scheduler.slab.get(server).msg_regs[0], b'X' as Word);
        }

        // Server replies with 'Y'. Phase 36b — `SysReply` is no
        // longer a userspace syscall under MCS; the kernel-side
        // `handle_reply` is still the function that performs the
        // transfer, callable directly.
        unsafe {
            KERNEL.get().scheduler.set_current(Some(server));
        }
        let r = handle_reply(&SyscallArgs {
            a1: 1,
            a2: b'Y' as Word,
            ..Default::default()
        });
        let _ = &mut sink; // keep `sink` borrow check happy across the move
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            // Caller is back to Running with reply payload in its
            // msg_regs.
            assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.slab.get(caller).msg_regs[0], b'Y' as Word);
            // Server's reply_to slot consumed.
            assert_eq!(s.scheduler.slab.get(server).reply_to, None);
            // Clean up — free the temp TCBs and reset current.
            free_temp_tcb(caller);
            free_temp_tcb(server);
            // Restore boot thread (id 0 — first admitted) as
            // current.
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ SysCall → Recv → Reply round-trip\n");
    }

    #[inline(never)]
    fn marked_reply_cap_call_hands_off_active_sc_to_lower_priority_caller() {
        use crate::cap::Cap;
        use crate::cte::Cte;
        use crate::invocation::REPLY_HANDOFF_MAGIC;
        use crate::kernel::{KernelState, KERNEL};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};
        use crate::types::seL4_Word as Word;

        let (server, caller, reply_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 10;
            let reply_idx = 8;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.replies[reply_idx] = Reply::new();

            let mut caller_t = Tcb::default();
            caller_t.priority = 40;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.sc = Some(1);
            let caller = s.scheduler.admit(caller_t);

            let mut server_t = Tcb::default();
            server_t.priority = 255;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.active_sc = Some(1);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r13 = REPLY_HANDOFF_MAGIC;
            }
            server_t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let server = s.scheduler.admit(server_t);

            s.replies[reply_idx] = Reply {
                bound_tcb: Some(caller),
            };
            s.scheduler.set_current(Some(server));
            (server, caller, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysCall,
            &SyscallArgs {
                a0: 2,
                a1: 1,
                a2: 0x5150 as Word,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.slab.get(caller).msg_regs[0], 0x5150);
            assert_eq!(s.scheduler.slab.get(server).active_sc, None);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.scheduler.current(), Some(caller));
            s.cnodes[10].0[2] = Cte::null();
            s.replies[reply_idx] = Reply::new();
            free_temp_tcb(caller);
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ marked Reply-cap active-SC return hands off to the caller\n");
    }

    #[inline(never)]
    fn reply_cap_fault_reply_restores_unknown_syscall_context() {
        use crate::cap::Cap;
        use crate::cte::Cte;
        use crate::kernel::{KernelState, KERNEL};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        #[repr(C, align(4096))]
        struct IpcPage([u64; 512]);
        static mut SERVER_BUF: IpcPage = IpcPage([0; 512]);

        let status = 0x1234_5678u64;
        let resume_ip = 0x0000_0000_801f_0c4eu64;
        let resume_sp = 0x0000_0100_105c_3cf8u64;
        let resume_flags = 0x202u64;

        let (server, caller, reply_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 10;
            let reply_idx = 12;
            for slot in s.cnodes[cn].0.iter_mut() {
                slot.set_cap(&Cap::Null);
            }
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.replies[reply_idx] = Reply::new();

            let mut caller_t = Tcb::default();
            caller_t.priority = 40;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.pending_fault = 2;
            caller_t.user_context.rsp = 0xaaaa;
            let caller = s.scheduler.admit(caller_t);

            let mut server_t = Tcb::default();
            server_t.priority = 255;
            server_t.state = ThreadStateType::Running;
            server_t.ipc_buffer_paddr =
                crate::arch::x86_64::paging::kernel_virt_to_phys((&raw mut SERVER_BUF) as u64);
            server_t.cspace_root = Cap::CNode {
                ptr: KernelState::cnode_ptr(cn),
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let server = s.scheduler.admit(server_t);

            s.replies[reply_idx] = Reply {
                bound_tcb: Some(caller),
            };
            s.scheduler.set_current(Some(server));
            (server, caller, reply_idx)
        };

        unsafe {
            let buf = (&raw mut SERVER_BUF) as *mut u64;
            for i in 4..18 {
                core::ptr::write_volatile(buf.add(1 + i), 0);
            }
            core::ptr::write_volatile(buf.add(1 + 15), resume_ip);
            core::ptr::write_volatile(buf.add(1 + 16), resume_sp);
            core::ptr::write_volatile(buf.add(1 + 17), resume_flags);
        }

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysCall,
            &SyscallArgs {
                a0: 2,
                a1: 18,
                a2: status as Word,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            let caller_t = s.scheduler.slab.get(caller);
            assert_eq!(caller_t.state, ThreadStateType::Running);
            assert_eq!(caller_t.pending_fault, 0);
            assert_eq!(caller_t.user_context.rax, status);
            assert_eq!(caller_t.user_context.rsp, resume_sp);
            assert_eq!(crate::fault::resume_ip(caller_t), resume_ip);
            assert_eq!(crate::fault::resume_flags(caller_t), resume_flags);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            s.cnodes[10].0[2] = Cte::null();
            s.replies[reply_idx] = Reply::new();
            free_temp_tcb(caller);
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ Reply-cap fault reply restores UnknownSyscall resume context\n");
    }

    #[inline(never)]
    fn nbsendrecv_fault_reply_rearms_endpoint_receive() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        #[repr(C, align(4096))]
        struct IpcPage([u64; 512]);
        static mut SERVER_BUF: IpcPage = IpcPage([0; 512]);

        let initial_rax = 0x7777_8888u64;
        let resume_ip = 0x0000_0100_0085_76b8u64;
        let resume_sp = 0x0000_0100_105b_feb0u64;
        let resume_flags = 0x202u64;

        let (server, caller, ep_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 13;
            let ep_idx = 10;
            let reply_idx = 11;
            for slot in s.cnodes[cn].0.iter_mut() {
                slot.set_cap(&Cap::Null);
            }
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xF1),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.replies[reply_idx] = Reply { bound_tcb: None };

            let mut caller_t = Tcb::default();
            caller_t.priority = 40;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.pending_fault = 6;
            caller_t.user_context.rax = initial_rax;
            caller_t.user_context.rsp = resume_sp;
            crate::fault::set_resume_ip(&mut caller_t, resume_ip);
            crate::fault::set_resume_flags(&mut caller_t, resume_flags);
            caller_t.sc = Some(1);
            caller_t.cspace_root = Cap::CNode {
                ptr: KernelState::cnode_ptr(cn),
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            caller_t.fault_handler = 1;
            let caller = s.scheduler.admit(caller_t);

            let mut server_t = Tcb::default();
            server_t.priority = 255;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.ipc_buffer_paddr =
                crate::arch::x86_64::paging::kernel_virt_to_phys((&raw mut SERVER_BUF) as u64);
            server_t.cspace_root = Cap::CNode {
                ptr: KernelState::cnode_ptr(cn),
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r12 = 2;
                server_t.user_context.r13 = 2;
            }
            let server = s.scheduler.admit(server_t);

            s.replies[reply_idx] = Reply {
                bound_tcb: Some(caller),
            };
            s.scheduler.set_current(Some(server));
            (server, caller, ep_idx, reply_idx)
        };

        unsafe {
            let buf = (&raw mut SERVER_BUF) as *mut u64;
            for i in 4..18 {
                core::ptr::write_volatile(buf.add(1 + i), 0);
            }
            core::ptr::write_volatile(buf.add(1 + 15), resume_ip);
            core::ptr::write_volatile(buf.add(1 + 16), resume_sp);
            core::ptr::write_volatile(buf.add(1 + 17), resume_flags);
        }

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysNBSendRecv,
            &SyscallArgs {
                a0: 1,
                a1: 0,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            let caller_t = s.scheduler.slab.get(caller);
            assert_eq!(caller_t.state, ThreadStateType::Running);
            assert_eq!(caller_t.pending_fault, 0);
            assert_eq!(caller_t.user_context.rax, initial_rax);
            assert_eq!(caller_t.user_context.rsp, resume_sp);
            assert_eq!(crate::fault::resume_ip(caller_t), resume_ip);
            assert_eq!(crate::fault::resume_flags(caller_t), resume_flags);

            let server_t = s.scheduler.slab.get(server);
            assert_eq!(server_t.state, ThreadStateType::BlockedOnReceive);
            assert_eq!(server_t.pending_reply, Some(reply_idx as u16));
            assert_eq!(server_t.composite_reply_handoff, Some(caller));
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert!(matches!(s.endpoints[ep_idx].state, EpState::Recv));

            s.scheduler.set_current(Some(caller));
            assert_eq!(s.scheduler.choose_thread(), Some(caller));
            crate::fault::deliver_fault(
                caller,
                crate::fault::FaultMessage::VMFault {
                    addr: 0x0000_0100_0094_46b8,
                    fsr: 0x7,
                    instruction: false,
                },
            )
            .expect("second VM fault should meet the server's re-armed receive");

            let caller_t = s.scheduler.slab.get(caller);
            assert_eq!(caller_t.state, ThreadStateType::BlockedOnReply);
            assert_eq!(caller_t.pending_fault, 6);
            let server_t = s.scheduler.slab.get(server);
            assert_eq!(server_t.state, ThreadStateType::Running);
            assert_eq!(server_t.pending_reply, None);
            assert_eq!(server_t.reply_to, Some(caller));
            assert_eq!(server_t.user_context.rdi, 0xF1);
            assert_eq!(server_t.user_context.rsi, 6 << 12 | 4);
            assert_eq!(server_t.user_context.r10, resume_ip);
            assert_eq!(server_t.user_context.r8, 0x0000_0100_0094_46b8);
            assert_eq!(server_t.user_context.r9, 0);
            assert_eq!(server_t.user_context.r15, 0x7);
            assert_eq!(s.replies[reply_idx].bound_tcb, Some(caller));
            assert!(matches!(s.endpoints[ep_idx].state, EpState::Idle));

            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.cnodes[13].0[1] = Cte::null();
            s.cnodes[13].0[2] = Cte::null();
            s.replies[reply_idx] = Reply::new();
            free_temp_tcb(caller);
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ NBSendRecv fault reply re-arms endpoint receive\n");
    }

    #[inline(never)]
    fn marked_reply_cap_call_hands_off_independent_sc_to_lower_priority_caller() {
        use crate::cap::Cap;
        use crate::cte::Cte;
        use crate::invocation::REPLY_HANDOFF_MAGIC;
        use crate::kernel::{KernelState, KERNEL};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};
        use crate::types::seL4_Word as Word;

        let (server, caller, reply_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 11;
            let reply_idx = 9;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.replies[reply_idx] = Reply::new();

            let mut caller_t = Tcb::default();
            caller_t.priority = 40;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.sc = Some(1);
            let caller = s.scheduler.admit(caller_t);

            let mut server_t = Tcb::default();
            server_t.priority = 255;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r13 = REPLY_HANDOFF_MAGIC;
            }
            server_t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let server = s.scheduler.admit(server_t);

            s.replies[reply_idx] = Reply {
                bound_tcb: Some(caller),
            };
            s.scheduler.set_current(Some(server));
            (server, caller, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysCall,
            &SyscallArgs {
                a0: 2,
                a1: 1,
                a2: 0x6261 as Word,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.slab.get(caller).msg_regs[0], 0x6261);
            assert_eq!(s.scheduler.slab.get(server).active_sc, None);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.scheduler.current(), Some(caller));
            s.cnodes[11].0[2] = Cte::null();
            s.replies[reply_idx] = Reply::new();
            free_temp_tcb(caller);
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ marked Reply-cap independent-SC return hands off to the caller\n");
    }

    #[inline(never)]
    fn recv_bound_notification_does_not_stage_reply_cap() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, ep_idx, ntfn_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            let cn = 4;
            let ep_idx = 2;
            let ntfn_idx = 2;
            let reply_idx = 2;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            let ep_cap = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE0),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            };
            let reply_cap = Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            };
            s.cnodes[cn].0[1] = Cte::with_cap(&ep_cap);
            s.cnodes[cn].0[2] = Cte::with_cap(&reply_cap);
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification {
                state: NtfnState::Active,
                pending_badge: 0xBAD0,
                ..Notification::new()
            };
            s.replies[reply_idx] = Reply::new();

            let mut t = Tcb::default();
            t.priority = 50;
            t.state = ThreadStateType::Running;
            t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            t.bound_notification = Some(ntfn_idx as u16);
            #[cfg(target_arch = "x86_64")]
            {
                t.user_context.r12 = 2;
            }
            let server = s.scheduler.admit(t);
            s.scheduler.set_current(Some(server));
            (server, ep_idx, ntfn_idx, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            let t = s.scheduler.slab.get(server);
            assert_eq!(t.pending_reply, None);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.endpoints[ep_idx].state, EpState::Idle);
            #[cfg(target_arch = "x86_64")]
            assert_eq!(t.user_context.rdi, 0xBAD0);
            s.notifications[ntfn_idx] = Notification::new();
            s.cnodes[4].0[1] = Cte::null();
            s.cnodes[4].0[2] = Cte::null();
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ bound notifications do not consume Recv reply caps\n");
    }

    #[inline(never)]
    fn recv_bound_notification_rotates_behind_ready_peer() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::sched_context::SchedContext;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, peer, ep_idx, ntfn_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 11;
            let ep_idx = 8;
            let ntfn_idx = 8;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE8),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification {
                state: NtfnState::Active,
                pending_badge: 0xD1,
                ..Notification::new()
            };
            s.sched_contexts[0] = SchedContext::new(10, 10);
            s.sched_contexts[1] = SchedContext::new(10, 10);

            let mut server_t = Tcb::default();
            server_t.priority = 100;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            server_t.bound_notification = Some(ntfn_idx as u16);
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx].bound_tcb = Some(server);
            s.sched_contexts[0].bound_tcb = Some(server);

            let mut peer_t = Tcb::default();
            peer_t.priority = 100;
            peer_t.state = ThreadStateType::Running;
            peer_t.sc = Some(1);
            let peer = s.scheduler.admit(peer_t);
            s.sched_contexts[1].bound_tcb = Some(peer);

            s.scheduler.set_current(Some(server));
            (server, peer, ep_idx, ntfn_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(server).ipc_badge, 0xD1);
            #[cfg(target_arch = "x86_64")]
            let server_rdi = s.scheduler.slab.get(server).user_context.rdi;
            #[cfg(target_arch = "x86_64")]
            let server_rsi = s.scheduler.slab.get(server).user_context.rsi;
            assert_eq!(s.endpoints[ep_idx].state, EpState::Idle);
            assert_eq!(s.notifications[ntfn_idx].state, NtfnState::Idle);
            assert_eq!(s.scheduler.current(), None);
            assert_eq!(s.scheduler.choose_thread(), Some(peer));
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(server_rdi, 0xD1);
                assert_eq!(server_rsi, 0);
            }
            s.notifications[ntfn_idx] = Notification::new();
            s.cnodes[11].0[1] = Cte::null();
            s.sched_contexts[0] = SchedContext::new(0, 0);
            s.sched_contexts[1] = SchedContext::new(0, 0);
            free_temp_tcb(peer);
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ bound notification receive rotates behind a ready peer\n");
    }

    #[inline(never)]
    fn blocked_recv_bound_notification_clears_reply_offer() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, ep_idx, ntfn_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            let cn = 8;
            let ep_idx = 6;
            let ntfn_idx = 5;
            let reply_idx = 6;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE6),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification::new();
            s.replies[reply_idx] = Reply::new();

            let mut server_t = Tcb::default();
            server_t.priority = 50;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            server_t.bound_notification = Some(ntfn_idx as u16);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r12 = 2;
            }
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx] = Notification {
                bound_tcb: Some(server),
                ..Notification::new()
            };
            s.scheduler.set_current(Some(server));
            (server, ep_idx, ntfn_idx, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.scheduler.slab.get(server).state,
                ThreadStateType::BlockedOnReceive
            );
            assert_eq!(
                s.scheduler.slab.get(server).pending_reply,
                Some(reply_idx as u16)
            );
            assert_eq!(s.endpoints[ep_idx].state, EpState::Recv);

            let s_ptr: *mut KernelState = s;
            let _ = crate::notification::signal(
                &mut (*s_ptr).notifications[ntfn_idx],
                &mut (*s_ptr).scheduler,
                0xBAD2,
            );
            let server_t = s.scheduler.slab.get(server);
            assert_eq!(server_t.state, ThreadStateType::Running);
            assert_eq!(server_t.pending_reply, None);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.endpoints[ep_idx].state, EpState::Idle);
            assert_eq!(s.notifications[ntfn_idx].state, NtfnState::Idle);
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(server_t.user_context.rdi, 0xBAD2);
                assert_eq!(server_t.user_context.rsi, 0);
            }
            s.notifications[ntfn_idx] = Notification::new();
            s.cnodes[8].0[1] = Cte::null();
            s.cnodes[8].0[2] = Cte::null();
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ bound-notification wake clears blocked Recv reply offer\n");
    }

    #[inline(never)]
    fn irq_bound_notification_wakes_blocked_endpoint_recv() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        const IRQ: u16 = 31;
        const IRQ_BADGE: u64 = 0x4000_0000_0000_0000;

        let (server, ep_idx, ntfn_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            let cn = 13;
            let ep_idx = 10;
            let ntfn_idx = 10;
            let reply_idx = 11;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.scheduler.reset_queues();
            s.irqs = crate::interrupt::IrqTable::new();
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE1F0),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification::new();
            s.replies[reply_idx] = Reply::new();

            let mut server_t = Tcb::default();
            server_t.priority = 100;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            server_t.bound_notification = Some(ntfn_idx as u16);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r12 = 2;
            }
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx] = Notification {
                bound_tcb: Some(server),
                ..Notification::new()
            };
            crate::interrupt::set_notification(&mut s.irqs, IRQ, ntfn_idx as u16, IRQ_BADGE)
                .unwrap();
            s.scheduler.set_current(Some(server));
            (server, ep_idx, ntfn_idx, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.scheduler.slab.get(server).state,
                ThreadStateType::BlockedOnReceive
            );
            assert_eq!(
                s.scheduler.slab.get(server).pending_reply,
                Some(reply_idx as u16)
            );
            assert_eq!(s.endpoints[ep_idx].state, EpState::Recv);

            let s_ptr: *mut KernelState = s;
            let woke = crate::interrupt::handle_interrupt(
                &mut (*s_ptr).irqs,
                &mut (*s_ptr).notifications,
                &mut (*s_ptr).scheduler,
                IRQ,
            );
            let server_t = (*s_ptr).scheduler.slab.get(server);
            assert_eq!(woke, Some(server));
            assert_eq!(server_t.state, ThreadStateType::Running);
            assert_eq!(server_t.pending_reply, None);
            assert_eq!((*s_ptr).replies[reply_idx].bound_tcb, None);
            assert_eq!((*s_ptr).endpoints[ep_idx].state, EpState::Idle);
            assert_eq!((*s_ptr).notifications[ntfn_idx].state, NtfnState::Idle);
            assert!((*s_ptr).irqs.get(IRQ).unwrap().pending);
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(server_t.user_context.rdi, IRQ_BADGE);
                assert_eq!(server_t.user_context.rsi, 0);
            }

            (*s_ptr).notifications[ntfn_idx] = Notification::new();
            (*s_ptr).replies[reply_idx] = Reply::new();
            (*s_ptr).endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            (*s_ptr).cnodes[13].0[1] = Cte::null();
            (*s_ptr).cnodes[13].0[2] = Cte::null();
            (*s_ptr).irqs = crate::interrupt::IrqTable::new();
            free_temp_tcb(server);
            (*s_ptr).scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ IRQ-bound notification wakes blocked endpoint Recv\n");
    }

    #[inline(never)]
    fn recv_prefers_queued_endpoint_over_bound_notification() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::{send_ipc, EpState, IpcOutcome, SendOptions};
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, caller, ep_idx, ntfn_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            let cn = 7;
            let ep_idx = 5;
            let ntfn_idx = 4;
            let reply_idx = 5;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            let ep_cap = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE5),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            };
            let reply_cap = Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            };
            s.cnodes[cn].0[1] = Cte::with_cap(&ep_cap);
            s.cnodes[cn].0[2] = Cte::with_cap(&reply_cap);
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification {
                state: NtfnState::Active,
                pending_badge: 0xBAD1,
                ..Notification::new()
            };
            s.replies[reply_idx] = Reply::new();

            let mut server_t = Tcb::default();
            server_t.priority = 50;
            server_t.state = ThreadStateType::Running;
            server_t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            server_t.bound_notification = Some(ntfn_idx as u16);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r12 = 2;
            }
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx].bound_tcb = Some(server);

            let mut caller_t = Tcb::default();
            caller_t.priority = 50;
            caller_t.state = ThreadStateType::Running;
            caller_t.ipc_label = 0x44;
            caller_t.ipc_length = 1;
            caller_t.msg_regs[0] = 0xC0DE;
            let caller = s.scheduler.admit(caller_t);
            let s_ptr: *mut KernelState = s;
            let outcome = send_ipc(
                &mut (*s_ptr).endpoints[ep_idx],
                &mut (*s_ptr).scheduler,
                caller,
                SendOptions {
                    blocking: true,
                    do_call: true,
                    can_grant: false,
                    can_donate: false,
                    badge: 0xCA11,
                },
            );
            assert!(matches!(outcome, IpcOutcome::Blocked));
            s.scheduler.set_current(Some(server));
            (server, caller, ep_idx, ntfn_idx, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            let server_t = s.scheduler.slab.get(server);
            assert_eq!(server_t.pending_reply, None);
            assert_eq!(s.replies[reply_idx].bound_tcb, Some(caller));
            assert_eq!(s.endpoints[ep_idx].state, EpState::Idle);
            assert_eq!(s.notifications[ntfn_idx].state, NtfnState::Active);
            assert_eq!(s.notifications[ntfn_idx].pending_badge, 0xBAD1);
            assert_eq!(
                s.scheduler.slab.get(caller).state,
                ThreadStateType::BlockedOnReply
            );
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(server_t.user_context.rdi, 0xCA11);
                assert_eq!(server_t.user_context.rsi, (0x44 << 12) | 1);
                assert_eq!(server_t.user_context.r10, 0xC0DE);
            }
            s.notifications[ntfn_idx] = Notification::new();
            s.replies[reply_idx] = Reply::new();
            s.cnodes[7].0[1] = Cte::null();
            s.cnodes[7].0[2] = Cte::null();
            free_temp_tcb(caller);
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ queued endpoint IPC wins over active bound notification\n");
    }

    #[inline(never)]
    fn replyrecv_reply_wake_hands_off_after_bound_notification() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, caller, ntfn_idx, ep_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 12;
            let ep_idx = 9;
            let ntfn_idx = 9;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE9),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification {
                state: NtfnState::Active,
                pending_badge: 0xD3,
                ..Notification::new()
            };

            let cspace = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let mut caller_t = Tcb::default();
            caller_t.priority = 100;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.sc = Some(1);
            let caller = s.scheduler.admit(caller_t);

            let mut server_t = Tcb::default();
            server_t.priority = 120;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.cspace_root = cspace;
            server_t.bound_notification = Some(ntfn_idx as u16);
            server_t.reply_to = Some(caller);
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx].bound_tcb = Some(server);
            s.scheduler.set_current(Some(server));
            (server, caller, ntfn_idx, ep_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysReplyRecv,
            &SyscallArgs {
                a0: 1,
                a1: 1,
                a2: 0xC0DE,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            let server_t = s.scheduler.slab.get(server);
            assert_eq!(server_t.reply_to, None);
            assert_eq!(server_t.composite_reply_handoff, None);
            assert_eq!(server_t.user_context.rdi, 0xD3);
            assert_eq!(server_t.user_context.rsi, 0);
            assert_eq!(s.notifications[ntfn_idx].state, NtfnState::Idle);
            assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.current(), Some(caller));
            s.notifications[ntfn_idx] = Notification::new();
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.cnodes[12].0[1] = Cte::null();
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
            free_temp_tcb(caller);
            free_temp_tcb(server);
        }
        arch::log("  ✓ ReplyRecv reply wake hands off after bound-notification receive\n");
    }

    #[inline(never)]
    fn nbsendrecv_reply_wake_yields_after_bound_notification() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, caller, ntfn_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 9;
            let ep_idx = 7;
            let ntfn_idx = 7;
            let reply_idx = 7;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE7),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification {
                state: NtfnState::Active,
                pending_badge: 0xD1,
                ..Notification::new()
            };

            let cspace = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let mut server_t = Tcb::default();
            server_t.priority = 120;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.cspace_root = cspace;
            server_t.bound_notification = Some(ntfn_idx as u16);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r12 = 2;
                server_t.user_context.r13 = 2;
            }
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx].bound_tcb = Some(server);

            let mut caller_t = Tcb::default();
            caller_t.priority = 100;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.sc = Some(1);
            let caller = s.scheduler.admit(caller_t);
            s.replies[reply_idx] = Reply {
                bound_tcb: Some(caller),
            };
            s.scheduler.set_current(Some(server));
            (server, caller, ntfn_idx, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysNBSendRecv,
            &SyscallArgs {
                a0: 1,
                a1: 1,
                a2: 0xABCD,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            let server_t = s.scheduler.slab.get(server);
            assert_eq!(server_t.user_context.rdi, 0xD1);
            assert_eq!(server_t.user_context.rsi, 0);
            assert_eq!(s.notifications[ntfn_idx].state, NtfnState::Idle);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.current(), Some(caller));
            s.scheduler.set_current(Some(server));
            assert_eq!(s.scheduler.take_direct_handoff(), Some(caller));
            s.notifications[ntfn_idx] = Notification::new();
            s.replies[reply_idx] = Reply::new();
            s.cnodes[9].0[1] = Cte::null();
            s.cnodes[9].0[2] = Cte::null();
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
            free_temp_tcb(caller);
            free_temp_tcb(server);
        }
        arch::log("  ✓ NBSendRecv reply wake hands off after bound-notification receive\n");
    }

    #[inline(never)]
    fn nbsendrecv_deferred_reply_wake_survives_later_bound_notification() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, caller, ntfn_idx, reply_idx, ep_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 11;
            let ep_idx = 8;
            let ntfn_idx = 8;
            let reply_idx = 9;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE8),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification {
                state: NtfnState::Idle,
                ..Notification::new()
            };

            let cspace = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let mut server_t = Tcb::default();
            server_t.priority = 100;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.cspace_root = cspace;
            server_t.bound_notification = Some(ntfn_idx as u16);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r12 = 2;
                server_t.user_context.r13 = 2;
            }
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx].bound_tcb = Some(server);

            let mut caller_t = Tcb::default();
            caller_t.priority = 100;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.sc = Some(1);
            let caller = s.scheduler.admit(caller_t);
            s.replies[reply_idx] = Reply {
                bound_tcb: Some(caller),
            };
            s.scheduler.set_current(Some(server));
            (server, caller, ntfn_idx, reply_idx, ep_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysNBSendRecv,
            &SyscallArgs {
                a0: 1,
                a1: 1,
                a2: 0xBCDE,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.scheduler.slab.get(server).state,
                ThreadStateType::BlockedOnReceive
            );
            assert_eq!(
                s.scheduler.slab.get(server).composite_reply_handoff,
                Some(caller)
            );
            assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.current(), None);

            let s_ptr: *mut KernelState = s;
            let woke = crate::notification::signal(
                &mut (*s_ptr).notifications[ntfn_idx],
                &mut (*s_ptr).scheduler,
                0xD2,
            );
            assert_eq!(woke, Some(server));
            assert_eq!(
                (*s_ptr).scheduler.slab.get(server).composite_reply_handoff,
                None
            );
            assert_eq!((*s_ptr).scheduler.slab.get(server).user_context.rdi, 0xD2);
            assert_eq!((*s_ptr).scheduler.current(), Some(caller));
            assert_eq!((*s_ptr).scheduler.take_direct_handoff(), Some(caller));

            (*s_ptr).notifications[ntfn_idx] = Notification::new();
            (*s_ptr).replies[reply_idx] = Reply::new();
            (*s_ptr).endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            (*s_ptr).cnodes[11].0[1] = Cte::null();
            (*s_ptr).cnodes[11].0[2] = Cte::null();
            (*s_ptr).scheduler.set_current(Some(crate::tcb::TcbId(0)));
            free_temp_tcb(caller);
            free_temp_tcb(server);
        }
        arch::log("  ✓ NBSendRecv deferred reply wake survives later bound-notification receive\n");
    }

    #[inline(never)]
    fn nbsendrecv_stale_reply_handoff_does_not_starve_bound_receiver() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::kernel::{KernelState, KERNEL};
        use crate::notification::{Notification, NtfnState};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, caller, ntfn_idx, reply_idx, ep_idx) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            let cn = 12;
            let ep_idx = 9;
            let ntfn_idx = 9;
            let reply_idx = 10;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE9),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.notifications[ntfn_idx] = Notification {
                state: NtfnState::Idle,
                ..Notification::new()
            };

            let cspace = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let mut server_t = Tcb::default();
            server_t.priority = 255;
            server_t.state = ThreadStateType::Running;
            server_t.sc = Some(0);
            server_t.cspace_root = cspace;
            server_t.bound_notification = Some(ntfn_idx as u16);
            #[cfg(target_arch = "x86_64")]
            {
                server_t.user_context.r12 = 2;
                server_t.user_context.r13 = 2;
            }
            let server = s.scheduler.admit(server_t);
            s.notifications[ntfn_idx].bound_tcb = Some(server);

            let mut caller_t = Tcb::default();
            caller_t.priority = 100;
            caller_t.state = ThreadStateType::BlockedOnReply;
            caller_t.sc = Some(1);
            let caller = s.scheduler.admit(caller_t);
            s.replies[reply_idx] = Reply {
                bound_tcb: Some(caller),
            };
            s.scheduler.set_current(Some(server));
            (server, caller, ntfn_idx, reply_idx, ep_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysNBSendRecv,
            &SyscallArgs {
                a0: 1,
                a1: 1,
                a2: 0xCDEF,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.scheduler.slab.get(server).state,
                ThreadStateType::BlockedOnReceive
            );
            assert_eq!(
                s.scheduler.slab.get(server).composite_reply_handoff,
                Some(caller)
            );
            assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);

            // Model the real interrupt path after the reply target has
            // already been dispatched and is interrupted by the bound
            // timer notification.
            s.scheduler.set_current(Some(caller));
            let s_ptr: *mut KernelState = s;
            let woke = crate::notification::signal(
                &mut (*s_ptr).notifications[ntfn_idx],
                &mut (*s_ptr).scheduler,
                0xD3,
            );
            assert_eq!(woke, Some(server));
            assert_eq!(
                (*s_ptr).scheduler.slab.get(server).composite_reply_handoff,
                None
            );
            assert_eq!((*s_ptr).scheduler.slab.get(server).user_context.rdi, 0xD3);
            assert_eq!((*s_ptr).scheduler.current(), None);
            assert_eq!((*s_ptr).scheduler.take_direct_handoff(), None);
            assert_eq!((*s_ptr).scheduler.choose_thread(), Some(server));

            (*s_ptr).notifications[ntfn_idx] = Notification::new();
            (*s_ptr).replies[reply_idx] = Reply::new();
            (*s_ptr).endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            (*s_ptr).cnodes[12].0[1] = Cte::null();
            (*s_ptr).cnodes[12].0[2] = Cte::null();
            (*s_ptr).scheduler.set_current(Some(crate::tcb::TcbId(0)));
            free_temp_tcb(caller);
            free_temp_tcb(server);
        }
        arch::log("  ✓ NBSendRecv stale reply handoff does not starve bound receiver\n");
    }

    #[inline(never)]
    fn nbrecv_with_reply_cap_does_not_leave_pending_offer() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};

        let (server, ep_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            let cn = 5;
            let ep_idx = 3;
            let reply_idx = 3;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE1),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.replies[reply_idx] = Reply::new();

            let mut t = Tcb::default();
            t.priority = 50;
            t.state = ThreadStateType::Running;
            t.cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            #[cfg(target_arch = "x86_64")]
            {
                t.user_context.r12 = 2;
            }
            let server = s.scheduler.admit(t);
            s.scheduler.set_current(Some(server));
            (server, ep_idx, reply_idx)
        };

        let mut sink = BufferSink::new();
        let r = handle_syscall(
            Syscall::SysNBRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            let t = s.scheduler.slab.get(server);
            assert_eq!(t.pending_reply, None);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.endpoints[ep_idx].state, EpState::Idle);
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(t.user_context.rdi, 0);
                assert_eq!(t.user_context.rsi, 0);
            }
            s.cnodes[5].0[1] = Cte::null();
            s.cnodes[5].0[2] = Cte::null();
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ NBRecv does not leave an unpaired reply-cap offer\n");
    }

    #[inline(never)]
    fn plain_send_recv_with_reply_cap_does_not_leave_pending_offer() {
        use crate::cap::{Badge, Cap, EndpointRights};
        use crate::cte::Cte;
        use crate::endpoint::EpState;
        use crate::kernel::{KernelState, KERNEL};
        use crate::reply::Reply;
        use crate::tcb::{Tcb, ThreadStateType};
        use crate::types::seL4_Word as Word;

        let (sender, server, ep_idx, reply_idx) = unsafe {
            let s = KERNEL.get();
            let cn = 6;
            let ep_idx = 4;
            let reply_idx = 4;
            let cnode_ptr = KernelState::cnode_ptr(cn);
            s.cnodes[cn].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(ep_idx),
                badge: Badge(0xE2),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            });
            s.cnodes[cn].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.endpoints[ep_idx] = crate::endpoint::Endpoint::new();
            s.replies[reply_idx] = Reply::new();

            let mk_tcb = || {
                let mut t = Tcb::default();
                t.priority = 50;
                t.state = ThreadStateType::Running;
                t.cspace_root = Cap::CNode {
                    ptr: cnode_ptr,
                    radix: 5,
                    guard_size: 59,
                    guard: 0,
                };
                t
            };
            let sender = s.scheduler.admit(mk_tcb());
            let mut server_tcb = mk_tcb();
            #[cfg(target_arch = "x86_64")]
            {
                server_tcb.user_context.r12 = 2;
            }
            let server = s.scheduler.admit(server_tcb);
            (sender, server, ep_idx, reply_idx)
        };

        let mut sink = BufferSink::new();
        unsafe {
            KERNEL.get().scheduler.set_current(Some(sender));
        }
        let r = handle_syscall(
            Syscall::SysSend,
            &SyscallArgs {
                a0: 1,
                a1: 1,
                a2: b'P' as Word,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            KERNEL.get().scheduler.set_current(Some(server));
        }
        let r = handle_syscall(
            Syscall::SysRecv,
            &SyscallArgs {
                a0: 1,
                ..Default::default()
            },
            &mut sink,
        );
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(server).pending_reply, None);
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.scheduler.slab.get(sender).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.slab.get(server).msg_regs[0], b'P' as Word);
            assert_eq!(s.endpoints[ep_idx].state, EpState::Idle);
            s.cnodes[6].0[1] = Cte::null();
            s.cnodes[6].0[2] = Cte::null();
            free_temp_tcb(sender);
            free_temp_tcb(server);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ plain Send receive does not retain the offered reply cap\n");
    }

    unsafe fn free_temp_tcb(id: crate::tcb::TcbId) {
        let s = crate::kernel::KERNEL.get();
        if s.scheduler.slab.try_get(id).is_none() {
            return;
        }
        crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, id);
        s.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
        s.scheduler.slab.free(id);
        s.scheduler.reset_queues();
    }

    #[inline(never)]
    fn debug_dump_scheduler_writes_placeholder() {
        let mut sink = BufferSink::new();
        handle_syscall(
            Syscall::SysDebugDumpScheduler,
            &SyscallArgs::default(),
            &mut sink,
        )
        .unwrap();
        assert!(sink.as_str().contains("scheduler dump"));
        arch::log("  ✓ SysDebugDumpScheduler stubs out a placeholder line\n");
    }
}
