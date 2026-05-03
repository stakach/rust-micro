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
        Self { a0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }
    }
}

/// Sink for kernel debug bytes. The kernel implements this around
/// `arch::log`; specs implement it around an in-memory buffer so they
/// can assert the exact byte sequence emitted by `SysDebugPutChar`.
pub trait DebugSink {
    fn put_byte(&mut self, byte: u8);
}

/// Best-effort cap-type tag for `seL4_DebugCapIdentify`. Upstream
/// returns cap-specific tag values (cap_endpoint_cap = 4 etc.);
/// libsel4allocman's debug-build sanity checks only care that 0 =
/// null and any other value = non-null. We honour that contract:
/// 0 for Null, 1 for everything else.
#[cfg(target_arch = "x86_64")]
fn debug_cap_type_tag(cap: &crate::cap::Cap) -> u64 {
    match cap {
        crate::cap::Cap::Null => 0,
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
        Syscall::SysSend => handle_send(args, /* blocking */ true, /* call */ false),
        Syscall::SysNBSend => handle_send(args, /* blocking */ false, /* call */ false),
        Syscall::SysCall => handle_send(args, /* blocking */ true, /* call */ true),
        Syscall::SysRecv => handle_recv(args, /* blocking */ true),
        Syscall::SysNBRecv => handle_recv(args, /* blocking */ false),
        // Phase 36b — under MCS there's no standalone Reply syscall;
        // reply is via Send on a Cap::Reply. Until the cap-based
        // reply IPC integration lands (the 34e follow-up), the
        // existing `handle_reply` path stays callable directly from
        // kernel specs but isn't reachable from userspace.
        Syscall::SysReplyRecv => {
            handle_reply(args)?;
            handle_recv(args, /* blocking */ true)
        }
        // Phase 36b — MCS notification-only Recv variants. Forward
        // to handle_recv for now; the difference (Wait doesn't
        // capture a reply cap because the receiver isn't a server
        // expecting a Call) will matter once cap-based reply lands.
        Syscall::SysWait => handle_recv(args, /* blocking */ true),
        Syscall::SysNBWait => handle_recv(args, /* blocking */ false),
        // Phase 36b — atomic Send+Recv composites. Not implemented
        // yet; surface IllegalOperation so user code spots the gap.
        Syscall::SysNBSendRecv | Syscall::SysNBSendWait => {
            Err(crate::error::KException::SyscallError(
                crate::error::SyscallError::new(
                    crate::types::seL4_Error::seL4_IllegalOperation,
                ),
            ))
        }
        Syscall::SysYield => {
            // Phase 29h — when the rootserver demo is live, yield
            // actually rotates so a child that's done its IPC can
            // hand the CPU back to the rootserver. Outside that
            // path, leave `SysYield` as the original no-op so spec
            // teardowns (which leave stale priority-bitmap state
            // across admit/free cycles) don't trip.
            //
            // The current thread is already enqueued (admit /
            // make_runnable / choose_thread all leave it on its
            // priority queue). Yield = "let an equal-priority peer
            // go first": dequeue cur and re-add it at the tail,
            // then clear `current` so the syscall return path picks
            // the new head. Re-enqueueing without dequeuing first
            // double-adds `cur` and corrupts the intrusive list.
            #[cfg(target_arch = "x86_64")]
            if crate::rootserver::ROOTSERVER_DEMO_ACTIVE
                .load(core::sync::atomic::Ordering::Relaxed)
            {
                unsafe {
                    let s = crate::kernel::KERNEL.get();
                    if let Some(cur) = s.scheduler.current() {
                        let cpu = crate::arch::get_cpu_id() as usize;
                        let q = &mut s.scheduler.nodes[cpu].queues;
                        let slab = &mut s.scheduler.slab;
                        q.dequeue(slab, cur);
                        q.enqueue(slab, cur);
                        s.scheduler.set_current(None);
                    }
                }
            }
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
                    let cspace_root = KERNEL.get().scheduler.slab
                        .get(cur).cspace_root;
                    let tag = match crate::cspace::lookup_cap(
                        KERNEL.get(), &cspace_root, args.a0)
                    {
                        Ok(cap) => debug_cap_type_tag(&cap),
                        Err(_) => 0,
                    };
                    let t = KERNEL.get().scheduler.slab.get_mut(cur);
                    t.user_context.rdi = tag;
                }
            }
            Ok(())
        }
        Syscall::SysDebugSnapshot
        | Syscall::SysDebugNameThread
        | Syscall::SysDebugSendIPI => {
            // Best-effort no-ops. Names would print to serial; we
            // skip for now.
            Ok(())
        }
        Syscall::SysSetTLSBase => {
            // Phase 41 — set IA32_FS_BASE for the current thread.
            // sel4test-driver's musllibc uses this to anchor TLS at
            // a known vaddr. We just write the MSR for now; per-TCB
            // save/restore on context switch is a follow-up — for
            // the smoke test the rootserver is the only thread
            // touching FS_BASE.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use crate::arch::x86_64::msr::{wrmsr, IA32_FS_BASE};
                wrmsr(IA32_FS_BASE, args.a0);
            }
            Ok(())
        }
        Syscall::SysX86DangerousWRMSR => {
            // Phase 41 — WRMSR(reg, value). Used by sel4test-driver
            // to set FS_BASE (its preferred TLS path). args.a0 = MSR
            // index, args.a1 = value.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                crate::arch::x86_64::msr::wrmsr(args.a0 as u32, args.a1);
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
    use crate::types::seL4_Word as Word;

    unsafe {
        let s = KERNEL.get();
        let current = s.scheduler.current().ok_or_else(|| {
            KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            ))
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
        // common transfer machinery picks it up.
        let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
        {
            let me = s.scheduler.slab.get_mut(current);
            me.ipc_label = info.label();
            me.ipc_length = info.length() as u32;
            me.msg_regs[0] = args.a2;
            me.msg_regs[1] = args.a3;
            me.msg_regs[2] = args.a4;
            me.msg_regs[3] = args.a5;
            me.reply_to = None; // consume the reply slot
        }
        // Copy from current → caller. We can reuse endpoint's
        // transfer if we expose it; for clarity we inline the
        // minimal copy here.
        let (label, length, regs): (Word, u32, [Word; crate::tcb::SCRATCH_MSG_LEN]) = {
            let me = s.scheduler.slab.get(current);
            (me.ipc_label, me.ipc_length, me.msg_regs)
        };
        {
            let r = s.scheduler.slab.get_mut(caller);
            r.ipc_label = label;
            r.ipc_length = length;
            r.ipc_badge = 0; // reply has no badge
            let n = (length as usize).min(r.msg_regs.len());
            r.msg_regs[..n].copy_from_slice(&regs[..n]);
        }
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
fn handle_send(args: &SyscallArgs, blocking: bool, call: bool) -> KResult<()> {
    use crate::cap::Cap;
    use crate::cspace::lookup_cap;
    use crate::endpoint::{send_ipc, SendOptions};
    use crate::kernel::KERNEL;

    unsafe {
        let s = KERNEL.get();
        let current = s.scheduler.current().ok_or_else(|| {
            KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            ))
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
                let buf = (crate::arch::x86_64::paging::phys_to_lin(buf_paddr)
                    as *const u64).wrapping_add(1);
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
                let buf = crate::arch::x86_64::paging::phys_to_lin(buf_paddr)
                    as *const u64;
                let mut staged: [crate::cap::Cap; 3] =
                    [crate::cap::Cap::Null; 3];
                let mut count = 0u8;
                let n = n_caps.min(staged.len());
                for i in 0..n {
                    let cptr = core::ptr::read_volatile(
                        buf.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET + i));
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

        let (ep_ptr, badge) = match target {
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
                (ptr, badge.0)
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
                    inv_tcb.user_context.r8  = inv_tcb.msg_regs[1];
                    inv_tcb.user_context.r9  = inv_tcb.msg_regs[2];
                    inv_tcb.user_context.r15 = inv_tcb.msg_regs[3];
                    // libsel4's seL4_GetMR(i) reads from the IPC
                    // buffer (not registers), so also stage there.
                    // Buffer layout: word 0 = tag, words 1..N = msg.
                    let ipc_paddr = inv_tcb.ipc_buffer_paddr;
                    if ipc_paddr != 0 {
                        let buf = (crate::arch::x86_64::paging::phys_to_lin(
                            ipc_paddr) as *mut u64).wrapping_add(1);
                        let n = (length as usize).min(inv_tcb.msg_regs.len());
                        for i in 0..n {
                            core::ptr::write_volatile(
                                buf.add(i), inv_tcb.msg_regs[i]);
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
        let opts = SendOptions { blocking, do_call: call, badge };
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
    use crate::endpoint::{receive_ipc, RecvOptions};
    use crate::kernel::KERNEL;

    unsafe {
        let s = KERNEL.get();
        let current = s.scheduler.current().ok_or_else(|| {
            KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            ))
        })?;
        let cspace_root = s.scheduler.slab.get(current).cspace_root;
        let target = lookup_cap(s, &cspace_root, args.a0)?;
        // Phase 36d — if the receiver passed a Reply cap cptr in
        // `args.a2`, register the Reply object so any incoming
        // Call binds it to the caller. This is how seL4 MCS
        // models `seL4_Recv(ep, &sender, replyCap)`. cptr 0 means
        // "no reply" — we fall back to the legacy Tcb.reply_to
        // path that handle_reply / SysReplyRecv still consult.
        if args.a2 != 0 {
            if let Ok(Cap::Reply { ptr, .. }) =
                lookup_cap(s, &cspace_root, args.a2)
            {
                let reply_idx =
                    crate::kernel::KernelState::reply_index(ptr) as u16;
                s.scheduler.slab.get_mut(current).pending_reply =
                    Some(reply_idx);
            }
        }
        let ep_ptr = match target {
            Cap::Endpoint { ptr, rights, .. } => {
                if !rights.can_receive {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                }
                ptr
            }
            // Phase 18a: Recv on a Notification cap is wait().
            Cap::Notification { ptr, rights, .. } => {
                if !rights.can_receive {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                }
                let idx = crate::kernel::KernelState::ntfn_index(ptr);
                let s_ptr: *mut crate::kernel::KernelState = s;
                let ntfn = &mut (*s_ptr).notifications[idx];
                let sched = &mut (*s_ptr).scheduler;
                let _outcome = crate::notification::wait(ntfn, sched, current);
                return Ok(());
            }
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )));
            }
        };
        // Bound-notification pre-check
        if let Some(bn_idx) = s.scheduler.slab.get(current).bound_notification {
            let s_ptr: *mut crate::kernel::KernelState = s;
            let ntfn = &mut (*s_ptr).notifications[bn_idx as usize];
            if matches!(ntfn.state, crate::notification::NtfnState::Active) {
                let badge = ntfn.pending_badge;
                ntfn.pending_badge = 0;
                ntfn.state = crate::notification::NtfnState::Idle;
                let tcb = s.scheduler.slab.get_mut(current);
                tcb.ipc_badge = badge;
                #[cfg(target_arch = "x86_64")]
                {
                    tcb.user_context.rdi = badge;
                    tcb.user_context.rsi = 0;
                }
                return Ok(());
            }
        }
        let idx = crate::kernel::KernelState::endpoint_index(ep_ptr);
        let opts = RecvOptions { blocking };
        let s_ptr: *mut crate::kernel::KernelState = s;
        let ep = &mut (*s_ptr).endpoints[idx];
        let sched = &mut (*s_ptr).scheduler;
        receive_ipc(ep, sched, current, opts);
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
        fn new() -> Self { Self { buf: [0; 64], len: 0 } }
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
        debug_dump_scheduler_writes_placeholder();
        sys_send_through_cspace_to_endpoint();
        sys_call_then_reply_round_trip();
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
        arch::log("  ✓ SysYield is a successful no-op\n");
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
        use crate::types::seL4_Word as Word;

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
            a0: 1,            // CPtr to slot 1
            a1: 0,            // empty MessageInfo
            a2: 0xAA,         // first message reg
            ..Default::default()
        };
        let r = handle_syscall(Syscall::SysSend, &args, &mut sink);
        // Blocking send to an idle endpoint with no waiter parks
        // the sender; the syscall surfaces success.
        assert!(r.is_ok(), "SysSend should not fault");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(boot_tcb).state,
                ThreadStateType::BlockedOnSend);
            assert_eq!(s.endpoints[0].state, crate::endpoint::EpState::Send);
            // Restore the boot thread for downstream specs.
            crate::endpoint::cancel_ipc(
                &mut s.endpoints[0],
                &mut s.scheduler,
                boot_tcb,
            );
            s.scheduler.slab.get_mut(boot_tcb).state =
                ThreadStateType::Running;
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
                    can_send: true, can_receive: true,
                    can_grant: false, can_grant_reply: true,
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
        unsafe { KERNEL.get().scheduler.set_current(Some(server)); }
        let r = handle_syscall(Syscall::SysRecv,
            &SyscallArgs { a0: 1, ..Default::default() }, &mut sink);
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(server).state,
                ThreadStateType::BlockedOnReceive);
            assert_eq!(s.endpoints[ep_idx].state, EpState::Recv);
        }

        // Caller does SysCall (a Send + auto-block-on-Reply).
        // Sender stages 'X' as msg_regs[0], length=1.
        unsafe { KERNEL.get().scheduler.set_current(Some(caller)); }
        let r = handle_syscall(Syscall::SysCall,
            &SyscallArgs { a0: 1, a1: 1, a2: b'X' as Word, ..Default::default() },
            &mut sink);
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            // Caller is parked on Reply; server is runnable with
            // the message + caller in its reply_to slot.
            assert_eq!(s.scheduler.slab.get(caller).state,
                ThreadStateType::BlockedOnReply);
            assert_eq!(s.scheduler.slab.get(server).reply_to, Some(caller));
            assert_eq!(s.scheduler.slab.get(server).msg_regs[0], b'X' as Word);
        }

        // Server replies with 'Y'. Phase 36b — `SysReply` is no
        // longer a userspace syscall under MCS; the kernel-side
        // `handle_reply` is still the function that performs the
        // transfer, callable directly.
        unsafe { KERNEL.get().scheduler.set_current(Some(server)); }
        let r = handle_reply(
            &SyscallArgs { a1: 1, a2: b'Y' as Word, ..Default::default() });
        let _ = &mut sink; // keep `sink` borrow check happy across the move
        assert!(r.is_ok());
        unsafe {
            let s = KERNEL.get();
            // Caller is back to Running with reply payload in its
            // msg_regs.
            assert_eq!(s.scheduler.slab.get(caller).state,
                ThreadStateType::Running);
            assert_eq!(s.scheduler.slab.get(caller).msg_regs[0], b'Y' as Word);
            // Server's reply_to slot consumed.
            assert_eq!(s.scheduler.slab.get(server).reply_to, None);
            // Clean up — free the temp TCBs and reset current.
            s.scheduler.slab.free(caller);
            s.scheduler.slab.free(server);
            // Restore boot thread (id 0 — first admitted) as
            // current.
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ SysCall → Recv → Reply round-trip\n");
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
