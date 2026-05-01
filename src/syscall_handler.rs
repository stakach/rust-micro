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
        Syscall::SysReply => handle_reply(args),
        Syscall::SysReplyRecv => {
            handle_reply(args)?;
            handle_recv(args, /* blocking */ true)
        }
        Syscall::SysYield => Ok(()),
        Syscall::SysDebugPutChar | Syscall::SysDebugDumpScheduler => {
            let n = syscall as i32 as i64;
            handle_unknown_syscall(n, args, sink)
        }
    }
}

/// SysReply: take the current thread's `reply_to` slot, transfer
/// the in-flight message back to the original caller, and unblock
/// them. Mirrors `seL4/src/object/reply.c::doReplyTransfer` for
/// the non-MCS path.
fn handle_reply(args: &SyscallArgs) -> KResult<()> {
    use crate::kernel::KERNEL;
    use crate::tcb::ThreadStateType;
    use crate::types::seL4_Word as Word;

    unsafe {
        let s = KERNEL.get();
        let current = s.scheduler.current.ok_or_else(|| {
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
        let current = s.scheduler.current.ok_or_else(|| {
            KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            ))
        })?;
        let cspace_root = s.scheduler.slab.get(current).cspace_root;
        let target = lookup_cap(s, &cspace_root, args.a0)?;
        let (ep_ptr, badge) = match target {
            Cap::Endpoint { ptr, badge, rights } => {
                if !rights.can_send {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                }
                (ptr, badge.0)
            }
            // Phase 16: non-Endpoint cap on a Send/Call → invocation
            // dispatch (Untyped::Retype, CNode::Copy/Move/...,
            // TCB::Suspend/Resume/SetPriority, etc.).
            other => {
                return crate::invocation::decode_invocation(other, args, current);
            }
        };
        // Stage the message on the sender TCB so endpoint::send_ipc
        // can copy it to the receiver. seL4_MessageInfo decode lives
        // in types::seL4_MessageInfo_t — we keep it minimal here.
        let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
        {
            let snd = s.scheduler.slab.get_mut(current);
            snd.ipc_label = info.label();
            snd.ipc_length = info.length() as u32;
            snd.ipc_badge = badge;
            snd.msg_regs[0] = args.a2;
            snd.msg_regs[1] = args.a3;
            snd.msg_regs[2] = args.a4;
            snd.msg_regs[3] = args.a5;
        }
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
        let current = s.scheduler.current.ok_or_else(|| {
            KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            ))
        })?;
        let cspace_root = s.scheduler.slab.get(current).cspace_root;
        let target = lookup_cap(s, &cspace_root, args.a0)?;
        let ep_ptr = match target {
            Cap::Endpoint { ptr, rights, .. } => {
                if !rights.can_receive {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                }
                ptr
            }
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )));
            }
        };
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
            Syscall::SysReply,
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
            let current = s.scheduler.current.expect("boot thread");

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
        let boot_tcb = unsafe { KERNEL.get().scheduler.current.unwrap() };

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
            s.scheduler.current = Some(boot_tcb);
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
        unsafe { KERNEL.get().scheduler.current = Some(server); }
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
        unsafe { KERNEL.get().scheduler.current = Some(caller); }
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

        // Server replies with 'Y'.
        unsafe { KERNEL.get().scheduler.current = Some(server); }
        let r = handle_syscall(Syscall::SysReply,
            &SyscallArgs { a1: 1, a2: b'Y' as Word, ..Default::default() },
            &mut sink);
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
            s.scheduler.current = Some(crate::tcb::TcbId(0));
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
