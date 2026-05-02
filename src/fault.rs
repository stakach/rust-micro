//! Phase 22 — fault delivery via the fault endpoint.
//!
//! When a user thread faults, the kernel sends a fault message to
//! the thread's fault handler (the endpoint cap stored in
//! `Tcb::fault_handler`). The faulter blocks `BlockedOnReply`; the
//! handler's `reply_to` is stamped with the faulter so a
//! `SysReply` resumes them. This mirrors `seL4/src/api/faults.c::
//! handleFault`.

use crate::cap::{Cap, EndpointObj, PPtr};
use crate::cspace::lookup_cap;
use crate::endpoint::{send_ipc, SendOptions};
use crate::error::{KException, KResult, SyscallError};
use crate::kernel::{KernelState, KERNEL};
use crate::tcb::TcbId;
use crate::types::{seL4_Error, seL4_Word as Word};

/// The four user-visible fault types. Discriminants match
/// `seL4_FaultType` in libsel4.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FaultMessage {
    Null,
    CapFault { addr: Word, in_recv: bool },
    UnknownSyscall { number: Word },
    UserException { number: u32, code: u32 },
    VMFault { addr: Word, fsr: Word, instruction: bool },
}

impl FaultMessage {
    /// `seL4_FaultType` discriminant — goes in `msg_regs[0]` so
    /// userspace fault handlers can dispatch on it.
    pub const fn type_word(&self) -> Word {
        match self {
            FaultMessage::Null => 0,
            FaultMessage::CapFault { .. } => 1,
            FaultMessage::UnknownSyscall { .. } => 2,
            FaultMessage::UserException { .. } => 3,
            FaultMessage::VMFault { .. } => 5,
        }
    }

    /// Pack the fault into 4 `msg_regs[0..4]` words. Layout:
    ///   regs[0] = fault type
    ///   regs[1..] = type-specific
    pub fn encode(&self, regs: &mut [Word]) -> usize {
        regs[0] = self.type_word();
        match *self {
            FaultMessage::Null => 1,
            FaultMessage::CapFault { addr, in_recv } => {
                regs[1] = addr;
                regs[2] = in_recv as Word;
                3
            }
            FaultMessage::UnknownSyscall { number } => {
                regs[1] = number;
                2
            }
            FaultMessage::UserException { number, code } => {
                regs[1] = number as Word;
                regs[2] = code as Word;
                3
            }
            FaultMessage::VMFault { addr, fsr, instruction } => {
                regs[1] = addr;
                regs[2] = fsr;
                regs[3] = instruction as Word;
                4
            }
        }
    }
}

/// Deliver `fault` to the handler endpoint named by
/// `faulter.fault_handler`. Returns `Ok(())` if delivery
/// succeeded (faulter is now blocked, handler will be woken with
/// the message); returns an error if there's no handler or the
/// cap isn't a usable Endpoint.
pub fn deliver_fault(faulter: TcbId, fault: FaultMessage) -> KResult<()> {
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(faulter).cspace_root;
        let cptr = s.scheduler.slab.get(faulter).fault_handler;
        if cptr == 0 {
            // No handler. Return the fault so the caller can
            // decide what to do (kernel typically suspends).
            return Err(KException::Fault(crate::error::FaultKind::CapFault));
        }
        let target = lookup_cap(s, &cspace_root, cptr)?;
        let (ep_ptr, badge) = match target {
            Cap::Endpoint { ptr, badge, rights } => {
                if !rights.can_send {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability)));
                }
                (ptr, badge.0)
            }
            _ => return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability))),
        };
        // Stage the fault as a Call-shaped message: handler runs,
        // does SysReply to resume the faulter.
        let regs_n = {
            let f = s.scheduler.slab.get_mut(faulter);
            let n = fault.encode(&mut f.msg_regs);
            f.ipc_label = fault.type_word();
            f.ipc_length = n as u32;
            n
        };
        let _ = regs_n;
        let idx = KernelState::endpoint_index(ep_ptr);
        let s_ptr: *mut KernelState = s;
        let ep = &mut (*s_ptr).endpoints[idx];
        let sched = &mut (*s_ptr).scheduler;
        send_ipc(ep, sched, faulter, SendOptions {
            blocking: true,
            do_call: true,
            badge,
        });
        Ok(())
    }
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::cap::{Badge, EndpointRights, FrameRights};
    use crate::cte::Cte;
    use crate::endpoint::Endpoint;
    use crate::tcb::{Tcb, ThreadStateType};

    pub fn test_fault() {
        arch::log("Running fault delivery tests...\n");
        fault_to_handler_round_trip();
        no_handler_returns_fault();
        // Restore the boot thread as current so downstream specs
        // (and the boot continuation in main.rs) keep working.
        unsafe {
            let s = KERNEL.get();
            // Find the lowest occupied slot — that's the boot
            // thread (admitted by `bootstrap_boot_thread`).
            let boot = s.scheduler.slab.entries.iter()
                .position(|e| e.is_some())
                .map(|i| TcbId(i as u16))
                .expect("boot thread must still be live");
            s.scheduler.set_current(Some(boot));
        }
        arch::log("Fault delivery tests completed\n");
    }

    /// Reset scheduler queues so a fresh fault test isn't poisoned
    /// by dangling sched_next/sched_prev links from earlier specs.
    fn reset_scheduler_queues() {
        unsafe {
            let s = KERNEL.get();
            // Wipe the priority bitmap + per-priority head/tail
            // pointers. The TCBs themselves stay in the slab —
            // each fresh `admit` re-enqueues them cleanly.
            s.scheduler.reset_queues();
            s.scheduler.set_current(None);
        }
    }

    fn make_tcb(prio: u8) -> TcbId {
        unsafe {
            let mut t = Tcb::default();
            t.priority = prio;
            t.state = ThreadStateType::Running;
            KERNEL.get().scheduler.admit(t)
        }
    }

    #[inline(never)]
    fn fault_to_handler_round_trip() {
        reset_scheduler_queues();
        // Build: handler thread + faulter thread sharing CNode 0,
        // an endpoint at slot 7.
        unsafe {
            for slot in KERNEL.get().cnodes[0].0.iter_mut() {
                slot.set_cap(&Cap::Null);
            }
            KERNEL.get().endpoints[7] = Endpoint::new();
        }
        let handler = make_tcb(80);
        let faulter = make_tcb(50);

        let cnode_cap = Cap::CNode {
            ptr: KernelState::cnode_ptr(0),
            radix: 5, guard_size: 59, guard: 0,
        };
        let ep_cap = Cap::Endpoint {
            ptr: KernelState::endpoint_ptr(7),
            badge: Badge(0xF1),
            rights: EndpointRights {
                can_send: true, can_receive: true,
                can_grant: false, can_grant_reply: true,
            },
        };
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[7] = Cte::with_cap(&ep_cap);
            // Faulter routes faults to slot 7.
            s.scheduler.slab.get_mut(faulter).cspace_root = cnode_cap;
            s.scheduler.slab.get_mut(faulter).fault_handler = 7;
            // Handler also has the endpoint visible at slot 7 so
            // it can SysRecv on it.
            s.scheduler.slab.get_mut(handler).cspace_root = cnode_cap;
            // Handler waits on the endpoint first.
            s.scheduler.set_current(Some(handler));
        }
        let r = crate::syscall_handler::handle_syscall(
            crate::syscalls::Syscall::SysRecv,
            &crate::syscall_handler::SyscallArgs { a0: 7, ..Default::default() },
            &mut SinkVoid,
        );
        assert!(r.is_ok());

        // Now fault the faulter.
        unsafe { KERNEL.get().scheduler.set_current(Some(faulter)); }
        deliver_fault(faulter, FaultMessage::VMFault {
            addr: 0xDEAD_BEEF,
            fsr: 0x4,
            instruction: false,
        }).expect("fault delivery ok");

        unsafe {
            let s = KERNEL.get();
            // Faulter is parked on Reply; handler is runnable
            // with the fault message in msg_regs.
            assert_eq!(s.scheduler.slab.get(faulter).state,
                ThreadStateType::BlockedOnReply);
            assert_eq!(s.scheduler.slab.get(handler).reply_to, Some(faulter));
            assert_eq!(s.scheduler.slab.get(handler).msg_regs[0], 5); // VMFault
            assert_eq!(s.scheduler.slab.get(handler).msg_regs[1], 0xDEAD_BEEF);
            assert_eq!(s.scheduler.slab.get(handler).msg_regs[2], 0x4);
        }

        // Handler does SysReply to resume the faulter. Phase 36b —
        // SysReply isn't a syscall under MCS, so we call the
        // handler directly.
        unsafe { KERNEL.get().scheduler.set_current(Some(handler)); }
        let r = crate::syscall_handler::handle_reply(
            &crate::syscall_handler::SyscallArgs::default());
        assert!(r.is_ok());

        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(faulter).state,
                ThreadStateType::Running);
            // Cleanup.
            s.scheduler.slab.free(handler);
            s.scheduler.slab.free(faulter);
            s.scheduler.set_current(Some(crate::tcb::TcbId(0)));
        }
        arch::log("  ✓ fault → handler → SysReply → faulter resumes\n");
    }

    #[inline(never)]
    fn no_handler_returns_fault() {
        reset_scheduler_queues();
        let faulter = make_tcb(50);
        // No fault_handler set (default 0).
        let r = deliver_fault(faulter, FaultMessage::UnknownSyscall { number: 99 });
        match r {
            Err(KException::Fault(_)) => {}
            other => panic!("expected Fault, got {:?}", other),
        }
        arch::log("  ✓ deliver_fault with no handler returns Err(Fault)\n");
    }

    struct SinkVoid;
    impl crate::syscall_handler::DebugSink for SinkVoid {
        fn put_byte(&mut self, _: u8) {}
    }

    // Suppress unused if FrameRights isn't referenced.
    #[allow(dead_code)]
    const _USED: FrameRights = FrameRights::ReadWrite;
}
