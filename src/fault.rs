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

fn log_dec_u64(mut v: u64) {
    let mut buf = [b'0'; 20];
    let mut i = buf.len();
    if v == 0 {
        crate::arch::log("0");
        return;
    }
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

fn log_hex64(v: u64) {
    let mut buf = [b'0'; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        let n = ((v >> shift) & 0xF) as u8;
        buf[i] = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        crate::arch::log(s);
    }
}

fn cap_name(cap: &Cap) -> &'static str {
    match cap {
        Cap::Null => "null",
        Cap::Untyped { .. } => "untyped",
        Cap::Endpoint { .. } => "endpoint",
        Cap::Notification { .. } => "notification",
        Cap::Reply { .. } => "reply",
        Cap::CNode { .. } => "cnode",
        Cap::Thread { .. } => "thread",
        Cap::IrqControl => "irq-control",
        Cap::IrqHandler { .. } => "irq-handler",
        Cap::Zombie { .. } => "zombie",
        Cap::Domain => "domain",
        Cap::Frame { .. } => "frame",
        Cap::PageTable { .. } => "page-table",
        Cap::PageDirectory { .. } => "page-directory",
        Cap::Pdpt { .. } => "pdpt",
        Cap::PML4 { .. } => "pml4",
        Cap::AsidControl => "asid-control",
        Cap::AsidPool { .. } => "asid-pool",
        Cap::IOPort { .. } => "io-port",
        Cap::IOPortControl => "io-port-control",
        Cap::IoSpace { .. } => "io-space",
        Cap::IoPageTable { .. } => "io-page-table",
        Cap::SchedContext { .. } => "sched-context",
        Cap::SchedControl { .. } => "sched-control",
        Cap::Arch { .. } => "arch",
    }
}

/// Print the fault-handler state for diagnostics when a user fault cannot be delivered.
pub fn log_fault_handler_state(faulter: TcbId) {
    unsafe {
        let s = KERNEL.get();
        let t = s.scheduler.slab.get(faulter);
        crate::arch::log("[fault-delivery] tcb=");
        log_dec_u64(faulter.0 as u64);
        crate::arch::log(" fault_cptr=0x");
        log_hex64(t.fault_handler);
        crate::arch::log(" stored=");
        crate::arch::log(cap_name(&t.fault_handler_cap));
        if let Cap::Endpoint { ptr, badge, rights } = t.fault_handler_cap {
            crate::arch::log(" ep=");
            log_dec_u64(KernelState::endpoint_index(ptr) as u64);
            crate::arch::log(" badge=0x");
            log_hex64(badge.0);
            crate::arch::log(" rights=");
            crate::arch::log(if rights.can_send { "S" } else { "-" });
            crate::arch::log(if rights.can_receive { "R" } else { "-" });
            crate::arch::log(if rights.can_grant { "G" } else { "-" });
            crate::arch::log(if rights.can_grant_reply { "P" } else { "-" });
        }
        let root = t.cspace_root;
        crate::arch::log(" cspace=");
        crate::arch::log(cap_name(&root));
        if t.fault_handler != 0 {
            match lookup_cap(s, &root, t.fault_handler) {
                Ok(cap) => {
                    crate::arch::log(" lookup=");
                    crate::arch::log(cap_name(&cap));
                    if let Cap::Endpoint { ptr, badge, rights } = cap {
                        crate::arch::log(" ep=");
                        log_dec_u64(KernelState::endpoint_index(ptr) as u64);
                        crate::arch::log(" badge=0x");
                        log_hex64(badge.0);
                        crate::arch::log(" rights=");
                        crate::arch::log(if rights.can_send { "S" } else { "-" });
                        crate::arch::log(if rights.can_receive { "R" } else { "-" });
                        crate::arch::log(if rights.can_grant { "G" } else { "-" });
                        crate::arch::log(if rights.can_grant_reply { "P" } else { "-" });
                    }
                }
                Err(_) => crate::arch::log(" lookup=err"),
            }
        }
        crate::arch::log(" pending_fault=");
        log_dec_u64(t.pending_fault as u64);
        crate::arch::log("\n");
    }
}

/// The four user-visible fault types. Discriminants match
/// `seL4_FaultType` in libsel4.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FaultMessage {
    Null,
    CapFault {
        addr: Word,
        in_recv: bool,
    },
    UnknownSyscall {
        number: Word,
    },
    UserException {
        number: u32,
        code: u32,
    },
    VMFault {
        addr: Word,
        fsr: Word,
        instruction: bool,
    },
    /// MCS timeout fault — raised when a thread with a timeout-fault
    /// endpoint exhausts its scheduling-context budget. `data` is the
    /// SC's badge (`seL4_Timeout_Data`); `consumed` is ticks consumed
    /// (`seL4_Timeout_Consumed`). Length 2.
    Timeout {
        data: u64,
        consumed: u64,
    },
    /// Hardware debug exception (CONFIG_HARDWARE_DEBUG_API). `reason`:
    /// 0 = Data / 1 = Instruction (a HW breakpoint hit), 2 = SingleStep,
    /// 3 = SoftwareBreakRequest (INT3). HW-breakpoint faults also carry
    /// `trigger_addr` + `bp_num` (MR length 4); single-step / INT3 carry
    /// only `fault_ip` + `reason` (length 2).
    DebugException {
        fault_ip: u64,
        reason: u64,
        trigger_addr: u64,
        bp_num: u64,
    },
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
            // Phase 43 — was 5; upstream's seL4_Fault_VMFault is 6
            // (slot 5 is Timeout). FRAMEDIPC0003's helper checks
            // `info.label == seL4_Fault_VMFault` and returns -1 if
            // mismatch, surfacing as the test's
            // `(uintptr_t)res(18446744073709551615) == dest` failure.
            FaultMessage::VMFault { .. } => 6,
            FaultMessage::Timeout { .. } => 5,
            FaultMessage::DebugException { .. } => 4,
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
            FaultMessage::VMFault {
                addr,
                fsr,
                instruction,
            } => {
                regs[1] = addr;
                regs[2] = fsr;
                regs[3] = instruction as Word;
                4
            }
            FaultMessage::Timeout { data, consumed } => {
                regs[1] = data;
                regs[2] = consumed;
                3
            }
            FaultMessage::DebugException {
                fault_ip,
                reason,
                trigger_addr,
                bp_num,
            } => {
                regs[1] = fault_ip;
                regs[2] = reason;
                regs[3] = trigger_addr;
                regs[4] = bp_num;
                5
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
        // MCS path: TCB_SetSpace resolved the fault EP cap in the
        // SETTER's cspace and stored it on the TCB — required for
        // inter-AS fault handling, where the cptr below would name
        // nothing (or the wrong thing) in the faulter's own cspace.
        let stored = s.scheduler.slab.get(faulter).fault_handler_cap;
        let target = if matches!(stored, Cap::Endpoint { .. }) {
            stored
        } else {
            let cspace_root = s.scheduler.slab.get(faulter).cspace_root;
            let cptr = s.scheduler.slab.get(faulter).fault_handler;
            if cptr == 0 {
                // No handler. Return the fault so the caller can
                // decide what to do (kernel typically suspends).
                return Err(KException::Fault(crate::error::FaultKind::CapFault));
            }
            lookup_cap(s, &cspace_root, cptr)?
        };
        let (ep_ptr, badge) = match target {
            Cap::Endpoint { ptr, badge, rights } => {
                if !rights.can_send {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                }
                (ptr, badge.0)
            }
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )))
            }
        };
        // Stage the fault as a Call-shaped message: handler runs,
        // does SysReply to resume the faulter. Layout of msg_regs
        // matches upstream's per-arch fault enum (e.g.
        // `seL4_UserException_Msg` on x86_64 = FaultIP, SP, FLAGS,
        // Number, Code → length 5). sel4utils_print_fault_message
        // asserts on the length, so the wire format has to be
        // accurate even if the test only inspects the label.
        let regs_n = {
            let f = s.scheduler.slab.get_mut(faulter);
            let n = encode_for_arch(&fault, f);
            f.ipc_label = fault.type_word();
            f.ipc_length = n as u32;
            // Remember the in-flight fault type: the reply path
            // dispatches on it (per-type register writeback +
            // restart-vs-Inactive) instead of doing a normal IPC
            // message fan-out into the faulter's registers.
            f.pending_fault = fault.type_word() as u8;
            n
        };
        let _ = regs_n;
        let idx = KernelState::endpoint_index(ep_ptr);
        let s_ptr: *mut KernelState = s;
        let ep = &mut (*s_ptr).endpoints[idx];
        let sched = &mut (*s_ptr).scheduler;
        send_ipc(
            ep,
            sched,
            faulter,
            SendOptions {
                blocking: true,
                do_call: true,
                badge,
                // Fault delivery acts as a Call from the faulter to its
                // fault handler — grant rights so the handler can install
                // a reply cap and send caps back if it wants to.
                can_grant: true,
                // do_call path handles donation via finish_call; this is
                // moot but matches the Call canDonate=true convention.
                can_donate: true,
            },
        );
        Ok(())
    }
}

/// Deliver an MCS timeout fault to `faulter`'s timeout-fault endpoint
/// (set via TCB_SetTimeoutEndpoint). Returns `true` if a fault was
/// delivered — i.e. the thread has a valid, sendable timeout EP and no
/// in-flight fault. Mirrors upstream `handleTimeout`/`validTimeoutHandler`.
/// The `seL4_Timeout_Data` MR carries the SC's badge so the handler can
/// identify the overrunning thread.
pub fn deliver_timeout_fault(faulter: TcbId) -> bool {
    unsafe {
        let s = KERNEL.get();
        // Only one fault in flight at a time.
        if s.scheduler.slab.get(faulter).pending_fault != 0 {
            return false;
        }
        let target = s.scheduler.slab.get(faulter).timeout_endpoint_cap;
        let (ep_ptr, badge) = match target {
            Cap::Endpoint { ptr, badge, rights } if rights.can_send => (ptr, badge.0),
            _ => return false,
        };
        // seL4_Timeout_Data = the SC's badge; Consumed = ticks used.
        let (data, consumed) = match s.scheduler.slab.get(faulter).sc {
            Some(sc_idx) => {
                let sc = &mut s.sched_contexts[sc_idx as usize];
                let report = (sc.badge, sc.consumed);
                // Upstream timeout delivery performs the same consumed
                // report reset as SchedContext_Consumed. Durable runtime
                // counters remain monotonic.
                sc.consumed = 0;
                report
            }
            None => (0, 0),
        };
        let fault = FaultMessage::Timeout { data, consumed };
        {
            let f = s.scheduler.slab.get_mut(faulter);
            let n = encode_for_arch(&fault, f);
            f.ipc_label = fault.type_word();
            f.ipc_length = n as u32;
            f.pending_fault = fault.type_word() as u8;
        }
        let idx = KernelState::endpoint_index(ep_ptr);
        let s_ptr: *mut KernelState = s;
        let ep = &mut (*s_ptr).endpoints[idx];
        let sched = &mut (*s_ptr).scheduler;
        send_ipc(
            ep,
            sched,
            faulter,
            SendOptions {
                blocking: true,
                do_call: true,
                badge,
                can_grant: true,
                can_donate: true,
            },
        );
        true
    }
}

/// Where this thread will resume execution. Threads captured by an
/// exception-style entry (#PF, #UD, #NM, IRQ preemption) carry their
/// RIP/RFLAGS in the dedicated iretq slots and TRUE rcx/r11 in the
/// GPR slots; syscall-entry threads use the sysret convention
/// (rcx = RIP, r11 = RFLAGS).
#[cfg(target_arch = "x86_64")]
pub fn resume_ip(f: &crate::tcb::Tcb) -> Word {
    if f.use_iretq_resume {
        f.user_context.rip
    } else {
        f.user_context.rcx
    }
}

#[cfg(target_arch = "aarch64")]
pub fn resume_ip(f: &crate::tcb::Tcb) -> Word {
    // seL4/src/arch/arm/machine/hardware.c::getRestartPC.
    f.user_context.fault_ip
}

/// IP to REPORT from TCB_ReadRegisters (the "fault IP"). For a thread
/// blocked in an IPC syscall, the saved IP is the SYSCALL *return*
/// address; report the syscall instruction itself (2 bytes earlier on
/// x86_64) so userspace `restart_after_syscall` — which adds
/// `ARCH_SYSCALL_INSTRUCTION_SIZE` and writes it back — lands exactly
/// on the return address (SCHED_CONTEXT_0009/0010). Exception-captured
/// threads (`use_iretq_resume`) already hold the faulting instruction.
#[cfg(target_arch = "x86_64")]
pub fn reported_ip(f: &crate::tcb::Tcb) -> Word {
    use crate::tcb::ThreadStateType::*;
    let ip = resume_ip(f);
    if !f.use_iretq_resume
        && matches!(
            f.state,
            BlockedOnReceive | BlockedOnSend | BlockedOnReply | BlockedOnNotification
        )
    {
        ip.wrapping_sub(2)
    } else {
        ip
    }
}

#[cfg(target_arch = "aarch64")]
pub fn reported_ip(f: &crate::tcb::Tcb) -> Word {
    f.user_context.fault_ip
}

#[cfg(target_arch = "x86_64")]
pub fn resume_flags(f: &crate::tcb::Tcb) -> Word {
    if f.use_iretq_resume {
        f.user_context.rflags
    } else {
        f.user_context.r11
    }
}

#[cfg(target_arch = "aarch64")]
pub fn resume_flags(f: &crate::tcb::Tcb) -> Word {
    f.user_context.spsr_el1
}

/// Set the address this thread resumes at, honoring its capture
/// flavor (see `resume_ip`). For sysret-flavor threads both rcx and
/// the .rip slot are written so a later flavor switch stays sane.
#[cfg(target_arch = "x86_64")]
pub fn set_resume_ip(f: &mut crate::tcb::Tcb, ip: Word) {
    f.user_context.rip = ip;
    if !f.use_iretq_resume {
        f.user_context.rcx = ip;
    }
}

#[cfg(target_arch = "aarch64")]
pub fn set_resume_ip(f: &mut crate::tcb::Tcb, ip: Word) {
    f.user_context.fault_ip = ip;
    f.user_context.elr_el1 = ip;
}

#[cfg(target_arch = "x86_64")]
pub fn set_resume_flags(f: &mut crate::tcb::Tcb, flags: Word) {
    f.user_context.rflags = flags;
    if !f.use_iretq_resume {
        f.user_context.r11 = flags;
    }
}

#[cfg(target_arch = "aarch64")]
pub fn set_resume_flags(f: &mut crate::tcb::Tcb, flags: Word) {
    // seL4 include/arch/arm/arch/64/mode/kernel/thread.h:
    // preserve NZCV and force an EL0t user PSTATE with FIQ masked.
    f.user_context.spsr_el1 = (flags & 0xf000_0000) | (1 << 6);
}

/// Apply a fault reply to `caller` (a thread blocked on an
/// in-flight fault — `pending_fault != 0`). Mirrors upstream
/// `handleFaultReply`: per-fault-type register writeback from the
/// reply MRs, then returns whether the faulter should restart
/// (true → make runnable; false → leave Inactive). The normal IPC
/// reply fan-out (msg_regs → rsi/rdi/r10/r8/r9/r15) must NOT run
/// for faulters — they didn't block in a syscall, so it would
/// corrupt live registers.
///
/// Restart rules (upstream `handleFaultReply` +
/// `Arch_handleFaultReply`):
///   * CapFault / VMFault → restart unconditionally (the fault
///     tests' VMFault arm only replies when it wants a restart).
///   * UnknownSyscall / UserException → restart iff label == 0;
///     reply MRs are copied back into the faulter's registers
///     (FLAGS sanitized like `Arch_sanitiseRegister`).
#[cfg(target_arch = "x86_64")]
pub unsafe fn apply_fault_reply(
    s: &mut KernelState,
    caller: TcbId,
    label: Word,
    length: usize,
    regs: &[Word],
) -> bool {
    let fault_type = s.scheduler.slab.get(caller).pending_fault;
    let t = s.scheduler.slab.get_mut(caller);
    t.pending_fault = 0;
    match fault_type {
        2 => {
            // UnknownSyscall — slots: 0 RAX, 1 RBX, 2 RCX, 3 RDX,
            // 4 RSI, 5 RDI, 6 RBP, 7..14 R8..R15, 15 FaultIP,
            // 16 SP, 17 FLAGS, 18 Syscall (ignored on reply).
            // RCX (2) / R11 (10) are skipped: the faulter entered
            // via SYSCALL, which destroyed them — sysret resume
            // rebuilds them from RIP/FLAGS.
            let n = length.min(regs.len());
            if n > 0 {
                t.user_context.rax = regs[0];
            }
            if n > 1 {
                t.user_context.rbx = regs[1];
            }
            if n > 3 {
                t.user_context.rdx = regs[3];
            }
            if n > 4 {
                t.user_context.rsi = regs[4];
            }
            if n > 5 {
                t.user_context.rdi = regs[5];
            }
            if n > 6 {
                t.user_context.rbp = regs[6];
            }
            if n > 7 {
                t.user_context.r8 = regs[7];
            }
            if n > 8 {
                t.user_context.r9 = regs[8];
            }
            if n > 9 {
                t.user_context.r10 = regs[9];
            }
            if n > 11 {
                t.user_context.r12 = regs[11];
            }
            if n > 12 {
                t.user_context.r13 = regs[12];
            }
            if n > 13 {
                t.user_context.r14 = regs[13];
            }
            if n > 14 {
                t.user_context.r15 = regs[14];
            }
            if n > 15 {
                set_resume_ip(t, regs[15]);
            }
            if n > 16 {
                t.user_context.rsp = regs[16];
            }
            if n > 17 {
                set_resume_flags(t, (regs[17] & 0xDD5) | 0x202);
            }
            label == 0
        }
        3 => {
            // UserException — slots: 0 FaultIP, 1 SP, 2 FLAGS.
            let n = length.min(regs.len());
            if n > 0 {
                set_resume_ip(t, regs[0]);
            }
            if n > 1 {
                t.user_context.rsp = regs[1];
            }
            if n > 2 {
                set_resume_flags(t, (regs[2] & 0xDD5) | 0x202);
            }
            label == 0
        }
        5 => {
            // Timeout reply (seL4_TimeoutReply_new): label = !resume,
            // MRs = a full seL4_UserContext when the handler wants to
            // RESET the faulter to a checkpoint (TIMEOUTFAULT0002/0003).
            // A length-0 reply (TIMEOUTFAULT0001) just resumes in place.
            // seL4_UserContext order: 0 rip, 1 rsp, 2 rflags, 3 rax,
            // 4 rbx, 5 rcx, 6 rdx, 7 rsi, 8 rdi, 9 rbp, 10..17 r8..r15,
            // 18 fs_base, 19 gs_base. rcx(5)/r11(13) are skipped — the
            // faulter resumes via sysret which rebuilds them from
            // RIP/FLAGS.
            let n = length.min(regs.len());
            if n >= 18 {
                set_resume_ip(t, regs[0]);
                t.user_context.rsp = regs[1];
                set_resume_flags(t, (regs[2] & 0xDD5) | 0x202);
                t.user_context.rax = regs[3];
                t.user_context.rbx = regs[4];
                t.user_context.rdx = regs[6];
                t.user_context.rsi = regs[7];
                t.user_context.rdi = regs[8];
                t.user_context.rbp = regs[9];
                t.user_context.r8 = regs[10];
                t.user_context.r9 = regs[11];
                t.user_context.r10 = regs[12];
                t.user_context.r12 = regs[14];
                t.user_context.r13 = regs[15];
                t.user_context.r14 = regs[16];
                t.user_context.r15 = regs[17];
            }
            // resume = !label.
            label == 0
        }
        4 => {
            // DebugException reply. For a single-step fault the handler
            // re-arms stepping via MR0 = n_instructions (default 1);
            // for a HW breakpoint it just resumes. Mirrors seL4
            // copyMRsFaultReply -> configureSingleStepping.
            #[cfg(target_arch = "x86_64")]
            if t.debug.single_step_enabled {
                use crate::arch::x86_64::debug;
                let n = if length >= 1 { regs[0] } else { 1 };
                debug::configure_single_stepping(&mut t.debug, n);
                if n == 0 {
                    t.user_context.rflags &= !debug::FLAGS_TF;
                } else {
                    t.user_context.rflags |= debug::FLAGS_TF;
                    t.use_iretq_resume = true;
                }
            }
            true
        }
        // CapFault (1), VMFault (6), anything else: no register
        // transfer, restart unconditionally.
        _ => true,
    }
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn apply_fault_reply(
    s: &mut KernelState,
    caller: TcbId,
    label: Word,
    length: usize,
    regs: &[Word],
) -> bool {
    let fault_type = s.scheduler.slab.get(caller).pending_fault;
    let t = s.scheduler.slab.get_mut(caller);
    t.pending_fault = 0;
    let n = length.min(regs.len());
    match fault_type {
        2 => {
            // AArch64 SYSCALL_MESSAGE in the pinned seL4 registerset:
            // X0..X7, FaultIP, SP_EL0, ELR_EL1 (LR), SPSR_EL1.
            for (dst, src) in t.user_context.x[..8].iter_mut().zip(regs.iter().take(n)) {
                *dst = *src;
            }
            if n > 8 {
                t.user_context.fault_ip = regs[8];
            }
            if n > 9 {
                t.user_context.sp_el0 = regs[9];
            }
            if n > 10 {
                t.user_context.elr_el1 = regs[10];
            }
            if n > 11 {
                set_resume_flags(t, regs[11]);
            }
            label == 0
        }
        3 => {
            // AArch64 EXCEPTION_MESSAGE: FaultIP, SP_EL0, SPSR_EL1.
            if n > 0 {
                set_resume_ip(t, regs[0]);
            }
            if n > 1 {
                t.user_context.sp_el0 = regs[1];
            }
            if n > 2 {
                set_resume_flags(t, regs[2]);
            }
            label == 0
        }
        4 => {
            if t.debug.single_step_enabled {
                let n = if length >= 1 { regs[0] } else { 1 };
                crate::arch::aarch64::debug::configure_single_stepping(&mut t.debug, n);
            }
            true
        }
        5 => {
            // AArch64 TIMEOUT_REPLY_MESSAGE from the pinned seL4
            // registerset: FaultIP, SP, SPSR, x0..x8, x16..x18,
            // x29, x30, x9..x15, x19..x28. seL4 limits the copy to
            // n_timeoutMessage (34), excluding the two TLS fields in
            // the public seL4_UserContext structure.
            if n > 0 {
                set_resume_ip(t, regs[0]);
            }
            if n > 1 {
                t.user_context.sp_el0 = regs[1];
            }
            if n > 2 {
                set_resume_flags(t, regs[2]);
            }
            for public in 3..n.min(12) {
                t.user_context.x[public - 3] = regs[public];
            }
            for (public, register) in [(12, 16), (13, 17), (14, 18), (15, 29), (16, 30)] {
                if n > public {
                    t.user_context.x[register] = regs[public];
                }
            }
            for public in 17..n.min(24) {
                t.user_context.x[public - 8] = regs[public];
            }
            for public in 24..n.min(34) {
                t.user_context.x[public - 5] = regs[public];
            }
            // resume = !label.
            label == 0
        }
        _ => true,
    }
}

/// Per-arch fault payload encoder. Mirrors libsel4's
/// `seL4_*_Msg` enums so `sel4utils_print_fault_message`'s
/// length assertions pass.
#[cfg(target_arch = "x86_64")]
fn encode_for_arch(fault: &FaultMessage, f: &mut crate::tcb::Tcb) -> usize {
    let ctx = f.user_context;
    let ip = resume_ip(f);
    let flags = resume_flags(f);
    let regs = &mut f.msg_regs;
    match *fault {
        FaultMessage::Null => 0,
        FaultMessage::CapFault { addr, in_recv } => {
            // libsel4 x86_64 seL4_CapFault_Msg: IP, Addr,
            // InRecvPhase, LookupFailureType, MR4..MR7. We only
            // populate IP/Addr/InRecvPhase; pad to length 8 with
            // zeros (test code typically inspects the first 3).
            regs[0] = ip;
            regs[1] = addr;
            regs[2] = in_recv as u64;
            for r in regs.iter_mut().take(8).skip(3) {
                *r = 0;
            }
            8
        }
        FaultMessage::UnknownSyscall { number } => {
            // x86_64 seL4_UnknownSyscall_Msg: RAX, RBX, RCX, RDX,
            // RSI, RDI, RBP, R8..R15, FaultIP, SP, FLAGS, Syscall
            // → length 19. The faulter entered via SYSCALL, so its
            // true RCX/R11 were destroyed by the instruction —
            // report the RIP/RFLAGS stand-ins like upstream does.
            regs[0] = ctx.rax;
            regs[1] = ctx.rbx;
            regs[2] = ctx.rcx;
            regs[3] = ctx.rdx;
            regs[4] = ctx.rsi;
            regs[5] = ctx.rdi;
            regs[6] = ctx.rbp;
            regs[7] = ctx.r8;
            regs[8] = ctx.r9;
            regs[9] = ctx.r10;
            regs[10] = ctx.r11;
            regs[11] = ctx.r12;
            regs[12] = ctx.r13;
            regs[13] = ctx.r14;
            regs[14] = ctx.r15;
            // FaultIP points at the `syscall` instruction itself:
            // SYSCALL saved next-RIP, and the insn is 2 bytes
            // (0F 05). Mirrors upstream c_traps.c
            // `setRegister(FaultIP, getRegister(NextIP) - 2)`.
            regs[15] = ip.wrapping_sub(2);
            regs[16] = ctx.rsp; // SP
            regs[17] = flags; // FLAGS
            regs[18] = number; // Syscall
            19
        }
        FaultMessage::UserException { number, code } => {
            // x86_64 seL4_UserException_Msg: FaultIP, SP, FLAGS,
            // Number, Code → length 5.
            regs[0] = ip;
            regs[1] = ctx.rsp; // user SP
            regs[2] = flags;
            regs[3] = number as u64;
            regs[4] = code as u64;
            5
        }
        FaultMessage::VMFault {
            addr,
            fsr,
            instruction,
        } => {
            // x86_64 seL4_VMFault_Msg: IP, Addr, PrefetchFault,
            // FSR → length 4.
            regs[0] = ip;
            regs[1] = addr;
            regs[2] = instruction as u64;
            regs[3] = fsr;
            4
        }
        FaultMessage::Timeout { data, consumed } => {
            // x86_64 seL4_Timeout_Msg: Data, Consumed → length 2.
            regs[0] = data;
            regs[1] = consumed;
            2
        }
        FaultMessage::DebugException {
            fault_ip,
            reason,
            trigger_addr,
            bp_num,
        } => {
            // seL4_DebugException_Msg: FaultIP, ExceptionReason, then
            // (HW breakpoint only) TriggerAddress, BreakpointNumber.
            // Single-step (2) / software-break (3) deliver 2 MRs;
            // a HW breakpoint/watchpoint hit delivers 4.
            regs[0] = fault_ip;
            regs[1] = reason;
            if reason != 2 && reason != 3 {
                regs[2] = trigger_addr;
                regs[3] = bp_num;
                4
            } else {
                2
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn encode_for_arch(fault: &FaultMessage, f: &mut crate::tcb::Tcb) -> usize {
    let ctx = f.user_context;
    let ip = resume_ip(f);
    let regs = &mut f.msg_regs;
    match *fault {
        FaultMessage::Null => 0,
        FaultMessage::CapFault { addr, in_recv } => {
            regs[0] = ip;
            regs[1] = addr;
            regs[2] = in_recv as Word;
            for r in regs.iter_mut().take(8).skip(3) {
                *r = 0;
            }
            8
        }
        FaultMessage::UnknownSyscall { number } => {
            regs[..8].copy_from_slice(&ctx.x[..8]);
            regs[8] = ctx.fault_ip;
            regs[9] = ctx.sp_el0;
            regs[10] = ctx.elr_el1;
            regs[11] = ctx.spsr_el1;
            regs[12] = number;
            13
        }
        FaultMessage::UserException { number, code } => {
            regs[0] = ctx.fault_ip;
            regs[1] = ctx.sp_el0;
            regs[2] = ctx.spsr_el1;
            regs[3] = number as Word;
            regs[4] = code as Word;
            5
        }
        FaultMessage::VMFault {
            addr,
            fsr,
            instruction,
        } => {
            regs[0] = ip;
            regs[1] = addr;
            regs[2] = instruction as Word;
            regs[3] = fsr;
            4
        }
        FaultMessage::Timeout { data, consumed } => {
            regs[0] = data;
            regs[1] = consumed;
            2
        }
        FaultMessage::DebugException {
            fault_ip,
            reason,
            trigger_addr,
            bp_num,
        } => {
            regs[0] = fault_ip;
            regs[1] = reason;
            if reason != 2 && reason != 3 {
                regs[2] = trigger_addr;
                regs[3] = bp_num;
                4
            } else {
                2
            }
        }
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
            let boot = s
                .scheduler
                .slab
                .entries
                .iter()
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
            // MCS is_schedulable needs an SC; placeholder index so
            // admit enqueues and block dequeues consistently (these
            // run against the global scheduler — a stale queue entry
            // would corrupt later boot).
            t.sc = Some(0);
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
            radix: 5,
            guard_size: 59,
            guard: 0,
        };
        let ep_cap = Cap::Endpoint {
            ptr: KernelState::endpoint_ptr(7),
            badge: Badge(0xF1),
            rights: EndpointRights {
                can_send: true,
                can_receive: true,
                can_grant: false,
                can_grant_reply: true,
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
            &crate::syscall_handler::SyscallArgs {
                a0: 7,
                ..Default::default()
            },
            &mut SinkVoid,
        );
        assert!(r.is_ok());

        // Now fault the faulter.
        unsafe {
            KERNEL.get().scheduler.set_current(Some(faulter));
        }
        deliver_fault(
            faulter,
            FaultMessage::VMFault {
                addr: 0xDEAD_BEEF,
                fsr: 0x4,
                instruction: false,
            },
        )
        .expect("fault delivery ok");

        unsafe {
            let s = KERNEL.get();
            // Faulter is parked on Reply; handler is runnable with
            // the fault payload in msg_regs. Layout matches upstream
            // x86_64 seL4_VMFault_Msg: IP, Addr, PrefetchFault, FSR.
            // The fault label (6 = VMFault) lives in `ipc_label`,
            // not msg_regs.
            assert_eq!(
                s.scheduler.slab.get(faulter).state,
                ThreadStateType::BlockedOnReply
            );
            assert_eq!(s.scheduler.slab.get(handler).reply_to, Some(faulter));
            assert_eq!(s.scheduler.slab.get(handler).ipc_label, 6);
            assert_eq!(s.scheduler.slab.get(handler).msg_regs[1], 0xDEAD_BEEF);
            assert_eq!(s.scheduler.slab.get(handler).msg_regs[3], 0x4);
        }

        // Handler does SysReply to resume the faulter. Phase 36b —
        // SysReply isn't a syscall under MCS, so we call the
        // handler directly.
        unsafe {
            KERNEL.get().scheduler.set_current(Some(handler));
        }
        let r =
            crate::syscall_handler::handle_reply(&crate::syscall_handler::SyscallArgs::default());
        assert!(r.is_ok());

        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.scheduler.slab.get(faulter).state,
                ThreadStateType::Running
            );
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
