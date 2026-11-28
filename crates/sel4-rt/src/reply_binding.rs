//! Non-mutating private TCB query of a capability-owned Reply relative to an expected caller.
//! This observes one serialized instant. It does not reserve the Reply or pin either TCB.

pub use crate::reply_binding_decoder::{
    decode_exact_offer_response, decode_response, Binding, Error,
};

/// Query with an expected-caller TCB capability and a Reply cptr in the invoker's CSpace.
/// No scheduler, donation, reply-chain or execution-hold state is changed. Exclusive ownership
/// and lifetime validation remain the caller's responsibility; this is not a reservation.
#[cfg(target_arch = "x86_64")]
pub unsafe fn query(expected_tcb: u64, reply: u64) -> Result<Binding, Error> {
    let (info, word): (u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") crate::SYS_CALL as u64 => _,
        inout("rdi") expected_tcb => _,
        inout("rsi") (crate::LBL_TCB_QUERY_REPLY_BINDING << 12) | 1 => info,
        inout("r10") reply => word,
        inout("r8") 0u64 => _, inout("r9") 0u64 => _, inout("r15") 0u64 => _,
        in("r12") 0u64, in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    decode_response(info, word)
}

/// Query whether `reply` is offered to `expected_tcb` while that TCB heads the blocked
/// receive queue of `endpoint`. All three CPtrs are resolved in the invoker's CSpace.
/// This is a non-mutating observation, not a reservation: the caller must retain the exact
/// physical objects and prevent their reuse until the next Call is admitted or refused.
#[cfg(target_arch = "x86_64")]
pub unsafe fn query_exact_offer(
    expected_tcb: u64,
    reply: u64,
    endpoint: u64,
) -> Result<bool, Error> {
    let (info, word): (u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") crate::SYS_CALL as u64 => _,
        inout("rdi") expected_tcb => _,
        inout("rsi") (crate::LBL_TCB_QUERY_REPLY_BINDING << 12) | 2 => info,
        inout("r10") reply => word,
        inout("r8") endpoint => _,
        inout("r9") 0u64 => _, inout("r15") 0u64 => _,
        in("r12") 0u64, in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    decode_exact_offer_response(info, word)
}
