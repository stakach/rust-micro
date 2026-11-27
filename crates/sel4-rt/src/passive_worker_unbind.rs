//! Atomic SC cutover for a private worker's first blocked receive.
//!
//! The kernel checks physical SC, TCB, Endpoint and Reply ownership in one
//! invocation. This wrapper returns the complete reply MessageInfo so a caller
//! can acknowledge only the exact zero-word success tag. Any other returned
//! value is indeterminate for the retained bootstrap resources.

/// Exactly three CPtrs in message registers; no extra capabilities.
const REQUEST_INFO: u64 = (crate::LBL_SCHED_CONTEXT_UNBIND_PASSIVE_WORKER << 12) | 3;

/// Call the private checked unbind on the bootstrap SC capability.
///
/// `worker`, `endpoint` and `reply` are invoker-owned CPtrs. The kernel
/// validates that the worker is the sole receiver of the endpoint, that this
/// Reply is offered to it, and that the SC is its original bound SC. Keep all
/// four capabilities retained if the returned tag is anything but zero.
#[cfg(target_arch = "x86_64")]
pub unsafe fn unbind(
    bootstrap_sc: u64,
    worker: u64,
    endpoint: u64,
    reply: u64,
) -> u64 {
    let response_info: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") crate::SYS_CALL as u64 => _,
        inout("rdi") bootstrap_sc => _,
        inout("rsi") REQUEST_INFO => response_info,
        inout("r10") worker => _,
        inout("r8") endpoint => _,
        inout("r9") reply => _,
        inout("r15") 0u64 => _,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    response_info
}
