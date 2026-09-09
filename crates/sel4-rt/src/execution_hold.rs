//! Checked private TCB execution exclusion. These operations do not change wait state.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Kernel(u64),
    /// The operation may have entered. Do not replay an acquisition or discard its owner.
    MalformedReply,
}

unsafe fn invoke(tcb: u64, request: u64, word: u64) -> (u64, u64) {
    let (info, result): (u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") crate::SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") request => info,
        inout("r10") word => result,
        inout("r8") 0u64 => _, inout("r9") 0u64 => _,
        inout("r15") 0u64 => _,
        in("r12") 0u64, in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (info, result)
}

/// Acquire one physical hold. The nonzero generation is unique across TCB lifetimes.
/// A held target rejects another acquire; logical nesting belongs to the caller.
pub unsafe fn acquire(tcb: u64) -> Result<u64, Error> {
    let (info, generation) = invoke(tcb, crate::LBL_TCB_ACQUIRE_EXECUTION_HOLD << 12, 0);
    if info >> 12 != 0 {
        return Err(Error::Kernel(info >> 12));
    }
    if info != 1 || generation == 0 {
        return Err(Error::MalformedReply);
    }
    Ok(generation)
}

/// Release only the exact hold. Underlying IPC completion, state and SC ownership decide
/// whether the target becomes eligible; this operation does not fabricate completion.
pub unsafe fn release(tcb: u64, generation: u64) -> Result<(), Error> {
    let (info, _) = invoke(
        tcb,
        (crate::LBL_TCB_RELEASE_EXECUTION_HOLD << 12) | 1,
        generation,
    );
    if info >> 12 != 0 {
        return Err(Error::Kernel(info >> 12));
    }
    if info != 0 {
        return Err(Error::MalformedReply);
    }
    Ok(())
}

/// Start an initially dormant TCB using ordinary Resume semantics. This is not
/// wait-preserving release: callers resuming a held wait must use `release`.
pub unsafe fn resume_initial(tcb: u64) -> Result<(), Error> {
    let (info, _) = invoke(tcb, crate::LBL_TCB_RESUME << 12, 0);
    if info >> 12 != 0 {
        return Err(Error::Kernel(info >> 12));
    }
    if info != 0 {
        return Err(Error::MalformedReply);
    }
    Ok(())
}
