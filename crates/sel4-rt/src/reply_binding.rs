//! Non-mutating private TCB query of a capability-owned Reply relative to an expected caller.
//! This observes one serialized instant. It does not reserve the Reply or pin either TCB.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Binding {
    Free,
    Offered,
    BoundToTarget,
    BoundElsewhere,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Kernel(u64),
    MalformedReply,
}

pub fn decode_response(info: u64, word: u64) -> Result<Binding, Error> {
    if info >> 12 != 0 {
        return Err(Error::Kernel(info >> 12));
    }
    if info != 1 {
        return Err(Error::MalformedReply);
    }
    match word {
        0 => Ok(Binding::Free),
        1 => Ok(Binding::Offered),
        2 => Ok(Binding::BoundToTarget),
        3 => Ok(Binding::BoundElsewhere),
        _ => Err(Error::MalformedReply),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_success_states_are_decoded() {
        for (word, expected) in [
            (0, Binding::Free),
            (1, Binding::Offered),
            (2, Binding::BoundToTarget),
            (3, Binding::BoundElsewhere),
        ] {
            assert_eq!(decode_response(1, word), Ok(expected));
        }
    }

    #[test]
    fn malformed_success_never_becomes_free() {
        for info in [0, 2, 127, 1 | (1 << 7), 1 | (1 << 9)] {
            assert_eq!(decode_response(info, 0), Err(Error::MalformedReply));
        }
        for word in [4, 99, u64::MAX] {
            assert_eq!(decode_response(1, word), Err(Error::MalformedReply));
        }
    }

    #[test]
    fn kernel_errors_are_not_classifications() {
        for error in 1..=10 {
            assert_eq!(decode_response(error << 12, 0), Err(Error::Kernel(error)));
        }
    }
}
