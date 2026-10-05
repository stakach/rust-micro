//! Snapshot of current physical VSpace separation. Never a pin or permission to replay effects.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Binding {
    Refused,
    MatchesSeparate,
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
        0 => Ok(Binding::Refused),
        1 => Ok(Binding::MatchesSeparate),
        _ => Err(Error::MalformedReply),
    }
}

/// Both roots are mandatory invoker-owned CPtrs. Recheck after any intervening owner change;
/// separate retained Reply and execution-hold authority is required for later effects.
#[cfg(target_arch = "x86_64")]
pub unsafe fn query(
    target_tcb: u64,
    expected_child_root: u64,
    held_provider_root: u64,
) -> Result<Binding, Error> {
    let (info, word): (u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") crate::SYS_CALL as u64 => _,
        inout("rdi") target_tcb => _,
        inout("rsi") (crate::LBL_TCB_QUERY_VSPACE_BINDING << 12) | 2 => info,
        inout("r10") expected_child_root => word,
        inout("r8") held_provider_root => _,
        inout("r9") 0u64 => _, inout("r15") 0u64 => _,
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
    fn exact_snapshot_results() {
        assert_eq!(decode_response(1, 0), Ok(Binding::Refused));
        assert_eq!(decode_response(1, 1), Ok(Binding::MatchesSeparate));
    }
    #[test]
    fn malformed_response_never_authorizes_separation() {
        for info in [0, 2, 1 | (1 << 7), 1 | (1 << 9)] {
            assert_eq!(decode_response(info, 1), Err(Error::MalformedReply));
        }
        for word in [2, 99, u64::MAX] {
            assert_eq!(decode_response(1, word), Err(Error::MalformedReply));
        }
        assert_eq!(decode_response(3 << 12, 1), Err(Error::Kernel(3)));
    }
}
