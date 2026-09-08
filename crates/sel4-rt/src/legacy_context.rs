//! x86-64 combined legacy-context extension; not the upstream register invocation ABI.
//!
//! Read has no input words and returns the 20-word public register layout followed by a
//! 512-byte FXSAVE64 image and six debug words (DR0-3, DR6, DR7). Write takes a selection
//! mask followed by that same payload.
//! RIP is the canonical execution continuation, not ReadRegisters' rewound syscall reporter.
//! Words 18/19 are reserved TLS positions: reads return zero and writes cannot select them.
//! A write validates all selected input before a single target quiescence; unselected state
//! is preserved from that live snapshot, not from the supplied payload. RESTART_MASK applies
//! WriteRegisters restart semantics only after installation. Without it, scheduling state
//! remains unchanged. Self-targets, extra caps, and non-x86 architectures are rejected.
//! Restart consumes a pending debug fault: its cached status is acknowledged unless DEBUG_MASK
//! supplies replacement state. Other unselected debug registers and stepping policy are retained.

pub const REGISTER_WORDS: usize = 20;
pub const FX_BYTES: usize = 512;
pub const FX_WORDS: usize = FX_BYTES / 8;
pub const DEBUG_WORDS: usize = 6;
pub const DEBUG_OFFSET: usize = REGISTER_WORDS + FX_WORDS;
pub const READ_WORDS: usize = DEBUG_OFFSET + DEBUG_WORDS;
pub const WRITE_WORDS: usize = 1 + READ_WORDS;
pub const REGISTER_MASK: u64 = (1 << 18) - 1;
pub const FX_MASK: u64 = 1 << 20;
/// Cancel outstanding IPC/reply/fault state and make runnable after installing selected state.
pub const RESTART_MASK: u64 = 1 << 21;
pub const DEBUG_MASK: u64 = 1 << 22;
pub const WRITE_MASK: u64 = REGISTER_MASK | FX_MASK | RESTART_MASK | DEBUG_MASK;

/// TLS remains owned by the existing TLS capability operations, not this payload.
pub const fn valid_selection(mask: u64) -> bool {
    mask & !WRITE_MASK == 0
}

/// Intel's specified MXCSR feature mask when FXSAVE reports a zero MXCSR_MASK.
pub const ZERO_REPORTED_MXCSR_MASK: u32 = 0x0000_ffbf;

pub const fn effective_mxcsr_mask(reported: u32) -> u32 {
    if reported == 0 {
        ZERO_REPORTED_MXCSR_MASK
    } else {
        reported
    }
}

/// Validate the only FXSAVE64 control field whose reserved bits can fault FXRSTOR.
/// The user-supplied MXCSR_MASK is informational, not authority; normalize it to the actual
/// effective CPU mask. No rounding, clamping or mutation occurs on rejected input.
pub fn validate_fx_state(bytes: &mut [u8; FX_BYTES], mask: u32) -> Result<(), ()> {
    let mxcsr = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    if mask == 0 || mxcsr & !mask != 0 {
        return Err(());
    }
    bytes[28..32].copy_from_slice(&mask.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_mask_controls_acceptance_not_user_mask() {
        for mask in [0xffbfu32, 0xffff, 0x1f80] {
            let mut bytes = [0xa5; FX_BYTES];
            bytes[24..28].copy_from_slice(&mask.to_le_bytes());
            bytes[28..32].fill(0xff);
            let before = bytes;
            validate_fx_state(&mut bytes, mask).unwrap();
            assert_eq!(&bytes[..28], &before[..28]);
            assert_eq!(&bytes[28..32], &mask.to_le_bytes());
            assert_eq!(&bytes[32..], &before[32..]);
            for bit in 0..32 {
                if mask & (1 << bit) == 0 {
                    bytes[24..28].copy_from_slice(&(1u32 << bit).to_le_bytes());
                    let before = bytes;
                    assert_eq!(validate_fx_state(&mut bytes, mask), Err(()));
                    assert_eq!(bytes, before);
                }
            }
        }
    }

    #[test]
    fn zero_report_uses_architectural_mask_but_uninitialized_validation_rejects() {
        assert_eq!(effective_mxcsr_mask(0), 0xffbf);
        assert_eq!(effective_mxcsr_mask(0xffff), 0xffff);
        let mut bytes = [0; FX_BYTES];
        assert_eq!(validate_fx_state(&mut bytes, 0), Err(()));
        bytes[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        validate_fx_state(&mut bytes, effective_mxcsr_mask(0)).unwrap();
        bytes[24..28].copy_from_slice(&0x1fc0u32.to_le_bytes());
        assert_eq!(
            validate_fx_state(&mut bytes, effective_mxcsr_mask(0)),
            Err(())
        );
    }

    #[test]
    fn selection_admits_only_public_gprs_legacy_fx_and_debug() {
        assert!(valid_selection(0));
        assert!(valid_selection(WRITE_MASK));
        for bit in 0..64 {
            assert_eq!(
                valid_selection(1 << bit),
                bit < 18 || bit == 20 || bit == 21 || bit == 22
            );
        }
        assert_eq!((DEBUG_OFFSET, READ_WORDS, WRITE_WORDS), (84, 90, 91));
    }
}
