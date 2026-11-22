//! VT-d translation retirement: the ordering that keeps a DMA mapping out of reuse until the
//! hardware has acknowledged that it no longer caches it (userspace-ntos#429).
//!
//! A cleared IO page-table entry or context entry may still be cached by the remapping hardware.
//! The kernel therefore writes the entry, issues the register-based invalidation, and waits for
//! the command to complete with a non-zero actual granularity before returning. Only then may a
//! caller release the frame, IO page table or IOVA. A timeout or an unperformed invalidation is
//! reported to the caller, which must not release anything (the kernel fail-stops).
//!
//! Context entries are retired present-word first: the context cache must be invalidated before
//! the IOTLB, because cached context entries tag IOTLB entries, and the domain word is cleared
//! only once both are acknowledged.
//!
//! The module is pure so the ordering is tested on the host (tests/vtd_retirement.rs).

use core::sync::atomic::{fence, Ordering};

pub const CCMD_REG: u64 = 0x28;
pub const INVALIDATION_SPINS: u32 = 100_000;
/// ICC | CIRG=global.
pub const CONTEXT_INVALIDATE: u64 = (1 << 63) | (1 << 61);
/// IVT | IIRG=global | DR | DW.
pub const IOTLB_INVALIDATE: u64 = (1 << 63) | (1 << 60) | (1 << 49) | (1 << 48);
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdError {
    Unavailable,
    TimedOut,
    UnsupportedGranularity,
    OwnershipConflict,
}

/// The remapping unit's 64-bit registers.
pub trait VtdRegisters {
    fn read64(&mut self, offset: u64) -> u64;
    fn write64(&mut self, offset: u64, value: u64);
}

fn wait_command_clear<R: VtdRegisters>(regs: &mut R, offset: u64, bit: u64) -> Result<(), VtdError> {
    for _ in 0..INVALIDATION_SPINS {
        if regs.read64(offset) & bit == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(VtdError::TimedOut)
}

/// Global context-cache invalidation, then global IOTLB invalidation, each acknowledged.
pub fn invalidate_context_and_iotlb_at<R: VtdRegisters>(regs: &mut R, iotlb: u64) -> Result<(), VtdError> {
    wait_command_clear(regs, CCMD_REG, 1 << 63)?;
    regs.write64(CCMD_REG, CONTEXT_INVALIDATE);
    wait_command_clear(regs, CCMD_REG, 1 << 63)?;
    // CAIG=0 means hardware did not perform the requested invalidation.
    if (regs.read64(CCMD_REG) >> 59) & 0x3 == 0 {
        return Err(VtdError::UnsupportedGranularity);
    }
    invalidate_iotlb_at(regs, iotlb)
}

/// Global IOTLB invalidation with read/write drain, acknowledged.
pub fn invalidate_iotlb_at<R: VtdRegisters>(regs: &mut R, iotlb: u64) -> Result<(), VtdError> {
    wait_command_clear(regs, iotlb, 1 << 63)?;
    regs.write64(iotlb, IOTLB_INVALIDATE);
    wait_command_clear(regs, iotlb, 1 << 63)?;
    // IAIG=0 means hardware did not perform the requested invalidation.
    if (regs.read64(iotlb) >> 57) & 0x7 == 0 {
        return Err(VtdError::UnsupportedGranularity);
    }
    Ok(())
}

/// Retire one IO page-table entry: `write_entry` stores the new (cleared or replaced) entry,
/// then the IOTLB invalidation is acknowledged. `Ok` is the only point after which the old
/// target may be reused.
pub fn retire_leaf<R: VtdRegisters>(
    regs: &mut R,
    iotlb: u64,
    write_entry: impl FnOnce(),
) -> Result<(), VtdError> {
    write_entry();
    fence(Ordering::SeqCst);
    invalidate_iotlb_at(regs, iotlb)
}

/// Retire a context entry: clear its present word, acknowledge the context-cache and IOTLB
/// invalidations, and only then clear its domain word. On error the domain word is retained.
pub fn retire_context<R: VtdRegisters>(
    regs: &mut R,
    iotlb: u64,
    clear_present: impl FnOnce(),
    clear_domain: impl FnOnce(),
) -> Result<(), VtdError> {
    clear_present();
    fence(Ordering::SeqCst);
    invalidate_context_and_iotlb_at(regs, iotlb)?;
    clear_domain();
    Ok(())
}

#[inline]
pub fn cte_low(asr_paddr: u64, tt: u64, present: bool) -> u64 {
    (asr_paddr & ADDR_MASK) | ((tt & 0x3) << 2) | (present as u64)
}
#[inline]
pub fn cte_high(aw: u64, did: u64) -> u64 {
    (aw & 0x7) | ((did & 0xFFFF) << 8)
}
#[inline]
pub fn cte_present(low: u64) -> bool {
    low & 1 != 0
}
#[inline]
pub fn cte_asr(low: u64) -> u64 {
    low & ADDR_MASK
}
#[inline]
pub fn cte_domain_id(high: u64) -> u16 {
    ((high >> 8) & 0xffff) as u16
}

/// An existing PCI requester context may only be extended by its installed, non-zero domain.
pub fn context_admits_domain(low: u64, high: u64, domain_id: u16) -> bool {
    domain_id != 0 && cte_present(low) && cte_domain_id(high) == domain_id
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaRetirementKind {
    Frame,
    Table(u8),
}

/// CNode retirement order: DMA frames first, then IO page tables from the deepest level up.
pub fn dma_retirement_phase(kind: DmaRetirementKind, levels: u8) -> Option<u8> {
    match kind {
        DmaRetirementKind::Frame => Some(0),
        DmaRetirementKind::Table(level) if level < levels => Some(levels - level),
        DmaRetirementKind::Table(_) => None,
    }
}

/// A copied IO page-table alias keeps the hardware mapping until its last cap is deleted.
pub fn retire_last_iopt_alias(remaining_mapped_aliases: usize) -> bool {
    remaining_mapped_aliases == 0
}
