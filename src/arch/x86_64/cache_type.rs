//! Pure Intel PAT/MTRR interpretation for one physical 4 KiB page.
//!
//! Intel SDM volume 3A, chapter 13 (Memory Cache Control), especially tables
//! 13-7 and 13-9 and section 13.11.4.1. The caller must prove CPU vendor,
//! feature support, per-CPU register consistency, the leaf's exact physical
//! identity, and normal CR0 caching before these inputs authorize a map.
//! This module reads no MSR and does not infer page-table ownership.

use crate::boot::direct_map_policy::EffectiveCacheType;

const PRESENT: u64 = 1;
const PS: u64 = 1 << 7;
const MTRR_E: u64 = 1 << 11;
const MTRR_FE: u64 = 1 << 10;
const MTRR_FIX_CAP: u64 = 1 << 8;
const MTRR_WC_CAP: u64 = 1 << 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryType { Uc, Wc, Wt, Wp, Wb, UcMinus }

/// A single verified CPU's cache registers. `fixed` follows the architectural
/// MSR order: FIX64K_00000, FIX16K_80000/A0000, then FIX4K_C0000..F8000.
/// `variable` holds all `IA32_MTRRCAP.VCNT` base/mask pairs in register order.
pub struct CacheRegisters<'a> {
    pub pat: u64,
    pub mtrr_cap: u64,
    pub mtrr_default: u64,
    pub fixed: &'a [u64; 11],
    pub variable: &'a [(u64, u64)],
    pub physical_bits: u8,
    /// False when CR0.CD/NW or the CPU/feature snapshot has not been proved.
    pub normal_caching: bool,
}

/// Classify one aligned physical page covered by the supplied leaf's physical
/// base and size. The native walker still must prove that this leaf came from
/// the intended root and virtual address.
/// Large leaves may span different fixed/variable MTRR types; callers must
/// classify every affected 4 KiB subrange before treating the leaf as uniform.
pub fn effective_page_cache_type(
    physical_page: u64,
    leaf: u64,
    leaf_bits: u32,
    registers: &CacheRegisters<'_>,
) -> EffectiveCacheType {
    if !registers.normal_caching
        || !(32..=52).contains(&registers.physical_bits)
        || physical_page & 0xfff != 0
        || physical_page >= (1u64 << registers.physical_bits)
        || leaf & PRESENT == 0
        || !matches!(leaf_bits, 12 | 21 | 30)
        || (leaf_bits != 12 && leaf & PS == 0)
    {
        return EffectiveCacheType::Unknown;
    }
    let frame_size = 1u64 << leaf_bits;
    let address_mask = ((1u64 << registers.physical_bits) - 1) & !(frame_size - 1);
    let leaf_base = leaf & address_mask;
    // In a large leaf, bit 12 is PAT; bits above it and below the physical
    // base are reserved. Do not treat a malformed leaf as evidence.
    if (leaf_bits != 12 && leaf & ((frame_size - 1) & !0x1fff) != 0)
        || (leaf & (((1u64 << 52) - 1) & !((1u64 << registers.physical_bits) - 1) & !(frame_size - 1)) != 0)
        || physical_page < leaf_base
        || physical_page >= leaf_base + frame_size
    {
        return EffectiveCacheType::Unknown;
    }
    let Some(pat_type) = pat_type(leaf, leaf_bits, registers.pat) else {
        return EffectiveCacheType::Unknown;
    };
    let Some(mtrr_type) = mtrr_type(physical_page, registers) else {
        return EffectiveCacheType::Unknown;
    };
    match (mtrr_type, pat_type) {
        (MemoryType::Uc, MemoryType::Wc)
        | (MemoryType::Wc, MemoryType::UcMinus | MemoryType::Wc | MemoryType::Wb)
        | (MemoryType::Wt | MemoryType::Wb | MemoryType::Wp, MemoryType::Wc)
        | (MemoryType::Wp, MemoryType::UcMinus) => EffectiveCacheType::WriteCombining,
        (MemoryType::Wb, MemoryType::Wb) => EffectiveCacheType::WriteBack,
        (MemoryType::Uc, _)
        | (_, MemoryType::Uc)
        | (MemoryType::Wc, MemoryType::Wt | MemoryType::Wp) =>
            EffectiveCacheType::Uncached,
        // WB/WT + UC-minus is an effective UC with page-derived cache snooping
        // (SDM table 13-7, note 2). Keep it outside strong-UC alias admission
        // until every potentially cached alias is accounted for.
        (MemoryType::Wt | MemoryType::Wb, MemoryType::UcMinus) =>
            EffectiveCacheType::Unknown,
        _ => EffectiveCacheType::Unknown,
    }
}

fn pat_type(leaf: u64, leaf_bits: u32, pat: u64) -> Option<MemoryType> {
    let pat_bit = if leaf_bits == 12 { 7 } else { 12 };
    let index = ((leaf >> pat_bit) & 1) << 2
        | ((leaf >> 4) & 1) << 1
        | ((leaf >> 3) & 1);
    decode_type(((pat >> (index * 8)) & 0xff) as u8, true, true)
}

fn decode_type(value: u8, uc_minus: bool, wc: bool) -> Option<MemoryType> {
    match value {
        0 => Some(MemoryType::Uc),
        1 if wc => Some(MemoryType::Wc),
        4 => Some(MemoryType::Wt),
        5 => Some(MemoryType::Wp),
        6 => Some(MemoryType::Wb),
        7 if uc_minus => Some(MemoryType::UcMinus),
        _ => None,
    }
}

fn mtrr_type(paddr: u64, r: &CacheRegisters<'_>) -> Option<MemoryType> {
    // With MTRRs disabled the manual describes an UC path, but do not assume
    // a PAT override is safe to alias while initialization may be in flight.
    if r.mtrr_default & MTRR_E == 0 { return None; }
    if r.mtrr_default & !(MTRR_E | MTRR_FE | 0xff) != 0 { return None; }
    if r.variable.len() != (r.mtrr_cap & 0xff) as usize { return None; }
    let wc = r.mtrr_cap & MTRR_WC_CAP != 0;
    let default_type = decode_type((r.mtrr_default & 0xff) as u8, false, wc)?;
    if paddr < 0x10_0000 && r.mtrr_default & MTRR_FE != 0 {
        if r.mtrr_cap & MTRR_FIX_CAP == 0 { return None; }
        let (register, index) = fixed_index(paddr);
        return decode_type(((r.fixed[register] >> (index * 8)) & 0xff) as u8, false, wc);
    }

    let physical_mask = (1u64 << r.physical_bits) - 1;
    let address_mask = physical_mask & !0xfff;
    let mut kinds = 0u8;
    for &(base, mask) in r.variable {
        if mask & (1 << 11) == 0 { continue; }
        if base & !((address_mask) | 0xff) != 0
            || mask & !(address_mask | (1 << 11)) != 0
        { return None; }
        let relevant = mask & address_mask;
        if (paddr & relevant) != (base & relevant) { continue; }
        let kind = decode_type((base & 0xff) as u8, false, wc)?;
        kinds |= match kind {
            MemoryType::Uc => 1,
            MemoryType::Wc => 2,
            MemoryType::Wt => 4,
            MemoryType::Wp => 8,
            MemoryType::Wb => 16,
            MemoryType::UcMinus => return None,
        };
    }
    if kinds & 1 != 0 { return Some(MemoryType::Uc); }
    match kinds {
        2 => Some(MemoryType::Wc),
        4 | 20 => Some(MemoryType::Wt),
        8 => Some(MemoryType::Wp),
        16 => Some(MemoryType::Wb),
        0 => Some(default_type),
        _ => None,
    }
}

fn fixed_index(paddr: u64) -> (usize, u64) {
    if paddr < 0x8_0000 { (0, paddr / 0x1_0000) }
    else if paddr < 0xa_0000 { (1, (paddr - 0x8_0000) / 0x4000) }
    else if paddr < 0xc_0000 { (2, (paddr - 0xa_0000) / 0x4000) }
    else { (3 + ((paddr - 0xc_0000) / 0x8000) as usize, (paddr / 0x1000) & 7) }
}
