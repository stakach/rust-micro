//! Intel SDM volume 3A, memory-cache control: a page's effective type depends
//! on its PAT selector and the fixed, variable, or default MTRR for its paddr.
//! This pure fixture does not read MSRs or touch native page tables.

#[path = "../src/boot/direct_map_policy.rs"]
pub(crate) mod direct_map_policy;
mod boot { pub(crate) use crate::direct_map_policy; }
#[path = "../src/arch/x86_64/cache_type.rs"]
mod cache_type;

use cache_type::{effective_page_cache_type, CacheRegisters};
use direct_map_policy::EffectiveCacheType as Type;

const PAT_RESET: u64 = 0x0007_0406_0007_0406;
const WB: u64 = 6;
const UC: u64 = 0;
const WC: u64 = 1;
const WT: u64 = 4;
const MTRR_E: u64 = 1 << 11;
const MTRR_FE: u64 = 1 << 10;
const FIX_CAP: u64 = 1 << 8;
const PAGE_PRESENT: u64 = 1;

fn regs<'a>(fixed: &'a [u64; 11], variable: &'a [(u64, u64)]) -> CacheRegisters<'a> {
    CacheRegisters {
        pat: PAT_RESET,
        mtrr_cap: variable.len() as u64,
        mtrr_default: MTRR_E | WB,
        fixed,
        variable,
        physical_bits: 36,
        normal_caching: true,
    }
}

fn variable(base: u64, size: u64, kind: u64) -> (u64, u64) {
    let physical_mask = (1u64 << 36) - 1;
    (base | kind, (physical_mask & !(size - 1) & !0xfff) | (1 << 11))
}

fn classify(paddr: u64, flags: u64, leaf_bits: u32, r: &CacheRegisters<'_>) -> Type {
    let base = paddr & !((1u64 << leaf_bits) - 1);
    effective_page_cache_type(paddr, base | flags, leaf_bits, r)
}

#[test]
fn physical_page_must_belong_to_the_exact_leaf() {
    let fixed = [0; 11];
    let r = regs(&fixed, &[]);
    assert_eq!(effective_page_cache_type(0x20_0000, 0x30_0000 | PAGE_PRESENT, 12, &r), Type::Unknown);
    let leaf_2m = 0x20_0000 | PAGE_PRESENT | (1 << 7);
    assert_eq!(effective_page_cache_type(0x20_0000, leaf_2m, 21, &r), Type::WriteBack);
    assert_eq!(effective_page_cache_type(0x3f_f000, leaf_2m, 21, &r), Type::WriteBack);
    assert_eq!(effective_page_cache_type(0x40_0000, leaf_2m, 21, &r), Type::Unknown);
    assert_eq!(effective_page_cache_type(0x20_0000, leaf_2m | (1 << 13), 21, &r), Type::Unknown,
        "large-leaf bit 13 is reserved, not a physical base bit");
    assert_eq!(effective_page_cache_type(0x20_0000, leaf_2m | (1 << 36), 21, &r), Type::Unknown,
        "a physical address bit beyond MAXPHYADDR cannot name this leaf");
    let leaf_1g = 0x4000_0000 | PAGE_PRESENT | (1 << 7);
    assert_eq!(effective_page_cache_type(0x4000_0000, leaf_1g, 30, &r), Type::WriteBack);
    assert_eq!(effective_page_cache_type(0x7fff_f000, leaf_1g, 30, &r), Type::WriteBack);
    assert_eq!(effective_page_cache_type(0x8000_0000, leaf_1g, 30, &r), Type::Unknown);
}

#[test]
fn pat_selector_uses_bit_7_for_4k_and_bit_12_for_large_leaves() {
    let fixed = [0; 11];
    let r = regs(&fixed, &[]);
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::WriteBack);
    // PCD/PWT 1 selects reset PAT3=UC, whereas PAT bit7 selects PAT4=WB.
    assert_eq!(classify(0x20_0000, PAGE_PRESENT | (1 << 4) | (1 << 3), 12, &r), Type::Uncached);
    assert_eq!(classify(0x20_0000, PAGE_PRESENT | (1 << 7), 12, &r), Type::WriteBack);
    for leaf_bits in [21, 30] {
        assert_eq!(classify(0x20_0000, PAGE_PRESENT | (1 << 7), leaf_bits, &r), Type::WriteBack,
            "PS bit must not be read as PAT");
        assert_eq!(classify(0x20_0000, PAGE_PRESENT | (1 << 7) | (1 << 4) | (1 << 3), leaf_bits, &r), Type::Uncached);
        assert_eq!(classify(0x20_0000, PAGE_PRESENT | (1 << 7) | (1 << 12), leaf_bits, &r), Type::WriteBack);
    }
}

#[test]
fn fixed_mtrr_overrides_variable_and_default_inside_first_megabyte() {
    let mut fixed = [0; 11];
    fixed[1] = WB << 8; // 0x80000 UC, 0x84000 WB
    let variable = [variable(0, 1 << 20, WB)];
    let mut r = regs(&fixed, &variable);
    r.mtrr_cap |= FIX_CAP;
    r.mtrr_default |= MTRR_FE;
    assert_eq!(classify(0x80000, PAGE_PRESENT, 12, &r), Type::Uncached);
    assert_eq!(classify(0x84000, PAGE_PRESENT, 12, &r), Type::WriteBack);
}

#[test]
fn fixed_mtrr_indexing_covers_a0000_and_first_and_last_fix4k_registers() {
    let mut fixed = [0x0606_0606_0606_0606; 11];
    fixed[2] &= !(0xff | (0xff << 56)); // A0000 and BC000 are UC.
    fixed[3] &= !(0xff | (0xff << 56)); // C0000 and C7000 are UC.
    fixed[10] &= !(0xff | (0xff << 56)); // F8000 and FF000 are UC.
    let mut r = regs(&fixed, &[]);
    r.mtrr_cap |= FIX_CAP;
    r.mtrr_default |= MTRR_FE;
    for page in [0xa_0000, 0xb_c000, 0xc_0000, 0xc_7000, 0xf_8000, 0xf_f000] {
        assert_eq!(classify(page, PAGE_PRESENT, 12, &r), Type::Uncached,
            "fixed register boundary {page:#x}");
    }
    for page in [0xa_4000, 0xb_8000, 0xc_1000, 0xc_8000, 0xf_9000, 0xf_7000] {
        assert_eq!(classify(page, PAGE_PRESENT, 12, &r), Type::WriteBack,
            "adjacent fixed register slot {page:#x}");
    }
}

#[test]
fn variable_overlap_precedence_and_default_are_conservative() {
    let fixed = [0; 11];
    let ranges = [variable(0, 4 << 20, WB), variable(2 << 20, 2 << 20, UC)];
    let r = regs(&fixed, &ranges);
    assert_eq!(classify(0x10_0000, PAGE_PRESENT, 12, &r), Type::WriteBack);
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Uncached);
    assert_eq!(classify(0x60_0000, PAGE_PRESENT, 12, &r), Type::WriteBack);

    let ranges = [variable(0, 4 << 20, WB), variable(2 << 20, 2 << 20, WT)];
    let r = regs(&fixed, &ranges);
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Unknown,
        "WT is valid but is not admitted by the current WB/UC/WC policy");

    let ranges = [variable(0, 4 << 20, WB), variable(2 << 20, 2 << 20, WC)];
    let mut r = regs(&fixed, &ranges);
    r.mtrr_cap |= 1 << 10; // WC is supported, but WB+WC overlap is undefined.
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Unknown,
        "undefined variable overlap must never become an apparent WB alias");
}

#[test]
fn pat_and_mtrr_combination_is_not_merely_mtrr_precedence() {
    let fixed = [0; 11];
    let mut r = regs(&fixed, &[]);
    r.mtrr_default = MTRR_E | UC;
    let mut pat = PAT_RESET;
    pat = (pat & !0xff) | WC; // PAT0=WC
    r.pat = pat;
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::WriteCombining,
        "Intel effective-type table maps MTRR UC + PAT WC to WC");

    r.mtrr_default = UC; // E clear gives an UC path; do not infer a safe WC alias.
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Unknown);
}

#[test]
fn variable_wc_requires_capability_and_obeys_pat_table() {
    let fixed = [0; 11];
    let ranges = [variable(2 << 20, 2 << 20, WC)];
    let mut r = regs(&fixed, &ranges);
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Unknown);
    r.mtrr_cap |= 1 << 10;
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::WriteCombining);
    // Reset PAT3=UC overrides the WC MTRR to an effective UC page.
    assert_eq!(classify(0x20_0000, PAGE_PRESENT | (1 << 4) | (1 << 3), 12, &r), Type::Uncached);
}

#[test]
fn pat_uc_minus_on_cacheable_mtrr_is_not_strong_uc_alias_proof() {
    let fixed = [0; 11];
    let mut r = regs(&fixed, &[]);
    let uc_minus_leaf = PAGE_PRESENT | (1 << 4); // Reset PAT2 = UC-minus.
    assert_eq!(classify(0x20_0000, uc_minus_leaf, 12, &r), Type::Unknown,
        "page-derived UC-minus requires cache snooping under WB MTRR");
    r.mtrr_default = MTRR_E | WT;
    assert_eq!(classify(0x20_0000, uc_minus_leaf, 12, &r), Type::Unknown);
    r.mtrr_default = MTRR_E | UC;
    assert_eq!(classify(0x20_0000, uc_minus_leaf, 12, &r), Type::Uncached,
        "an UC MTRR forces the entire physical range uncached");
}

#[test]
fn unsupported_or_unproved_inputs_are_unknown() {
    let fixed = [0; 11];
    let mut r = regs(&fixed, &[]);
    r.normal_caching = false;
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Unknown);
    r.normal_caching = true;
    r.physical_bits = 64;
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Unknown);
    r.physical_bits = 36;
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 13, &r), Type::Unknown);
    assert_eq!(classify(0x20_0000, 0, 12, &r), Type::Unknown);
    r.mtrr_default = MTRR_E | 2; // Reserved memory type.
    assert_eq!(classify(0x20_0000, PAGE_PRESENT, 12, &r), Type::Unknown);
}
