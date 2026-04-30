//! x86_64 virtual-address-space helpers.
//!
//! This is the algorithmic core of seL4's `arch/x86/64/kernel/vspace.c`:
//! decompose a virtual address into the four page-table indices,
//! build the right PTE / PDE / PDPTE / PML4E for a given mapping,
//! and walk the table chain. Actual TLB invalidation, ASID
//! allocation, and the cap-derivation rules tying frames to vspace
//! roots will land alongside the syscall trap entry; everything in
//! this module is hardware-free and testable today.

use crate::structures::arch::{PdeLarge, PdePt, Pdpte1g, PdptePd, Pml4e, Pte};
use crate::types::seL4_Word as Word;

// `Pde` and `Pdpte` are tagged unions in the .bf and our codegen
// only emits structs for `block`s, not `tagged_union`s. The wire
// format is one word in both cases — the variant is selected by the
// `page_size` bit. We surface the per-variant types here directly.

// ---------------------------------------------------------------------------
// Address decomposition.
//
// Layout of a 4-level x86_64 virtual address (canonical 48-bit):
//   bits 47..40 -> PML4 index (9)
//   bits 39..31 -> PDPT index (9)
//   bits 30..22 -> PD   index (9)
//   bits 21..13 -> PT   index (9)
//   bits 11..00 -> page offset (12)
// 2 MiB pages live in the PD level (skip the PT entry); 1 GiB pages
// live in the PDPT level (skip both).
// ---------------------------------------------------------------------------

pub const ENTRIES_PER_TABLE: usize = 512;
pub const PAGE_BITS_4K: u32 = 12;
pub const PAGE_BITS_2M: u32 = 21;
pub const PAGE_BITS_1G: u32 = 30;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VAddrIndices {
    pub pml4: u16,
    pub pdpt: u16,
    pub pd: u16,
    pub pt: u16,
    pub offset: u32,
}

pub const fn decompose_vaddr(vaddr: Word) -> VAddrIndices {
    VAddrIndices {
        pml4: ((vaddr >> 39) & 0x1FF) as u16,
        pdpt: ((vaddr >> 30) & 0x1FF) as u16,
        pd: ((vaddr >> 21) & 0x1FF) as u16,
        pt: ((vaddr >> 12) & 0x1FF) as u16,
        offset: (vaddr & 0xFFF) as u32,
    }
}

/// Inverse of `decompose_vaddr` — useful for spec assertions.
pub const fn compose_vaddr(idx: VAddrIndices) -> Word {
    (idx.pml4 as Word) << 39
        | (idx.pdpt as Word) << 30
        | (idx.pd as Word) << 21
        | (idx.pt as Word) << 12
        | (idx.offset as Word & 0xFFF)
}

// ---------------------------------------------------------------------------
// Mapping rights — a tiny VMRights enum + helpers to pack into PTE
// flag bits. seL4 passes these around as a `vm_rights_t` (kernel/
// user / read / write distinctions).
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VmRights {
    /// Kernel-only, read+write.
    KernelOnly,
    /// User read-only.
    UserRO,
    /// User read-write.
    UserRW,
}

impl VmRights {
    pub const fn user(self) -> bool {
        matches!(self, VmRights::UserRO | VmRights::UserRW)
    }
    pub const fn writable(self) -> bool {
        matches!(self, VmRights::KernelOnly | VmRights::UserRW)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CacheAttr {
    /// Default writeback cacheable memory.
    Writeback,
    /// Strong uncached (UC) — used for MMIO.
    Uncached,
    /// Write-through (WT).
    WriteThrough,
}

// ---------------------------------------------------------------------------
// PTE / PDE / PDPTE / PML4E construction.
//
// The bitfield types ship from build.rs codegen; we provide
// type-safe helpers that fill the right fields given a physical
// address, rights, and cache attributes.
// ---------------------------------------------------------------------------

const fn split_cache(c: CacheAttr) -> (u64, u64, u64) {
    // (PAT, PCD, PWT)
    match c {
        CacheAttr::Writeback => (0, 0, 0),
        CacheAttr::Uncached => (0, 1, 0),
        CacheAttr::WriteThrough => (0, 0, 1),
    }
}

/// Build a 4 KiB PTE pointing to `paddr` (must be page-aligned).
pub fn make_pte(paddr: Word, rights: VmRights, cache: CacheAttr, executable: bool) -> Pte {
    let (pat, pcd, pwt) = split_cache(cache);
    Pte::zeroed()
        .with_present(1)
        .with_read_write(rights.writable() as u64)
        .with_super_user(rights.user() as u64)
        .with_xd((!executable) as u64)
        .with_pat(pat)
        .with_cache_disabled(pcd)
        .with_write_through(pwt)
        .with_page_base_address(paddr >> PAGE_BITS_4K)
}

/// Build a PD entry pointing to a page table at `pt_paddr`.
pub fn make_pde_pt(pt_paddr: Word, rights: VmRights, executable: bool) -> PdePt {
    PdePt::zeroed()
        .with_present(1)
        .with_read_write(rights.writable() as u64)
        .with_super_user(rights.user() as u64)
        .with_xd((!executable) as u64)
        .with_pt_base_address(pt_paddr >> PAGE_BITS_4K)
}

/// Build a PD entry mapping a 2 MiB large page directly.
pub fn make_pde_large(paddr: Word, rights: VmRights, cache: CacheAttr, executable: bool) -> PdeLarge {
    let (pat, pcd, pwt) = split_cache(cache);
    PdeLarge::zeroed()
        .with_present(1)
        .with_page_size(1)
        .with_read_write(rights.writable() as u64)
        .with_super_user(rights.user() as u64)
        .with_xd((!executable) as u64)
        .with_pat(pat)
        .with_cache_disabled(pcd)
        .with_write_through(pwt)
        // The 2 MiB page address is encoded with its low 9 zero bits
        // implicit (i.e. bits 21..51).
        .with_page_base_address(paddr >> PAGE_BITS_2M)
}

/// Build a PDPT entry pointing to a page directory.
pub fn make_pdpte_pd(pd_paddr: Word, rights: VmRights, executable: bool) -> PdptePd {
    PdptePd::zeroed()
        .with_present(1)
        .with_page_size(0)
        .with_read_write(rights.writable() as u64)
        .with_super_user(rights.user() as u64)
        .with_xd((!executable) as u64)
        .with_pd_base_address(pd_paddr >> PAGE_BITS_4K)
}

/// Build a PDPT entry mapping a 1 GiB page.
pub fn make_pdpte_1g(paddr: Word, rights: VmRights, cache: CacheAttr, executable: bool) -> Pdpte1g {
    let (pat, pcd, pwt) = split_cache(cache);
    Pdpte1g::zeroed()
        .with_present(1)
        .with_page_size(1)
        .with_read_write(rights.writable() as u64)
        .with_super_user(rights.user() as u64)
        .with_xd((!executable) as u64)
        .with_pat(pat)
        .with_cache_disabled(pcd)
        .with_write_through(pwt)
        .with_page_base_address(paddr >> PAGE_BITS_1G)
}

/// Build a PML4 entry pointing to a PDPT.
pub fn make_pml4e(pdpt_paddr: Word, rights: VmRights, executable: bool) -> Pml4e {
    Pml4e::zeroed()
        .with_present(1)
        .with_read_write(rights.writable() as u64)
        .with_super_user(rights.user() as u64)
        .with_xd((!executable) as u64)
        .with_pdpt_base_address(pdpt_paddr >> PAGE_BITS_4K)
}

// ---------------------------------------------------------------------------
// Map / unmap a 4 KiB frame inside a fully-populated PT slice.
//
// In the full kernel, `frame_map` resolves the PT containing the
// target slot via the cap chain (PML4 → PDPT → PD → PT) and writes
// the PTE there. The cap-side wiring lands when we have a real
// VSpace cap and ASID pool; for now we deliver the function that
// writes the entry given the resolved PT.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MapError {
    /// Target slot already holds a present PTE.
    AlreadyMapped,
    /// `paddr` or `vaddr` not 4 KiB-aligned.
    AlignmentError,
    /// `vaddr` outside the canonical 48-bit user/kernel space.
    OutOfRange,
}

pub fn frame_map_4k(
    pt: &mut [Pte; ENTRIES_PER_TABLE],
    vaddr: Word,
    paddr: Word,
    rights: VmRights,
    cache: CacheAttr,
    executable: bool,
) -> Result<(), MapError> {
    if (vaddr & 0xFFF) != 0 || (paddr & 0xFFF) != 0 {
        return Err(MapError::AlignmentError);
    }
    if !canonical(vaddr) {
        return Err(MapError::OutOfRange);
    }
    let idx = decompose_vaddr(vaddr).pt as usize;
    if pt[idx].present() != 0 {
        return Err(MapError::AlreadyMapped);
    }
    pt[idx] = make_pte(paddr, rights, cache, executable);
    Ok(())
}

pub fn frame_unmap_4k(pt: &mut [Pte; ENTRIES_PER_TABLE], vaddr: Word) {
    let idx = decompose_vaddr(vaddr).pt as usize;
    pt[idx] = Pte::zeroed();
}

/// True if `vaddr` is in the canonical 48-bit range — i.e. bits
/// 47..63 are all 0 (low half) or all 1 (high half).
pub const fn canonical(vaddr: Word) -> bool {
    let high = vaddr >> 47;
    high == 0 || high == 0x1_FFFF
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_vspace() {
        arch::log("Running vspace tests...\n");
        decompose_user_addr();
        decompose_kernel_addr();
        canonical_check();
        pte_round_trip();
        frame_map_writes_pte();
        frame_map_rejects_alignment();
        frame_map_rejects_double_map();
        arch::log("vspace tests completed\n");
    }

    #[inline(never)]
    fn decompose_user_addr() {
        // Pick a userspace address with distinct nybbles so an
        // off-by-one would fail loudly.
        // PML4=0x12, PDPT=0xAB, PD=0x34, PT=0xCD, off=0x123.
        // 0x12 << 39 | 0xAB << 30 | 0x34 << 21 | 0xCD << 12 | 0x123
        let v: Word = (0x12u64 << 39) | (0xABu64 << 30)
            | (0x34u64 << 21) | (0xCDu64 << 12) | 0x123;
        let i = decompose_vaddr(v);
        assert_eq!(i.pml4, 0x12);
        assert_eq!(i.pdpt, 0xAB);
        assert_eq!(i.pd, 0x34);
        assert_eq!(i.pt, 0xCD);
        assert_eq!(i.offset, 0x123);
        // And recompose round-trips for canonical addresses.
        assert_eq!(compose_vaddr(i), v);
        arch::log("  ✓ decompose_vaddr extracts the 4 indices + offset\n");
    }

    #[inline(never)]
    fn decompose_kernel_addr() {
        // Kernel-half address: high bits set. Indices are the same
        // canonical 9-bit slices.
        let v: Word = 0xFFFF_8000_DEAD_B000;
        let i = decompose_vaddr(v);
        // PML4 = bits 39..47 of 0xFFFF_8000_DEAD_B000 = 0x100.
        assert_eq!(i.pml4, 0x100);
        arch::log("  ✓ decompose_vaddr handles kernel-half addresses\n");
    }

    #[inline(never)]
    fn canonical_check() {
        assert!(canonical(0x0000_0000_DEAD_B000));
        assert!(canonical(0xFFFF_FFFF_DEAD_B000));
        assert!(canonical(0x0000_7FFF_FFFF_FFFF));
        assert!(canonical(0xFFFF_8000_0000_0000));
        // Address with bit 47 set but bits 48..63 zero is NOT canonical.
        assert!(!canonical(0x0000_8000_0000_0000));
        // Address with bit 47 clear but bits 48..63 set is NOT canonical.
        assert!(!canonical(0xFFFF_7FFF_FFFF_FFFF));
        arch::log("  ✓ canonical address check matches Intel SDM\n");
    }

    #[inline(never)]
    fn pte_round_trip() {
        // Build a PTE for a user-rw frame at 0x1000_0000 with
        // writeback caching, no-execute set.
        let pte = make_pte(0x1000_0000, VmRights::UserRW, CacheAttr::Writeback, false);
        assert_eq!(pte.present(), 1);
        assert_eq!(pte.read_write(), 1);
        assert_eq!(pte.super_user(), 1);
        assert_eq!(pte.xd(), 1);
        // Page base stored as paddr >> 12.
        assert_eq!(pte.page_base_address(), 0x1000_0000 >> 12);
        // Cache attr is Writeback → all three bits 0.
        assert_eq!(pte.pat(), 0);
        assert_eq!(pte.cache_disabled(), 0);
        assert_eq!(pte.write_through(), 0);
        arch::log("  ✓ make_pte round-trips through the bitfield encoding\n");
    }

    #[inline(never)]
    fn frame_map_writes_pte() {
        let mut pt = [Pte::zeroed(); ENTRIES_PER_TABLE];
        let vaddr: Word = 0x0000_1234_5678_9000;
        let paddr: Word = 0x0000_0000_4000_0000;
        frame_map_4k(&mut pt, vaddr, paddr, VmRights::UserRW, CacheAttr::Writeback, true)
            .unwrap();
        let idx = decompose_vaddr(vaddr).pt as usize;
        assert_eq!(pt[idx].present(), 1);
        assert_eq!(pt[idx].page_base_address(), paddr >> 12);
        // Other entries untouched.
        let other = (idx + 1) % ENTRIES_PER_TABLE;
        assert_eq!(pt[other].present(), 0);
        // Unmap clears the slot.
        frame_unmap_4k(&mut pt, vaddr);
        assert_eq!(pt[idx].present(), 0);
        arch::log("  ✓ frame_map_4k writes PTE at the expected slot\n");
    }

    #[inline(never)]
    fn frame_map_rejects_alignment() {
        let mut pt = [Pte::zeroed(); ENTRIES_PER_TABLE];
        // vaddr unaligned.
        assert_eq!(
            frame_map_4k(&mut pt, 0x1001, 0x2000, VmRights::UserRW, CacheAttr::Writeback, true),
            Err(MapError::AlignmentError),
        );
        // paddr unaligned.
        assert_eq!(
            frame_map_4k(&mut pt, 0x1000, 0x2008, VmRights::UserRW, CacheAttr::Writeback, true),
            Err(MapError::AlignmentError),
        );
        // Non-canonical vaddr.
        assert_eq!(
            frame_map_4k(&mut pt, 0x0000_8000_0000_0000, 0x2000, VmRights::UserRW, CacheAttr::Writeback, true),
            Err(MapError::OutOfRange),
        );
        arch::log("  ✓ frame_map_4k rejects unaligned and non-canonical addrs\n");
    }

    #[inline(never)]
    fn frame_map_rejects_double_map() {
        let mut pt = [Pte::zeroed(); ENTRIES_PER_TABLE];
        let vaddr: Word = 0x1000;
        frame_map_4k(&mut pt, vaddr, 0x2000, VmRights::UserRW, CacheAttr::Writeback, true)
            .unwrap();
        assert_eq!(
            frame_map_4k(&mut pt, vaddr, 0x3000, VmRights::UserRW, CacheAttr::Writeback, true),
            Err(MapError::AlreadyMapped),
        );
        arch::log("  ✓ frame_map_4k rejects double-map without unmap first\n");
    }
}
