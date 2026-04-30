//! Phase 11c — kernel boot and rootserver placement.
//!
//! Mirrors the parts of `seL4/src/kernel/boot.c` that don't touch
//! the C kernel's globals: memory-region discovery, reserved-region
//! carving, rootserver placement.
//!
//! The real boot.c does much more — populate the BootInfo frame,
//! create initial caps, hand control to the init thread. That's
//! the next phase. This commit lands the algorithmic core with the
//! BOOTBOOT memory-map adapter so the bring-up has a foundation.

use crate::region::{align_up, PRegion};
use crate::types::seL4_Word as Word;

// ---------------------------------------------------------------------------
// Memory-map representation. Independent of BOOTBOOT so the algorithm
// can be exercised against synthetic maps in specs.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MemKind {
    Free,
    Used,
    Acpi,
    Mmio,
}

#[derive(Copy, Clone, Debug)]
pub struct MemEntry {
    pub region: PRegion,
    pub kind: MemKind,
}

// ---------------------------------------------------------------------------
// Bounded slot-style "vector" — fixed-capacity array used in place of
// alloc::Vec. seL4 sizes these from CONFIG_MAX_NUM_FREEMEM_REG (16
// in upstream); we pick the same default.
// ---------------------------------------------------------------------------

pub const MAX_FREEMEM_REGIONS: usize = 16;
pub const MAX_RESERVED_REGIONS: usize = 16;

#[derive(Copy, Clone, Debug)]
pub struct RegionList {
    pub entries: [PRegion; MAX_FREEMEM_REGIONS],
    pub len: usize,
}

impl Default for RegionList {
    fn default() -> Self { Self::new() }
}

impl RegionList {
    pub const fn new() -> Self {
        Self { entries: [PRegion { start: 0, end: 0 }; MAX_FREEMEM_REGIONS], len: 0 }
    }

    pub fn push(&mut self, r: PRegion) -> Result<(), BootError> {
        if r.is_empty() {
            return Ok(());
        }
        if self.len >= MAX_FREEMEM_REGIONS {
            return Err(BootError::TooManyRegions);
        }
        self.entries[self.len] = r;
        self.len += 1;
        Ok(())
    }

    pub fn as_slice(&self) -> &[PRegion] {
        &self.entries[..self.len]
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum BootError {
    /// The freemem / reserved-region list is full.
    TooManyRegions,
    /// No contiguous free range big enough for the rootserver.
    NoSuitableRegion,
    /// Reserved region overlaps with itself or the existing list in
    /// an unexpected way.
    OverlapInternal,
}

// ---------------------------------------------------------------------------
// Pass 1: extract free regions from a memory map. Mirrors
// `init_freemem` in seL4 — sorts and coalesces adjacent runs.
// ---------------------------------------------------------------------------

pub fn extract_free(map: &[MemEntry]) -> Result<RegionList, BootError> {
    let mut out = RegionList::new();
    for entry in map {
        if entry.kind == MemKind::Free {
            out.push(entry.region)?;
        }
    }
    sort_regions(&mut out);
    coalesce_regions(&mut out);
    Ok(out)
}

fn sort_regions(list: &mut RegionList) {
    // Simple insertion sort — list is small (<= MAX_FREEMEM_REGIONS).
    for i in 1..list.len {
        let key = list.entries[i];
        let mut j = i;
        while j > 0 && list.entries[j - 1].start > key.start {
            list.entries[j] = list.entries[j - 1];
            j -= 1;
        }
        list.entries[j] = key;
    }
}

fn coalesce_regions(list: &mut RegionList) {
    if list.len < 2 {
        return;
    }
    let mut w = 0;
    for r in 1..list.len {
        if list.entries[w].end >= list.entries[r].start {
            // Overlap or touch — merge.
            if list.entries[r].end > list.entries[w].end {
                list.entries[w].end = list.entries[r].end;
            }
        } else {
            w += 1;
            list.entries[w] = list.entries[r];
        }
    }
    list.len = w + 1;
}

// ---------------------------------------------------------------------------
// Pass 2: subtract reserved regions from the free list. Mirrors
// `reserve_region` in seL4 — splits a free region around any
// overlap with a reserved range.
// ---------------------------------------------------------------------------

pub fn reserve(free: &mut RegionList, reserved: PRegion) -> Result<(), BootError> {
    if reserved.is_empty() {
        return Ok(());
    }
    let mut new_list = RegionList::new();
    for i in 0..free.len {
        let f = free.entries[i];
        if !f.overlaps(reserved) {
            new_list.push(f)?;
            continue;
        }
        // Split: keep the prefix below `reserved.start` and the
        // suffix above `reserved.end`, drop anything in between.
        if f.start < reserved.start {
            new_list.push(PRegion::new(f.start, reserved.start))?;
        }
        if f.end > reserved.end {
            new_list.push(PRegion::new(reserved.end, f.end))?;
        }
    }
    *free = new_list;
    Ok(())
}

// ---------------------------------------------------------------------------
// Pass 3: rootserver placement.
//
// The rootserver is a contiguous chunk of physical memory that holds
// the initial CNode, TCB, IPC buffer frame, and BootInfo frame. seL4
// sizes it from a config-driven layout (`rootserver_mem_t`); we
// expose the same layout struct.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default)]
pub struct RootserverMem {
    pub cnode: u64,
    pub tcb: u64,
    pub ipc_buf: u64,
    pub boot_info: u64,
    pub paging_start: u64,
    pub paging_end: u64,
}

#[derive(Copy, Clone, Debug)]
pub struct RootserverLayout {
    /// log2 bytes of the initial root CNode.
    pub cnode_size_bits: u32,
    /// log2 bytes of one TCB.
    pub tcb_size_bits: u32,
    /// log2 bytes of one frame.
    pub page_bits: u32,
    /// log2 bytes for the rootserver's bootstrap paging structures.
    pub paging_bits: u32,
}

impl RootserverLayout {
    pub const fn default_x86_64() -> Self {
        Self {
            cnode_size_bits: 12, // 1 KiB CNode (radix 7) + slack
            tcb_size_bits: crate::object_type::TCB_SIZE_BITS,
            page_bits: 12,
            paging_bits: 12, // one page table for the initial vspace
        }
    }

    pub const fn total_bytes(&self) -> u64 {
        (1u64 << self.cnode_size_bits)
            + (1u64 << self.tcb_size_bits)
            + (1u64 << self.page_bits)   // IPC buffer
            + (1u64 << self.page_bits)   // BootInfo frame
            + (1u64 << self.paging_bits) // initial paging
    }
}

pub fn place_rootserver(
    free: &mut RegionList,
    layout: &RootserverLayout,
) -> Result<RootserverMem, BootError> {
    let total = layout.total_bytes();
    // Find the first free region big enough, respecting CNode
    // alignment (the largest object's alignment).
    let align_bits = max_align_bits(layout);
    for i in 0..free.len {
        let f = free.entries[i];
        let base = align_up(f.start, align_bits);
        if base.checked_add(total).map(|e| e <= f.end).unwrap_or(false) {
            // Carve out the rootserver region from this entry.
            let rs_end = base + total;
            let mem = layout_at(base, layout);
            // Splice the region: keep the prefix and the suffix.
            let prefix = PRegion::new(f.start, base);
            let suffix = PRegion::new(rs_end, f.end);
            // Replace entry i with prefix; insert suffix after.
            free.entries[i] = prefix;
            if !suffix.is_empty() {
                if free.len >= MAX_FREEMEM_REGIONS {
                    return Err(BootError::TooManyRegions);
                }
                let tail = free.len;
                let mut j = tail;
                while j > i + 1 {
                    free.entries[j] = free.entries[j - 1];
                    j -= 1;
                }
                free.entries[i + 1] = suffix;
                free.len += 1;
            }
            // Drop empty prefix.
            if free.entries[i].is_empty() {
                for j in i..(free.len - 1) {
                    free.entries[j] = free.entries[j + 1];
                }
                free.len -= 1;
            }
            return Ok(mem);
        }
    }
    Err(BootError::NoSuitableRegion)
}

fn max_align_bits(layout: &RootserverLayout) -> u32 {
    let mut m = layout.cnode_size_bits;
    if layout.tcb_size_bits > m { m = layout.tcb_size_bits; }
    if layout.page_bits > m { m = layout.page_bits; }
    if layout.paging_bits > m { m = layout.paging_bits; }
    m
}

fn layout_at(base: u64, layout: &RootserverLayout) -> RootserverMem {
    let mut p = base;
    let cnode = p; p += 1u64 << layout.cnode_size_bits;
    let tcb = p; p += 1u64 << layout.tcb_size_bits;
    let ipc_buf = p; p += 1u64 << layout.page_bits;
    let boot_info = p; p += 1u64 << layout.page_bits;
    let paging_start = p; p += 1u64 << layout.paging_bits;
    let paging_end = p;
    RootserverMem { cnode, tcb, ipc_buf, boot_info, paging_start, paging_end }
}

// ---------------------------------------------------------------------------
// BOOTBOOT memory-map adapter. Walks the inline mmap entries that
// follow the BOOTBOOT header and converts each into a `MemEntry`.
// Only run on an x86_64 build.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub fn read_bootboot_mmap(out: &mut [MemEntry]) -> usize {
    use crate::bootboot::*;
    let bootboot = unsafe { &*(BOOTBOOT_INFO as *const BOOTBOOT) };
    // Number of mmap entries = (header size − offset of mmap field) / 16.
    let mmap_offset = core::mem::offset_of!(BOOTBOOT, mmap) as u32;
    let total = (bootboot.size - mmap_offset) / 16;
    let count = (total as usize).min(out.len());
    let base_ptr = &bootboot.mmap as *const MMapEnt;
    for i in 0..count {
        let ent = unsafe { core::ptr::read_unaligned(base_ptr.add(i)) };
        let raw_size = ent.size;
        let kind = match (raw_size & 0xF) as u32 {
            MMAP_FREE => MemKind::Free,
            MMAP_ACPI => MemKind::Acpi,
            MMAP_MMIO => MemKind::Mmio,
            _ => MemKind::Used,
        };
        let bytes = raw_size & !0xF;
        out[i] = MemEntry {
            region: PRegion::new(ent.ptr, ent.ptr + bytes),
            kind,
        };
    }
    count
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_boot() {
        arch::log("Running boot tests...\n");
        extract_filters_to_free_only();
        sort_and_coalesce();
        reserve_splits_around_overlap();
        place_rootserver_carves_region();
        place_rootserver_picks_aligned_address();
        place_rootserver_fails_when_too_small();
        bootboot_mmap_yields_at_least_one_free_region();
        arch::log("Boot tests completed\n");
    }

    fn entry(start: u64, end: u64, kind: MemKind) -> MemEntry {
        MemEntry { region: PRegion::new(start, end), kind }
    }

    #[inline(never)]
    fn extract_filters_to_free_only() {
        let map = [
            entry(0, 0x1000, MemKind::Used),
            entry(0x1000, 0x10000, MemKind::Free),
            entry(0x10000, 0x20000, MemKind::Mmio),
            entry(0x20000, 0x30000, MemKind::Free),
        ];
        let free = extract_free(&map).unwrap();
        assert_eq!(free.len, 2);
        assert_eq!(free.entries[0].start, 0x1000);
        assert_eq!(free.entries[1].start, 0x20000);
        arch::log("  ✓ extract_free keeps only Free entries\n");
    }

    #[inline(never)]
    fn sort_and_coalesce() {
        // Out-of-order with adjacent regions that should merge.
        let map = [
            entry(0x10000, 0x20000, MemKind::Free),
            entry(0x20000, 0x30000, MemKind::Free), // touches → merge
            entry(0x0, 0x5000, MemKind::Free),
        ];
        let free = extract_free(&map).unwrap();
        assert_eq!(free.len, 2);
        assert_eq!(free.entries[0].start, 0x0);
        assert_eq!(free.entries[0].end, 0x5000);
        assert_eq!(free.entries[1].start, 0x10000);
        assert_eq!(free.entries[1].end, 0x30000);
        arch::log("  ✓ sort + coalesce merges adjacent free regions\n");
    }

    #[inline(never)]
    fn reserve_splits_around_overlap() {
        let map = [entry(0, 0x10000, MemKind::Free)];
        let mut free = extract_free(&map).unwrap();
        // Reserve a chunk in the middle.
        reserve(&mut free, PRegion::new(0x4000, 0x6000)).unwrap();
        assert_eq!(free.len, 2);
        assert_eq!(free.entries[0], PRegion::new(0, 0x4000));
        assert_eq!(free.entries[1], PRegion::new(0x6000, 0x10000));
        arch::log("  ✓ reserve splits a free region around the carve\n");
    }

    #[inline(never)]
    fn place_rootserver_carves_region() {
        let map = [entry(0x10_0000, 0x40_0000, MemKind::Free)];
        let mut free = extract_free(&map).unwrap();
        let layout = RootserverLayout::default_x86_64();
        let rs = place_rootserver(&mut free, &layout).unwrap();
        // Rootserver memory got allocated at the start of the
        // region (after alignment).
        assert!(rs.cnode >= 0x10_0000);
        assert_eq!(rs.cnode % (1 << layout.cnode_size_bits), 0);
        // After the carve, the remaining free region picks up where
        // the rootserver ended.
        assert_eq!(free.entries[0].start, rs.paging_end);
        arch::log("  ✓ place_rootserver carves out + leaves suffix free\n");
    }

    #[inline(never)]
    fn place_rootserver_picks_aligned_address() {
        // First region too small; second has slack.
        let map = [
            entry(0x10_0000, 0x10_1000, MemKind::Free),
            entry(0x20_0000, 0x80_0000, MemKind::Free),
        ];
        let mut free = extract_free(&map).unwrap();
        let layout = RootserverLayout::default_x86_64();
        let rs = place_rootserver(&mut free, &layout).unwrap();
        // Falls into the second region.
        assert!(rs.cnode >= 0x20_0000);
        // First (too-small) region untouched in some position.
        let still_present = free.as_slice().iter().any(|r| r.start == 0x10_0000);
        assert!(still_present, "small region should be preserved");
        arch::log("  ✓ place_rootserver skips too-small regions\n");
    }

    #[inline(never)]
    fn place_rootserver_fails_when_too_small() {
        let map = [entry(0x10_0000, 0x10_1000, MemKind::Free)];
        let mut free = extract_free(&map).unwrap();
        let layout = RootserverLayout::default_x86_64();
        match place_rootserver(&mut free, &layout) {
            Err(BootError::NoSuitableRegion) => {}
            other => panic!("expected NoSuitableRegion, got {:?}",
                other.map(|_| ()).err()),
        }
        arch::log("  ✓ place_rootserver fails on insufficient memory\n");
    }

    #[inline(never)]
    #[cfg(target_arch = "x86_64")]
    fn bootboot_mmap_yields_at_least_one_free_region() {
        let mut entries = [MemEntry { region: PRegion::new(0, 0), kind: MemKind::Used }; 16];
        let n = read_bootboot_mmap(&mut entries);
        assert!(n > 0, "BOOTBOOT must report at least one mmap entry");
        let any_free = entries[..n].iter().any(|e| e.kind == MemKind::Free);
        assert!(any_free, "BOOTBOOT must report at least one free region");
        arch::log("  ✓ BOOTBOOT mmap parses at least one Free region\n");
    }

    #[inline(never)]
    #[cfg(not(target_arch = "x86_64"))]
    fn bootboot_mmap_yields_at_least_one_free_region() {}
}
