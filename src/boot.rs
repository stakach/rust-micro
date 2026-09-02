//! Phase 11c — kernel boot and rootserver placement.
//!
//! Mirrors the parts of `seL4/src/kernel/boot.c` that don't touch
//! the C kernel's globals: memory-region discovery, reserved-region
//! carving, rootserver placement.
//!
//! The real boot.c does much more — populate the BootInfo frame,
//! create initial caps, hand control to the init thread. That's
//! the next phase. This commit lands the algorithmic core with the
//! Simpleboot memory-map adapter so the bring-up has a foundation.

use crate::region::{align_down, align_up, PRegion};

// ---------------------------------------------------------------------------
// Memory-map representation. Independent of Simpleboot so the algorithm
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

pub const MAX_BOOT_MMAP_ENTRIES: usize = 240;
pub const MAX_FREEMEM_REGIONS: usize = 128;
pub const MAX_RESERVED_REGIONS: usize = 128;

#[derive(Copy, Clone, Debug)]
pub struct RegionList {
    pub entries: [PRegion; MAX_FREEMEM_REGIONS],
    pub len: usize,
}

impl Default for RegionList {
    fn default() -> Self {
        Self::new()
    }
}

impl RegionList {
    pub const fn new() -> Self {
        Self {
            entries: [PRegion { start: 0, end: 0 }; MAX_FREEMEM_REGIONS],
            len: 0,
        }
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
    if layout.tcb_size_bits > m {
        m = layout.tcb_size_bits;
    }
    if layout.page_bits > m {
        m = layout.page_bits;
    }
    if layout.paging_bits > m {
        m = layout.paging_bits;
    }
    m
}

fn layout_at(base: u64, layout: &RootserverLayout) -> RootserverMem {
    let mut p = base;
    let cnode = p;
    p += 1u64 << layout.cnode_size_bits;
    let tcb = p;
    p += 1u64 << layout.tcb_size_bits;
    let ipc_buf = p;
    p += 1u64 << layout.page_bits;
    let boot_info = p;
    p += 1u64 << layout.page_bits;
    let paging_start = p;
    p += 1u64 << layout.paging_bits;
    let paging_end = p;
    RootserverMem {
        cnode,
        tcb,
        ipc_buf,
        boot_info,
        paging_start,
        paging_end,
    }
}

// ---------------------------------------------------------------------------
// Simpleboot memory-map adapter. Walks the Multiboot2 memory-map tag
// and converts each entry into a `MemEntry`.
// ---------------------------------------------------------------------------

pub fn read_simpleboot_mmap(out: &mut [MemEntry]) -> usize {
    const EFI_MEMORY_MAPPED_IO: u32 = 11;
    const EFI_MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;

    let mut count = 0usize;
    crate::simpleboot::for_each_mmap_entry(|entry| {
        if count >= out.len() {
            return;
        }
        let kind = match entry.entry_type {
            crate::simpleboot::MULTIBOOT_MEMORY_AVAILABLE => MemKind::Free,
            crate::simpleboot::MULTIBOOT_MEMORY_ACPI_RECLAIMABLE
            | crate::simpleboot::MULTIBOOT_MEMORY_NVS => MemKind::Acpi,
            _ if entry.reserved == EFI_MEMORY_MAPPED_IO
                || entry.reserved == EFI_MEMORY_MAPPED_IO_PORT_SPACE =>
            {
                MemKind::Mmio
            }
            _ => MemKind::Used,
        };
        let Some(end) = entry.base_addr.checked_add(entry.length) else {
            return;
        };
        out[count] = MemEntry {
            region: PRegion::new(entry.base_addr, end),
            kind,
        };
        count += 1;
    });
    count
}

fn reserve_simpleboot_allocations(free: &mut RegionList) -> Result<(), BootError> {
    if let Some((start, end)) = crate::simpleboot::mbi_region() {
        reserve_page_range(free, start, end)?;
    }

    let mut err = None;
    crate::simpleboot::for_each_module_region(|start, end| {
        if err.is_none() {
            err = reserve_page_range(free, start, end).err();
        }
    });
    if let Some(e) = err {
        return Err(e);
    }

    crate::simpleboot::for_each_kernel_region(|start, end| {
        if err.is_none() {
            err = reserve_page_range(free, start, end).err();
        }
    });
    if let Some(e) = err {
        return Err(e);
    }

    #[cfg(target_arch = "x86_64")]
    reserve_live_page_tables(free)?;
    Ok(())
}

fn reserve_page_range(free: &mut RegionList, start: u64, end: u64) -> Result<(), BootError> {
    if end <= start {
        return Ok(());
    }
    reserve(free, PRegion::new(align_down(start, 12), align_up(end, 12)))
}

#[cfg(target_arch = "x86_64")]
fn reserve_live_page_tables(free: &mut RegionList) -> Result<(), BootError> {
    const PTE_PADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    unsafe fn walk(free: &mut RegionList, table_paddr: u64, level: u8) -> Result<(), BootError> {
        const PTE_PRESENT: u64 = 1 << 0;
        const PTE_PS: u64 = 1 << 7;
        const PTE_PADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

        let table = table_paddr as *const u64;
        for i in 0..512 {
            let entry = core::ptr::read_volatile(table.add(i));
            if entry & PTE_PRESENT == 0 {
                continue;
            }
            if level <= 3 && entry & PTE_PS != 0 {
                continue;
            }
            let child = entry & PTE_PADDR_MASK;
            if child == 0 {
                continue;
            }
            reserve_page_range(free, child, child + 4096)?;
            let child_level = level - 1;
            if child_level > 1 {
                walk(free, child, child_level)?;
            }
        }
        Ok(())
    }

    let root = crate::arch::x86_64::paging::read_cr3() & PTE_PADDR_MASK;
    reserve_page_range(free, root, root + 4096)?;
    unsafe { walk(free, root, 4) }
}

// ---------------------------------------------------------------------------
// Top-level boot orchestration. Mirrors the high-level shape of
// seL4's `init_kernel()`: read the loader's memory map, build the
// free + reserved-region lists, place the rootserver. Userspace
// launch and BootInfo population follow once we have the page-table
// installer.
// ---------------------------------------------------------------------------

pub fn kernel_init() -> Result<RootserverMem, BootError> {
    use crate::arch;

    arch::log("boot: reading Simpleboot memory map\n");
    let mut entries = [MemEntry {
        region: PRegion::new(0, 0),
        kind: MemKind::Used,
    }; MAX_BOOT_MMAP_ENTRIES];
    let n = read_simpleboot_mmap(&mut entries);
    arch::log("boot:   ");
    log_count(n);
    arch::log(" map entries\n");

    let mut free = extract_free(&entries[..n])?;
    reserve_simpleboot_allocations(&mut free)?;
    arch::log("boot: free regions after sort+coalesce: ");
    log_count(free.len);
    arch::log("\n");

    let layout = RootserverLayout::default_x86_64();
    let mem = place_rootserver(&mut free, &layout)?;

    arch::log("boot: rootserver placed:\n");
    arch::log("  cnode @0x");
    log_hex64(mem.cnode);
    arch::log("\n");
    arch::log("  tcb   @0x");
    log_hex64(mem.tcb);
    arch::log("\n");
    arch::log("  ipc   @0x");
    log_hex64(mem.ipc_buf);
    arch::log("\n");
    arch::log("  bi    @0x");
    log_hex64(mem.boot_info);
    arch::log("\n");

    Ok(mem)
}

/// Phase 41 — reserve a contiguous chunk of Simpleboot-identity-
/// mapped low memory for the rootserver loader's user-page
/// allocator. Sized for sel4test-driver-class workloads (~3.9 MiB
/// of LOAD segments + aux). Called before specs run so the
/// rootserver-loader spec can `super::load()` the live initrd ELF.
///
/// Phase 42 — also reserves a separate "rootserver Untyped" region
/// that gets handed to the rootserver as the backing memory of a
/// Cap::Untyped. sel4test's vka allocator carves TCBs / CNodes /
/// frames / page tables out of this; sized large enough to run the
/// full sel4test suite (~64 MiB).
pub fn reserve_user_page_region() -> Result<(), BootError> {
    use crate::arch;

    let mut entries = [MemEntry {
        region: PRegion::new(0, 0),
        kind: MemKind::Used,
    }; MAX_BOOT_MMAP_ENTRIES];
    let n = read_simpleboot_mmap(&mut entries);
    let mut free = extract_free(&entries[..n])?;
    reserve_simpleboot_allocations(&mut free)?;

    const USER_PAGES_SIZE: u64 = 16 * 1024 * 1024;
    // Phase 44 — the VT-d IOMMU's root + context tables live in a small
    // pool sliced off the TOP of the user-pages carve. Bundling it with
    // the 16 MiB user-pages chunk (rather than a separate carve_chunk)
    // is deliberate: a standalone small carve would land in the lowest
    // free region (conventional memory at paddr 0), which is exactly
    // where place_rootserver lays down the rootserver — vtd_init would
    // then zero the rootserver's TCB. The 16 MiB chunk is large enough
    // that it never fits in that low region, so the pool stays clear.
    #[cfg(target_arch = "x86_64")]
    const IOMMU_POOL_SIZE: u64 = 64 * 1024;
    #[cfg(not(target_arch = "x86_64"))]
    const IOMMU_POOL_SIZE: u64 = 0;
    let user_pages_base = carve_chunk(&mut free, USER_PAGES_SIZE + IOMMU_POOL_SIZE, 12)?;

    arch::log("boot: reserved user-pages @0x");
    log_hex64(user_pages_base);
    arch::log("..");
    log_hex64(user_pages_base + USER_PAGES_SIZE);
    arch::log("\n");

    unsafe {
        crate::rootserver::install_user_page_region(user_pages_base, USER_PAGES_SIZE);
    }

    #[cfg(target_arch = "x86_64")]
    {
        let iommu_base = user_pages_base + USER_PAGES_SIZE;
        arch::log("boot: reserved iommu-pool @0x");
        log_hex64(iommu_base);
        arch::log("..");
        log_hex64(iommu_base + IOMMU_POOL_SIZE);
        arch::log("\n");
        unsafe {
            crate::arch::x86_64::iommu::install_iommu_pool(iommu_base, IOMMU_POOL_SIZE);
        }
    }

    #[cfg(feature = "extern-rootserver")]
    {
        let cnode_base = carve_chunk(
            &mut free,
            crate::rootserver::ROOTSERVER_CNODE_BYTES,
            crate::rootserver::ROOTSERVER_CNODE_SIZE_BITS,
        )?;
        arch::log("boot: reserved root-cnode @0x");
        log_hex64(cnode_base);
        arch::log("..");
        log_hex64(cnode_base + crate::rootserver::ROOTSERVER_CNODE_BYTES);
        arch::log("\n");
        unsafe {
            crate::rootserver::install_rootserver_cnode_backing(cnode_base);
        }
    }

    // Phase 42 — backing memory for the rootserver's Untyped cap.
    //
    // This remains a single power-of-two, power-of-two-aligned seL4 Untyped. Size it from the live
    // Simpleboot free map instead of hard-coding the old 256 MiB value: the ReactOS desktop workload
    // now reaches a broader steady-state service/process wave, and the normal QEMU launch gives us
    // enough RAM to hand the rootserver 512 MiB while preserving smaller spec maps.
    let ut_size_bits = choose_rootserver_untyped_size_bits(&free)?;
    let ut_size = 1u64 << ut_size_bits;
    let ut_base = carve_chunk(&mut free, ut_size, ut_size_bits)?;

    arch::log("boot: reserved rootserver-ut @0x");
    log_hex64(ut_base);
    arch::log("..");
    log_hex64(ut_base + ut_size);
    arch::log(" (size_bits=");
    log_count(ut_size_bits as usize);
    arch::log(")\n");

    unsafe {
        crate::rootserver::install_rootserver_untyped(ut_base, ut_size_bits as u8);
    }

    Ok(())
}

const ROOTSERVER_UT_MIN_SIZE_BITS: u32 = 28; // 256 MiB
const ROOTSERVER_UT_TARGET_SIZE_BITS: u32 = 29; // 512 MiB

fn choose_rootserver_untyped_size_bits(free: &RegionList) -> Result<u32, BootError> {
    let mut size_bits = ROOTSERVER_UT_TARGET_SIZE_BITS;
    loop {
        if rootserver_untyped_fits(free, size_bits) {
            return Ok(size_bits);
        }
        if size_bits == ROOTSERVER_UT_MIN_SIZE_BITS {
            break;
        }
        size_bits -= 1;
    }
    Err(BootError::NoSuitableRegion)
}

fn rootserver_untyped_fits(free: &RegionList, size_bits: u32) -> bool {
    let Some(size) = 1u64.checked_shl(size_bits) else {
        return false;
    };
    for i in 0..free.len {
        let f = free.entries[i];
        let base = align_up(f.start, size_bits);
        if base.checked_add(size).map(|e| e <= f.end).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Carve a contiguous chunk of `size` bytes (aligned to `1 << align_bits`)
/// out of the free-region list. Returns the chunk's base paddr and
/// shrinks the free region accordingly. Used by `kernel_init` for
/// out-of-band reservations like the rootserver user-page region.
fn carve_chunk(free: &mut RegionList, size: u64, align_bits: u32) -> Result<u64, BootError> {
    for i in 0..free.len {
        let f = free.entries[i];
        let base = align_up(f.start, align_bits);
        if base.checked_add(size).map(|e| e <= f.end).unwrap_or(false) {
            let chunk_end = base + size;
            // Splice: keep prefix below chunk, suffix above.
            let prefix = PRegion::new(f.start, base);
            let suffix = PRegion::new(chunk_end, f.end);
            free.entries[i] = prefix;
            if !suffix.is_empty() {
                if free.len >= MAX_FREEMEM_REGIONS {
                    return Err(BootError::TooManyRegions);
                }
                let mut j = free.len;
                while j > i + 1 {
                    free.entries[j] = free.entries[j - 1];
                    j -= 1;
                }
                free.entries[i + 1] = suffix;
                free.len += 1;
            }
            if free.entries[i].is_empty() {
                for j in i..(free.len - 1) {
                    free.entries[j] = free.entries[j + 1];
                }
                free.len -= 1;
            }
            return Ok(base);
        }
    }
    Err(BootError::NoSuitableRegion)
}

fn log_count(n: usize) {
    let mut buf = [b'0'; 4];
    let mut v = n;
    let mut i = 4;
    if v == 0 {
        crate::arch::log("0");
        return;
    }
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

fn log_hex64(v: u64) {
    let mut buf = [b'0'; 16];
    for i in 0..16 {
        let nyb = ((v >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nyb < 10 {
            b'0' + nyb
        } else {
            b'a' + (nyb - 10)
        };
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        crate::arch::log(s);
    }
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
        rootserver_untyped_prefers_target_when_available();
        rootserver_untyped_falls_back_to_minimum();
        rootserver_untyped_fails_below_minimum();
        #[cfg(target_arch = "x86_64")]
        simpleboot_mmap_yields_at_least_one_free_region();
        arch::log("Boot tests completed\n");
    }

    fn entry(start: u64, end: u64, kind: MemKind) -> MemEntry {
        MemEntry {
            region: PRegion::new(start, end),
            kind,
        }
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
            other => panic!(
                "expected NoSuitableRegion, got {:?}",
                other.map(|_| ()).err()
            ),
        }
        arch::log("  ✓ place_rootserver fails on insufficient memory\n");
    }

    #[inline(never)]
    fn rootserver_untyped_prefers_target_when_available() {
        let map = [entry(0x10_0000, 0x4010_0000, MemKind::Free)];
        let free = extract_free(&map).unwrap();
        assert_eq!(
            choose_rootserver_untyped_size_bits(&free).unwrap(),
            ROOTSERVER_UT_TARGET_SIZE_BITS
        );
        arch::log("  ✓ rootserver Untyped prefers target size when available\n");
    }

    #[inline(never)]
    fn rootserver_untyped_falls_back_to_minimum() {
        let map = [entry(0x1000_0000, 0x2000_0000, MemKind::Free)];
        let free = extract_free(&map).unwrap();
        assert_eq!(
            choose_rootserver_untyped_size_bits(&free).unwrap(),
            ROOTSERVER_UT_MIN_SIZE_BITS
        );
        arch::log("  ✓ rootserver Untyped falls back to minimum size\n");
    }

    #[inline(never)]
    fn rootserver_untyped_fails_below_minimum() {
        let map = [entry(0x1000_0000, 0x1800_0000, MemKind::Free)];
        let free = extract_free(&map).unwrap();
        assert!(matches!(
            choose_rootserver_untyped_size_bits(&free),
            Err(BootError::NoSuitableRegion)
        ));
        arch::log("  ✓ rootserver Untyped fails below minimum size\n");
    }

    #[inline(never)]
    #[cfg(target_arch = "x86_64")]
    fn simpleboot_mmap_yields_at_least_one_free_region() {
        let mut entries = [MemEntry {
            region: PRegion::new(0, 0),
            kind: MemKind::Used,
        }; 16];
        let n = read_simpleboot_mmap(&mut entries);
        assert!(n > 0, "Simpleboot must report at least one mmap entry");
        let any_free = entries[..n].iter().any(|e| e.kind == MemKind::Free);
        assert!(any_free, "Simpleboot must report at least one free region");
        arch::log("  ✓ Simpleboot mmap parses at least one Free region\n");
    }

    #[inline(never)]
    #[cfg(not(target_arch = "x86_64"))]
    fn simpleboot_mmap_yields_at_least_one_free_region() {}
}
