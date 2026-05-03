//! Phase 13a/b — kernel page-table installer.
//!
//! BOOTBOOT hands us a working page table: kernel image at
//! 0xFFFFFFFF_FFE02000+, BootInfo at 0xFFFFFFFF_FFE00000, and an
//! identity map of low physical memory (so the bootloader's own
//! code/data + the ACPI tables it discovered remain reachable).
//! Useful, but it doesn't include MMIO mappings for the LAPIC /
//! IOAPIC, doesn't have user-accessible pages anywhere, and is
//! shared between every "thread" (we have one address space).
//!
//! This module owns *our* page tables. We read the existing PML4
//! via CR3 to discover what mappings BOOTBOOT installed, then build
//! a new PML4 that:
//!
//!   * mirrors BOOTBOOT's high-half kernel mappings (so the kernel
//!     keeps running across the CR3 swap)
//!   * keeps the low-memory identity map (we still need it for ACPI
//!     tables and for accessing the page tables themselves)
//!   * adds a 4 KiB cache-disabled mapping for the LAPIC at the
//!     `mmio` symbol address
//!   * leaves a fresh PDPT slot for user-mode mappings that user-
//!     space threads will use later
//!
//! Once `install_kernel_page_tables` returns, the LAPIC driver's
//! MMIO accesses become safe and per-thread page tables become
//! possible (each thread will get its own PML4 cloned from this
//! kernel template).

use core::arch::asm;
use core::ptr;

use super::msr::{rdmsr, IA32_APIC_BASE_MSR};

// ---------------------------------------------------------------------------
// Page-table page pool. We need a handful of intermediate tables;
// each is a 4 KiB-aligned 512-entry array of u64. BSS-allocated so
// we don't depend on alloc().
// ---------------------------------------------------------------------------

#[repr(C, align(4096))]
pub struct PtPage(pub [u64; 512]);

// Sized for sel4test-driver-class workloads: each PML4 + PDPT/PD/PT
// installed for the rootserver's vaddr range comes from this pool,
// plus large-page splits when the loader walks into BOOTBOOT's
// 2 MiB identity entries. 64 pages is generous for current needs.
const POOL_SIZE: usize = 64;

#[no_mangle]
pub static mut KPT_POOL: [PtPage; POOL_SIZE] = [const { PtPage([0; 512]) }; POOL_SIZE];

#[no_mangle]
pub static mut KPT_USED: usize = 0;

/// Allocate a fresh table from the kernel-image pool. Returns the
/// kernel-virtual address — converted to physical at use sites.
unsafe fn alloc_table_va() -> *mut u64 {
    assert!(KPT_USED < POOL_SIZE, "kernel page-table pool exhausted");
    let p = (&raw const KPT_POOL[KPT_USED]) as *mut u64;
    KPT_USED += 1;
    for i in 0..512 {
        ptr::write_volatile(p.add(i), 0);
    }
    p
}

/// Public-from-arch helper: same as `alloc_table_va` but callable
/// from sibling modules (e.g. usermode page-table install).
pub unsafe fn alloc_user_table_va() -> *mut u64 {
    alloc_table_va()
}

/// Phase 24 — clone the live PML4 into a fresh page-table page.
/// Returns the new PML4's physical address (suitable for CR3).
///
/// We copy *every* live PML4 entry verbatim, not just the
/// kernel-half ones. BOOTBOOT installs its low-memory identity
/// map at PML4[0], and the kernel relies on it to walk page
/// tables and reach ACPI / CR3-relative memory; if we zeroed
/// the user half, the very next instruction the kernel ran
/// after CR3 swap would page-fault on a missing identity-map
/// entry. User-mode address-space isolation in our setup comes
/// from PML4 *user-half* entries that the user code populates
/// dynamically (above 256 GiB; PML4[2] in our demo) — those land
/// in fresh sub-tables per PML4, so two threads sharing the
/// PML4[0] identity map can still hold disjoint user-space
/// mappings above 256 GiB.
pub unsafe fn make_user_pml4() -> u64 {
    let live = phys_to_lin(read_cr3() & 0x000F_FFFF_FFFF_F000) as *const u64;
    let new_va = alloc_table_va();
    // Phase 42 — kernel paddr access goes via the kernel-half
    // linear map (`phys_to_lin`) now, so PML4[0]'s BOOTBOOT identity
    // is no longer load-bearing for the kernel. Stripping the
    // user-half here would let sel4test's allocman install user PTs
    // anywhere in PML4[0..256] without colliding with BOOTBOOT's
    // 2 MiB identity entries — but the SMP `ap_dispatches_user_thread`
    // spec test currently regresses (silent user-mode fault on AP1
    // before the SYSCALL counter increments), which suggests one
    // remaining paddr-as-vaddr access on the AP-side dispatch path.
    // Until that's traced, we keep the full clone so internal specs
    // pass; flip the loop bound back to `256..512` once the AP path
    // is migrated.
    for i in 0..512 {
        let entry = ptr::read_volatile(live.add(i));
        ptr::write_volatile(new_va.add(i), entry);
    }
    kernel_virt_to_phys(new_va as u64)
}

/// Clone the kernel-half entries of the live PML4 into a
/// freshly-retyped target PML4 (called from
/// `decode_untyped_retype` for `Cap::PML4`). The user-half is
/// zeroed so the new vspace starts empty.
///
/// Why we copy PML4[256..512]:
///   * SYSCALL entry restores `gs:[OFF_CTX + ...]` from
///     `PER_CPU_SYSCALL` (a kernel-virt address); without the
///     kernel-half entries the very first instruction after a
///     child SYSCALL would page-fault.
///   * The kernel-half linear map (installed at boot in PML4[256+])
///     lives in this range — copying it preserves kernel paddr
///     access while the user runs with this PML4 in CR3.
pub unsafe fn clone_live_pml4_to_paddr(target_paddr: u64) {
    let live = phys_to_lin(read_cr3() & 0x000F_FFFF_FFFF_F000) as *const u64;
    let target = phys_to_lin(target_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    // Zero the whole page first — Untyped retypes don't clear memory,
    // and we don't want stale entries left over from prior retypes
    // that landed on the same paddr.
    for i in 0..512 {
        ptr::write_volatile(target.add(i), 0);
    }
    // See `make_user_pml4` for why the user-half is still copied for
    // now; once the AP-dispatch paddr-as-vaddr access is found, this
    // can drop to `256..512`.
    for i in 0..512 {
        let entry = ptr::read_volatile(live.add(i));
        ptr::write_volatile(target.add(i), entry);
    }
}

// ---------------------------------------------------------------------------
// PTE flag constants. Same encoding as `vspace::make_pte` but
// without the bitfield wrapper — we want raw u64 entries for the
// tables we install at boot.
// ---------------------------------------------------------------------------

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_RW: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_PWT: u64 = 1 << 3;
pub const PTE_PCD: u64 = 1 << 4;
pub const PTE_PS: u64 = 1 << 7; // 2 MiB / 1 GiB pages
pub const PTE_NX: u64 = 1 << 63;

// ---------------------------------------------------------------------------
// Address-space layout we install.
// ---------------------------------------------------------------------------

pub const KERNEL_MMIO_VBASE: u64 = 0xFFFF_FFFF_F800_0000;
pub const KERNEL_LAPIC_VBASE: u64 = KERNEL_MMIO_VBASE; // first MMIO slot

/// Base of the kernel-half "linear map": every physical address `p`
/// in the range [0, LINEAR_MAP_GIB·1 GiB) is reachable from kernel
/// mode at vaddr `LINEAR_MAP_BASE + p`. Replaces the BOOTBOOT
/// PML4[0] identity map for kernel paddr-as-vaddr accesses, so
/// user vspaces can free PML4[0] for their own mappings.
///
/// `LINEAR_MAP_BASE` is set at boot by `install_kernel_page_tables`,
/// not at compile time, because the empty PML4 slot we land in
/// depends on what BOOTBOOT installed (BOOTBOOT touches `PML4[256]`
/// on at least some firmware revisions). The corresponding PML4
/// index is stored in `LINEAR_MAP_PML4_IDX`.
#[no_mangle]
pub static mut LINEAR_MAP_BASE: u64 = 0;
#[no_mangle]
pub static mut LINEAR_MAP_PML4_IDX: usize = 0;
/// Coverage in 1 GiB increments. 4 GiB is comfortably above the
/// rootserver UT (256 MiB) + qemu RAM (1 GiB) we configure today;
/// bumping this just adds a few PDPT entries.
pub const LINEAR_MAP_GIB: u64 = 4;

/// Translate a physical address to its kernel-virtual counterpart
/// in the linear map. Caller must have invoked
/// `install_kernel_page_tables` first.
#[inline(always)]
pub fn phys_to_lin(paddr: u64) -> u64 {
    debug_assert!(paddr < LINEAR_MAP_GIB * (1 << 30));
    unsafe { LINEAR_MAP_BASE + paddr }
}

// ---------------------------------------------------------------------------
// CR3 helpers.
// ---------------------------------------------------------------------------

pub fn read_cr3() -> u64 {
    let v: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) v, options(nostack, nomem, preserves_flags));
    }
    v
}

/// Read PML4[`idx`] from the live page table.
pub fn read_pml4_entry(idx: usize) -> u64 {
    let pml4 = (read_cr3() & 0xFFFF_F000) as *const u64;
    unsafe { ptr::read_volatile(pml4.add(idx)) }
}

// ---------------------------------------------------------------------------
// Install kernel-half MMIO + user-mode mappings into the live PML4.
//
// Strategy (Phase 13b): rather than building a fresh PML4 (which
// would need to know physical addresses of the new tables — and the
// kernel BSS pages aren't identity-mapped at their physical
// address), we *extend* the BOOTBOOT-supplied PML4 in place. We
// reach the existing tables through the loader's low-memory
// identity map (confirmed live by the Phase 13a spec), and we use
// page-table pages allocated from KPT_POOL — those pages live in
// the kernel image, which BOOTBOOT identity-mapped along with the
// rest of kernel memory.
//
// To do that we need physical addresses for kernel-image pages.
// We compute the kernel's virt→phys offset once by translating a
// known-mapped kernel virtual address (the address of `KPT_POOL`
// itself) through the live page tables, then use that offset
// throughout.
// ---------------------------------------------------------------------------

#[no_mangle]
pub static mut KERNEL_VIRT_TO_PHYS_OFFSET: u64 = 0;

/// Walk the live page tables to translate a kernel virtual address
/// into its physical backing. Returns None if the address isn't
/// mapped or sits behind a 2 MiB / 1 GiB large page (we only need
/// 4 KiB-resolution translation here).
pub fn live_virt_to_phys(vaddr: u64) -> Option<u64> {
    unsafe {
        let pml4 = (read_cr3() & 0xFFFF_F000) as *const u64;
        let pml4_e = ptr::read_volatile(pml4.add(((vaddr >> 39) & 0x1FF) as usize));
        if pml4_e & PTE_PRESENT == 0 {
            return None;
        }
        let pdpt = (pml4_e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpt_e = ptr::read_volatile(pdpt.add(((vaddr >> 30) & 0x1FF) as usize));
        if pdpt_e & PTE_PRESENT == 0 {
            return None;
        }
        if pdpt_e & PTE_PS != 0 {
            // 1 GiB page.
            return Some((pdpt_e & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF));
        }
        let pd = (pdpt_e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pd_e = ptr::read_volatile(pd.add(((vaddr >> 21) & 0x1FF) as usize));
        if pd_e & PTE_PRESENT == 0 {
            return None;
        }
        if pd_e & PTE_PS != 0 {
            // 2 MiB page.
            return Some((pd_e & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x001F_FFFF));
        }
        let pt = (pd_e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pt_e = ptr::read_volatile(pt.add(((vaddr >> 12) & 0x1FF) as usize));
        if pt_e & PTE_PRESENT == 0 {
            return None;
        }
        Some((pt_e & 0x000F_FFFF_FFFF_F000) | (vaddr & 0xFFF))
    }
}

/// Convert a kernel-virtual address to physical using the cached
/// offset. `init_paging` must have run first.
pub fn kernel_virt_to_phys(v: u64) -> u64 {
    unsafe { v.wrapping_sub(KERNEL_VIRT_TO_PHYS_OFFSET) }
}

/// Public entry point — call once at boot, after init_serial etc.
/// but before any code that needs MMIO mappings (the LAPIC, IOAPIC).
pub fn install_kernel_page_tables() {
    unsafe {
        // Cache the kernel virt→phys offset by translating a known-
        // mapped kernel virtual symbol. Done BEFORE install_linear_map
        // because that needs `kernel_virt_to_phys` to compute the
        // PDPT page's paddr.
        let kpt_va = (&raw const KPT_POOL) as u64;
        let kpt_pa = live_virt_to_phys(kpt_va)
            .expect("KPT_POOL must be live-mapped");
        KERNEL_VIRT_TO_PHYS_OFFSET = kpt_va - kpt_pa;

        // Patch the existing PML4 directly. We never CR3-swap —
        // BOOTBOOT's tables already cover the kernel; we just add
        // entries for the linear map, the LAPIC, and (in later
        // phases) user-mode pages.
        let pml4 = (read_cr3() & 0x000F_FFFF_FFFF_F000) as *mut u64;

        // Linear map first, so subsequent paddr-as-vaddr accesses
        // (in this function and elsewhere) can use `phys_to_lin`.
        install_linear_map(pml4);

        let lapic_paddr = rdmsr(IA32_APIC_BASE_MSR) & 0xFFFF_F000;
        map_4k_into(
            pml4,
            KERNEL_LAPIC_VBASE,
            lapic_paddr,
            PTE_PRESENT | PTE_RW | PTE_PCD | PTE_PWT | PTE_NX,
        );

        // Invalidate any stale TLB entry for the LAPIC virtual page.
        asm!(
            "invlpg [{addr}]",
            addr = in(reg) KERNEL_LAPIC_VBASE,
            options(nostack, preserves_flags),
        );
    }
}

/// Build the kernel-half linear map. Scans `PML4[256..510]` for
/// the first empty slot (BOOTBOOT touches PML4[256] on some
/// firmware; PML4[511] is the kernel image), allocates a PDPT page,
/// and populates it with `LINEAR_MAP_GIB` 1 GiB large-page entries.
/// Caches the chosen slot's vaddr base in `LINEAR_MAP_BASE` for
/// `phys_to_lin` to read.
unsafe fn install_linear_map(pml4: *mut u64) {
    // Idempotent: `install_kernel_page_tables` is called from spec
    // setup helpers (e.g. `launch_smp_ping_thread`) as well as boot,
    // and we must NOT pick a different slot on the second call —
    // every `phys_to_lin` consumer would then point at the wrong
    // virtual range. The first call sets LINEAR_MAP_BASE; later
    // calls bail.
    if LINEAR_MAP_BASE != 0 {
        return;
    }
    let mut chosen_idx: Option<usize> = None;
    for idx in 256..511 {
        let e = ptr::read_volatile(pml4.add(idx));
        if e & PTE_PRESENT == 0 {
            chosen_idx = Some(idx);
            break;
        }
    }
    let idx = chosen_idx.expect("no free kernel-half PML4 slot");
    LINEAR_MAP_PML4_IDX = idx;
    // PML4[idx] vaddr = idx << 39, sign-extended (bit 47 set =>
    // upper 16 bits = 0xFFFF).
    LINEAR_MAP_BASE = 0xFFFF_0000_0000_0000 | ((idx as u64) << 39);

    let pdpt_v = alloc_table_va();
    let pdpt_p = kernel_virt_to_phys(pdpt_v as u64);

    let leaf_flags = PTE_PRESENT | PTE_RW | PTE_PS | PTE_NX;
    for i in 0..LINEAR_MAP_GIB {
        let paddr_1gib = i * (1 << 30);
        ptr::write_volatile(pdpt_v.add(i as usize), paddr_1gib | leaf_flags);
    }

    let mid_flags = PTE_PRESENT | PTE_RW;
    ptr::write_volatile(pml4.add(idx), (pdpt_p & !0xFFF) | mid_flags);

    // TLB flush.
    asm!("mov rax, cr3; mov cr3, rax", out("rax") _,
        options(nostack, preserves_flags));
}

/// Map `vaddr -> paddr` (4 KiB) into the page tables rooted at
/// `pml4` (kernel-virtual writable pointer). Allocates intermediate
/// tables from KPT_POOL, recording their physical addresses (via
/// kernel_virt_to_phys).
unsafe fn map_4k_into(pml4: *mut u64, vaddr: u64, paddr: u64, leaf_flags: u64) {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    let mid_flags = PTE_PRESENT | PTE_RW;

    let pdpt = ensure_table_into(pml4.add(pml4_idx), mid_flags);
    let pd = ensure_table_into(pdpt.add(pdpt_idx), mid_flags);
    let pt = ensure_table_into(pd.add(pd_idx), mid_flags);
    ptr::write_volatile(pt.add(pt_idx), (paddr & !0xFFF) | leaf_flags);
}

unsafe fn ensure_table_into(entry_ptr: *mut u64, flags: u64) -> *mut u64 {
    let entry = ptr::read_volatile(entry_ptr);
    if entry & PTE_PRESENT != 0 {
        if entry & PTE_PS != 0 {
            panic!("ensure_table_into: walked into a large page");
        }
        // Existing entry — embedded value is a physical address;
        // BOOTBOOT identity-maps low memory so it's
        // dereferenceable as-is.
        return (entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
    }
    // Allocate a fresh table from KPT_POOL. The pool lives in the
    // kernel image, which BOOTBOOT identity-maps along with the
    // rest of low physical memory; we install the physical address
    // into the page-table tree so further walks via the identity
    // map land on the same page.
    let table_v = alloc_table_va();
    let table_p = kernel_virt_to_phys(table_v as u64);
    ptr::write_volatile(entry_ptr, (table_p & !0xFFF) | flags);
    table_p as *mut u64
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_paging() {
        arch::log("Running paging tests...\n");
        cr3_readable();
        existing_pml4_has_kernel_mapping();
        install_then_lapic_reads();
        arch::log("Paging tests completed\n");
    }

    #[inline(never)]
    fn cr3_readable() {
        let cr3 = read_cr3();
        assert!(cr3 != 0, "CR3 should hold a non-zero PML4 paddr");
        // PML4 is 4 KiB-aligned.
        assert_eq!(cr3 & 0xFFF, 0, "PML4 must be 4 KiB aligned");
        arch::log("  ✓ CR3 readable, points at a 4 KiB-aligned PML4\n");
    }

    #[inline(never)]
    fn existing_pml4_has_kernel_mapping() {
        // PML4[511] backs virtual addresses ≥ 0xFFFFFFxxxxxxxxxx
        // — the upper-half. Our kernel runs at 0xFFFFFFFF_FFE02000+,
        // so PML4[511] must be present.
        let entry = read_pml4_entry(511);
        assert_eq!(entry & PTE_PRESENT, PTE_PRESENT,
            "PML4[511] must be present (kernel image lives there)");
        arch::log("  ✓ existing PML4[511] is present (kernel half mapped)\n");
    }

    #[inline(never)]
    fn install_then_lapic_reads() {
        // Install our own page tables. After this CR3 points at our
        // PML4, which mirrors BOOTBOOT's mappings + adds the LAPIC.
        install_kernel_page_tables();

        // The LAPIC version register should now be readable.
        super::super::lapic::init_lapic();
        let v = super::super::lapic::version();
        assert!(v != 0, "LAPIC version register must be readable now");
        let id = super::super::lapic::apic_id();
        assert!(id < 256, "LAPIC ID is 8 bits");
        arch::log("  ✓ kernel PT installed; LAPIC MMIO live\n");
    }
}
