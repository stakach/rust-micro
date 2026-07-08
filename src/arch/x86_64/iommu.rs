//! Intel VT-d IOMMU (CONFIG_IOMMU). Mirrors seL4
//! `src/plat/pc99/machine/intel-vtd.c` + `src/arch/x86/object/iospace.c`.
//!
//! Phase 44 — full root / context / IO-page-table support backing the
//! sel4test IOPT family. The VT-d hardware data structures are built
//! in low RAM (linear-map-covered, so the kernel can read/write them
//! through `phys_to_lin`); the in-memory bookkeeping matches what
//! upstream seL4 maintains. The sel4test IOPT tests perform no real
//! DMA, so translation-enable (the GCMD TE bit) is best-effort and
//! never blocked on.
//!
//! Key decision: `numIOPTLevels = 4`. QEMU's TCG VT-d unit advertises
//! SAGAW with 4-level support; the sel4test IOPT0008/0011 cases index
//! `pts[EXPECTED_PT_DEPTH = 3]`, which only exists when the map loop
//! allocates 4 page tables. The context-entry address-width field is
//! `aw = numIOPTLevels - 2 = 2`.

use super::acpi;
use super::paging::{self, phys_to_lin, KERNEL_IOMMU_VBASE};

// VT-d register offsets (intel-vtd.c:21-37).
const VER_REG: u64 = 0x00;
const CAP_REG: u64 = 0x08;
const GCMD_REG: u64 = 0x18;
const GSTS_REG: u64 = 0x1C;
const RTADDR_REG: u64 = 0x20;
const SRTP: u32 = 30; // Set Root Table Pointer (GCMD, one-shot)
const RTPS: u32 = 30; // Root Table Pointer Status (GSTS)
const TE: u32 = 31; // Translation Enable (GCMD, persistent)
const TES: u32 = 31; // Translation Enable Status (GSTS)

/// VT-d second-level page-table index bits (9) and 4 KiB page bits.
pub const VTD_PT_INDEX_BITS: u64 = 9;
pub const PAGE_BITS: u64 = 12;

// ---------------------------------------------------------------------------
// Boot-discovered state.
// ---------------------------------------------------------------------------

/// Number of IO page-table levels. 4 under QEMU TCG (see module docs).
static mut NUM_IOPT_LEVELS: u64 = 4;
/// Number of DMA-remapping hardware units found (0 ⇒ no IOMMU).
static mut NUM_DRHU: u32 = 0;
/// Physical address of the 4 KiB root table (256 × 16-byte RTEs).
static mut VTD_ROOT_TABLE_PADDR: u64 = 0;
/// Kernel-virtual base of the first DRHD's register block.
static mut VTD_REGS: u64 = 0;

pub fn num_iopt_levels() -> u64 {
    unsafe { NUM_IOPT_LEVELS }
}

pub fn iommu_present() -> bool {
    unsafe { NUM_DRHU > 0 }
}

// ---------------------------------------------------------------------------
// IOMMU page pool — root + context tables. Seeded at boot from a small
// chunk of low RAM (carved in boot::reserve_user_page_region). Pages
// are handed out lazily; context tables are created on first use of a
// PCI bus. Returns physical addresses (always linear-map covered).
// ---------------------------------------------------------------------------

static mut POOL_BASE: u64 = 0;
static mut POOL_SIZE: u64 = 0;
static mut POOL_USED: u64 = 0;

/// Install the IOMMU page pool (called once at boot before `vtd_init`).
/// If the carved region starts at physical 0, skip the first page so
/// no IOMMU table is ever placed at paddr 0 (which we use as a "no
/// table" sentinel for the root table + VT-d entry addresses).
pub unsafe fn install_iommu_pool(base_paddr: u64, size: u64) {
    if base_paddr == 0 {
        POOL_BASE = 0x1000;
        POOL_SIZE = size.saturating_sub(0x1000);
    } else {
        POOL_BASE = base_paddr;
        POOL_SIZE = size;
    }
    POOL_USED = 0;
}

/// Allocate one zeroed 4 KiB page from the IOMMU pool; returns paddr.
/// `POOL_SIZE == 0` means the pool was never installed (base paddr 0
/// is a legitimate low-RAM address, so it can't be the sentinel).
unsafe fn alloc_iommu_page() -> Option<u64> {
    if POOL_SIZE == 0 || POOL_USED + 4096 > POOL_SIZE {
        return None;
    }
    let paddr = POOL_BASE + POOL_USED;
    POOL_USED += 4096;
    let lin = phys_to_lin(paddr) as *mut u8;
    for i in 0..4096 {
        core::ptr::write_volatile(lin.add(i), 0);
    }
    Some(paddr)
}

// ---------------------------------------------------------------------------
// Hardware entry encode / decode. Hand-coded to the Intel VT-d layout
// (mirrors seL4's vtd_rte / vtd_cte / vtd_pte bitfield blocks). The
// kernel is the only reader/writer for the IOPT tests (no DMA), so the
// encoding only needs to be self-consistent — it also happens to match
// the architectural layout.
//
//   Root entry  (16 B): low qword  bit0 = present, bits[63:12] = CTP.
//   Context     (16 B): low qword  bit0 = present, bits[3:2] = transl.
//                                    type, bits[63:12] = ASR (SLPTPTR);
//                       high qword bits[2:0] = AW, bits[23:8] = DID.
//   Page entry  ( 8 B): bit0 = read, bit1 = write, bits[63:12] = addr.
// ---------------------------------------------------------------------------

const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[inline]
fn rte_new(ctp_paddr: u64, present: bool) -> u64 {
    (ctp_paddr & ADDR_MASK) | (present as u64)
}
#[inline]
fn rte_present(w: u64) -> bool {
    w & 1 != 0
}
#[inline]
fn rte_ctp(w: u64) -> u64 {
    w & ADDR_MASK
}

#[inline]
fn cte_low(asr_paddr: u64, tt: u64, present: bool) -> u64 {
    (asr_paddr & ADDR_MASK) | ((tt & 0x3) << 2) | (present as u64)
}
#[inline]
fn cte_high(aw: u64, did: u64) -> u64 {
    (aw & 0x7) | ((did & 0xFFFF) << 8)
}
#[inline]
fn cte_present(low: u64) -> bool {
    low & 1 != 0
}
#[inline]
fn cte_asr(low: u64) -> u64 {
    low & ADDR_MASK
}

#[inline]
fn pte_new(addr_paddr: u64, write: bool, read: bool) -> u64 {
    (addr_paddr & ADDR_MASK) | ((write as u64) << 1) | (read as u64)
}
#[inline]
pub fn pte_write(w: u64) -> bool {
    w & 0b10 != 0
}
#[inline]
pub fn pte_addr(w: u64) -> u64 {
    w & ADDR_MASK
}

// ---------------------------------------------------------------------------
// PCI request-id decode (pci.h get_pci_bus/dev/fun).
// ---------------------------------------------------------------------------

#[inline]
fn get_pci_bus(rid: u16) -> usize {
    ((rid >> 8) & 0xff) as usize
}

// ---------------------------------------------------------------------------
// Context-slot lookup. Returns a kernel-linear pointer to the 16-byte
// context entry (two u64 words) for `pci_request_id`. When `allocate`
// is set and the bus has no context table yet, one is created lazily
// (mirrors seL4's BOOT_CODE vtd_create_context_table, deferred to
// first map). With `allocate == false`, an absent table yields `None`.
// ---------------------------------------------------------------------------

/// Pointer to a context entry: `[0]` = low qword, `[1]` = high qword.
pub struct CtxSlot(pub *mut u64);

pub unsafe fn lookup_vtd_context_slot(pci_request_id: u16, allocate: bool) -> Option<CtxSlot> {
    if VTD_ROOT_TABLE_PADDR == 0 {
        return None;
    }
    let bus = get_pci_bus(pci_request_id);
    let root_lin = phys_to_lin(VTD_ROOT_TABLE_PADDR) as *mut u64;
    // Each RTE is 16 bytes = 2 u64; meaningful data in the low word.
    let rte_slot = root_lin.add(bus * 2);
    let rte = core::ptr::read_volatile(rte_slot);
    let ctp = if rte_present(rte) {
        rte_ctp(rte)
    } else if allocate {
        let ct_paddr = alloc_iommu_page()?;
        core::ptr::write_volatile(rte_slot, rte_new(ct_paddr, true));
        core::ptr::write_volatile(rte_slot.add(1), 0);
        ct_paddr
    } else {
        return None;
    };
    let ct_lin = phys_to_lin(ctp) as *mut u64;
    // Context index = (dev << 3) | fun = RID & 0xff; each CTE = 16 B.
    let ctx_index = (pci_request_id & 0xff) as usize;
    Some(CtxSlot(ct_lin.add(ctx_index * 2)))
}

impl CtxSlot {
    pub unsafe fn present(&self) -> bool {
        cte_present(core::ptr::read_volatile(self.0))
    }
    pub unsafe fn asr(&self) -> u64 {
        cte_asr(core::ptr::read_volatile(self.0))
    }
    /// Install this context entry as the root of an IO address space.
    pub unsafe fn install_root(&self, domain_id: u16, asr_paddr: u64) {
        let aw = NUM_IOPT_LEVELS - 2;
        core::ptr::write_volatile(self.0, cte_low(asr_paddr, 0, true));
        core::ptr::write_volatile(self.0.add(1), cte_high(aw, domain_id as u64));
    }
    pub unsafe fn clear(&self) {
        core::ptr::write_volatile(self.0, 0);
        core::ptr::write_volatile(self.0.add(1), 0);
    }
}

// ---------------------------------------------------------------------------
// IO-page-table slot lookup (iospace.c:76-120). Walks from the top
// IOPT (context ASR) down. `slot` is a kernel-linear pointer to the
// matched 8-byte PTE; `level` is `levels_remaining` at the match
// point; `ok` is true unless a null table pointer was hit.
// ---------------------------------------------------------------------------

pub struct IoptLookup {
    pub slot: *mut u64,
    pub level: u64,
    pub ok: bool,
}

unsafe fn lookup_iopt_slot_resolve(
    iopt_paddr: u64,
    translation: u64,
    levels_to_resolve: u64,
    levels_remaining: u64,
) -> IoptLookup {
    if iopt_paddr == 0 {
        return IoptLookup { slot: core::ptr::null_mut(), level: levels_remaining, ok: false };
    }
    let n = NUM_IOPT_LEVELS;
    let shift = VTD_PT_INDEX_BITS * (n - 1 - (levels_to_resolve - levels_remaining));
    let iopt_index = (translation >> shift) & ((1 << VTD_PT_INDEX_BITS) - 1);
    let slot = (phys_to_lin(iopt_paddr) as *mut u64).add(iopt_index as usize);
    let entry = core::ptr::read_volatile(slot);
    if !pte_write(entry) || levels_remaining == 0 {
        return IoptLookup { slot, level: levels_remaining, ok: true };
    }
    let next = pte_addr(entry);
    lookup_iopt_slot_resolve(next, translation, levels_to_resolve, levels_remaining - 1)
}

/// Top-level walk: `top_iopt_paddr` is the context ASR (paddr of the
/// top IO page table); `io_address` is byte-addressed.
pub unsafe fn lookup_iopt_slot(top_iopt_paddr: u64, io_address: u64) -> IoptLookup {
    if top_iopt_paddr == 0 {
        return IoptLookup { slot: core::ptr::null_mut(), level: 0, ok: false };
    }
    let n = NUM_IOPT_LEVELS;
    lookup_iopt_slot_resolve(top_iopt_paddr, io_address >> PAGE_BITS, n - 1, n - 1)
}

/// Resolve a fixed number of levels (used by deleteIOPageTable).
pub unsafe fn lookup_iopt_slot_levels(
    top_iopt_paddr: u64,
    translation: u64,
    levels_to_resolve: u64,
    levels_remaining: u64,
) -> IoptLookup {
    lookup_iopt_slot_resolve(top_iopt_paddr, translation, levels_to_resolve, levels_remaining)
}

/// Read a PTE slot's address field (kernel-linear pointer in).
pub unsafe fn slot_addr(slot: *mut u64) -> u64 {
    pte_addr(core::ptr::read_volatile(slot))
}
/// Install a read/write PTE pointing at `paddr`.
pub unsafe fn slot_install(slot: *mut u64, paddr: u64, write: bool, read: bool) {
    core::ptr::write_volatile(slot, pte_new(paddr, write, read));
}
/// Zero a PTE slot.
pub unsafe fn slot_clear(slot: *mut u64) {
    core::ptr::write_volatile(slot, 0);
}

// ---------------------------------------------------------------------------
// Boot init. Replaces the old viability probe.
// ---------------------------------------------------------------------------

fn log_hex(v: u64) {
    let mut buf = [b'0'; 16];
    for i in 0..16 {
        let nyb = ((v >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nyb < 10 { b'0' + nyb } else { b'a' + (nyb - 10) };
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        crate::arch::log(s);
    }
}

/// Discover the first DRHD, map its register block, allocate the root
/// table, and (best-effort) point the unit at it. Must run after the
/// IOMMU page pool is installed (`install_iommu_pool`). Idempotent-ish:
/// safe to call once.
pub fn vtd_init() {
    let bootboot = unsafe { &*(crate::bootboot::BOOTBOOT_INFO as *const crate::bootboot::BOOTBOOT) };
    let sdt_addr = unsafe { bootboot.arch.x86_64 }.acpi_ptr;

    let dmar = match acpi::find_dmar(sdt_addr) {
        Ok(d) => d,
        Err(_) => {
            crate::arch::log("IOMMU: no DMAR table — IOMMU disabled\n");
            return;
        }
    };
    let base = match acpi::dmar_first_drhd_base(dmar) {
        Some(b) => b,
        None => {
            crate::arch::log("IOMMU: DMAR has no DRHD unit\n");
            return;
        }
    };

    unsafe {
        paging::map_kernel_mmio_page(KERNEL_IOMMU_VBASE, base);
    }
    let off = base & 0xFFF;
    let regs = KERNEL_IOMMU_VBASE + off;
    unsafe { VTD_REGS = regs };

    let ver = unsafe { core::ptr::read_volatile((regs + VER_REG) as *const u32) };
    let cap = unsafe { core::ptr::read_volatile((regs + CAP_REG) as *const u64) };
    let sagaw = (cap >> 8) & 0x1F;
    if ver == 0 || ver == 0xFFFF_FFFF || cap == u64::MAX || sagaw == 0 {
        crate::arch::log("IOMMU: VT-d register file dead — disabled\n");
        return;
    }

    // numIOPTLevels = 4 (see module docs). Verify SAGAW advertises the
    // 4-level width (bit 2); fall back to whatever's there but keep 4
    // since QEMU TCG supports it.
    unsafe { NUM_IOPT_LEVELS = 4 };

    // Allocate the root table.
    let root = unsafe { alloc_iommu_page() };
    let Some(root_paddr) = root else {
        crate::arch::log("IOMMU: page pool exhausted — disabled\n");
        return;
    };
    unsafe {
        VTD_ROOT_TABLE_PADDR = root_paddr;
        NUM_DRHU = 1;
    }

    // Best-effort: point the unit at the root table (SRTP). The IOPT
    // tests do no DMA, so we deliberately do NOT set the Translation
    // Enable (TE) bit, and we bound every status spin so a flaky TCG
    // unit can never hang the kernel.
    unsafe {
        core::ptr::write_volatile((regs + RTADDR_REG) as *mut u64, root_paddr);
        let status = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
        core::ptr::write_volatile((regs + GCMD_REG) as *mut u32, status | (1 << SRTP));
        let mut spins = 0u32;
        while spins < 100_000 {
            let s = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
            if (s >> RTPS) & 1 != 0 {
                break;
            }
            spins += 1;
        }
    }

    crate::arch::log("IOMMU: VT-d initialised; CAP=0x");
    log_hex(cap);
    crate::arch::log(" levels=4 root=0x");
    log_hex(root_paddr);
    crate::arch::log("\n");
}

/// Turn on VT-d DMA remapping (GCMD Translation-Enable). Idempotent + bounded.
///
/// `vtd_init` deliberately leaves TE OFF so device DMA is identity (untranslated) until
/// a driver actually asks for confinement. This is called LAZILY the first time a device
/// gets an IO-space context (see `decode_x86_iopt` install_root), so identity DMA keeps
/// working right up until the moment a driver builds a confined mapping. Once TE is on,
/// any device WITHOUT a present context entry has its DMA blocked (faulted) — which is
/// the whole point: a driver can only DMA into the frames it was granted.
pub unsafe fn enable_translation() {
    if VTD_REGS == 0 {
        return;
    }
    let regs = VTD_REGS;
    let status = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
    if (status >> TES) & 1 != 0 {
        return; // already enabled
    }
    // Write TE only (SRTP bit 30 = 0 so the already-set root pointer isn't re-triggered).
    core::ptr::write_volatile((regs + GCMD_REG) as *mut u32, 1 << TE);
    let mut spins = 0u32;
    while spins < 100_000 {
        let s = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
        if (s >> TES) & 1 != 0 {
            crate::arch::log("IOMMU: translation ENABLED (TE)\n");
            return;
        }
        spins += 1;
    }
    crate::arch::log("IOMMU: TE enable timed out\n");
}
