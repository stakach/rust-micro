//! Intel VT-d IOMMU (CONFIG_IOMMU). Mirrors seL4
//! `src/plat/pc99/machine/intel-vtd.c` + `src/arch/x86/object/iospace.c`.
//!
//! VT-d root, context, and IO-page-table support. The hardware data
//! structures are built in low RAM (linear-map-covered, so the kernel
//! can read/write them through `phys_to_lin`). DMA now uses these tables:
//! translation enable and every required invalidation must complete
//! before a mapping or its backing frame can be reused.
//!
//! Key decision: `numIOPTLevels = 4`. The QEMU launcher requests 48-bit
//! VT-d so CAP.SAGAW advertises four-level support; older QEMU defaults to
//! 39-bit/three-level VT-d. The sel4test IOPT0008/0011 cases index
//! `pts[EXPECTED_PT_DEPTH = 3]`, which only exists when the map loop
//! allocates 4 page tables. The context-entry address-width field is
//! `aw = numIOPTLevels - 2 = 2`.

use super::acpi;
use super::paging::{self, phys_to_lin, KERNEL_IOMMU_VBASE};
use core::sync::atomic::{fence, Ordering};

mod domain;
mod retirement;
use domain::{check_domain, domain_count, reserve_domain, retire_owned_domain, MAX_DOMAINS};
use retirement::INVALIDATION_SPINS;
use retirement::{
    context_admits_domain, cte_asr, cte_domain_id, cte_high, cte_low, cte_present,
    invalidate_context_and_iotlb_at, retire_context, retire_leaf, VtdRegisters,
};
pub use retirement::{dma_retirement_phase, retire_last_iopt_alias, DmaRetirementKind, VtdError};

// VT-d register offsets (intel-vtd.c:21-37).
const VER_REG: u64 = 0x00;
const CAP_REG: u64 = 0x08;
const ECAP_REG: u64 = 0x10;
const GCMD_REG: u64 = 0x18;
const GSTS_REG: u64 = 0x1C;
const RTADDR_REG: u64 = 0x20;
const IOTLB_REG: u64 = 0x08;
// Register-based global IOTLB invalidation, with DMA read and write drain.
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
/// Offset of the IOTLB invalidation register, discovered from ECAP.IRO.
static mut VTD_IOTLB_OFFSET: u64 = 0;
/// Exact PCI requester IDs copied from the boot DMAR endpoint scopes.
/// Kernel BSS remains mapped in every user CR3; the ACPI physical pointer does not.
static mut VTD_ALLOWED_RIDS: [u64; 1024] = [0; 1024];
static mut VTD_INCLUDE_ALL_RIDS: bool = false;
/// Exclusive upper bound for domain IDs on the discovered remapping unit.
static mut VTD_DOMAIN_COUNT: usize = 0;
/// BKL-owned domain reservations. Nonzero entries hold the context's requester ID.
static mut VTD_DOMAIN_OWNERS: [u16; MAX_DOMAINS] = [0; MAX_DOMAINS];

#[cold]
pub fn fail_stop(error: VtdError) -> ! {
    panic!("VT-d translation retirement failed: {error:?}")
}

pub fn num_iopt_levels() -> u64 {
    unsafe { NUM_IOPT_LEVELS }
}

pub fn iommu_present() -> bool {
    unsafe { NUM_DRHU > 0 }
}

pub fn iopt_contains_address(level: u8, mapped_address: u64, address: u64) -> bool {
    if level == 0 || level as u64 >= num_iopt_levels() {
        return true;
    }
    let shift = PAGE_BITS + VTD_PT_INDEX_BITS * (num_iopt_levels() - level as u64);
    (mapped_address >> shift) == (address >> shift)
}

/// A copied mapped IOPT cap is an alias of the same hardware edge.
pub fn external_descendant_needs_explicit_unmap(
    owner_cnode: usize,
    descendant_cnode: usize,
    level: u8,
    mapped_address: u64,
    descendant_address: u64,
) -> bool {
    owner_cnode != descendant_cnode
        && iopt_contains_address(level, mapped_address, descendant_address)
}

struct MmioRegisters(u64);

impl VtdRegisters for MmioRegisters {
    fn read64(&mut self, offset: u64) -> u64 {
        unsafe { core::ptr::read_volatile((self.0 + offset) as *const u64) }
    }

    fn write64(&mut self, offset: u64, value: u64) {
        unsafe { core::ptr::write_volatile((self.0 + offset) as *mut u64, value) }
    }
}

/// Register-based invalidation is available only while queued invalidation is off.
/// Global granularity is deliberately used: the kernel currently discovers one
/// DRHD and does not have a hardware-scope-to-requester index.
unsafe fn invalidation_regs() -> Result<(u64, u64), VtdError> {
    let regs = VTD_REGS;
    let iotlb = VTD_IOTLB_OFFSET;
    if regs == 0 || iotlb == 0 {
        return Err(VtdError::Unavailable);
    }
    // GSTS.QIES: register invalidation is prohibited while the queue is enabled.
    if core::ptr::read_volatile((regs + GSTS_REG) as *const u32) & (1 << 26) != 0 {
        return Err(VtdError::Unavailable);
    }
    Ok((regs, iotlb))
}

/// The caller has already updated a present context entry or a root entry.
/// Intel VT-d requires the context-cache command to finish before the IOTLB
/// command, because cached context information may tag IOTLB entries.
pub unsafe fn invalidate_context_and_iotlb() -> Result<(), VtdError> {
    let (base, iotlb) = invalidation_regs()?;
    fence(Ordering::SeqCst);
    invalidate_context_and_iotlb_at(&mut MmioRegisters(base), iotlb)
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
// (mirrors seL4's vtd_rte / vtd_cte / vtd_pte bitfield blocks).
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

/// Context entry and the requester whose root/context table lookup produced it.
pub struct CtxSlot {
    entry: *mut u64,
    requester: u16,
}

/// Refuse invalid domains and foreign owners before a lazy context-table allocation.
pub unsafe fn check_context_domain(requester: u16, domain_id: u16) -> Result<(), VtdError> {
    if VTD_ROOT_TABLE_PADDR == 0 {
        return Err(VtdError::Unavailable);
    }
    let owners = &*core::ptr::addr_of!(VTD_DOMAIN_OWNERS);
    check_domain(&owners[..VTD_DOMAIN_COUNT], domain_id, requester)
}

pub unsafe fn lookup_vtd_context_slot(pci_request_id: u16, allocate: bool) -> Option<CtxSlot> {
    if VTD_ROOT_TABLE_PADDR == 0 {
        return None;
    }
    let word = (pci_request_id as usize) >> 6;
    let bit = 1u64 << (pci_request_id & 63);
    if !VTD_INCLUDE_ALL_RIDS && VTD_ALLOWED_RIDS[word] & bit == 0 {
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
        core::ptr::write_volatile(rte_slot.add(1), 0);
        core::ptr::write_volatile(rte_slot, rte_new(ct_paddr, true));
        invalidate_context_and_iotlb().unwrap_or_else(|error| fail_stop(error));
        ct_paddr
    } else {
        return None;
    };
    let ct_lin = phys_to_lin(ctp) as *mut u64;
    // Context index = (dev << 3) | fun = RID & 0xff; each CTE = 16 B.
    let ctx_index = (pci_request_id & 0xff) as usize;
    Some(CtxSlot {
        entry: ct_lin.add(ctx_index * 2),
        requester: pci_request_id,
    })
}

impl CtxSlot {
    pub unsafe fn present(&self) -> bool {
        cte_present(core::ptr::read_volatile(self.entry))
    }
    pub unsafe fn asr(&self) -> u64 {
        cte_asr(core::ptr::read_volatile(self.entry))
    }
    /// An existing PCI requester context may only be extended by its installed domain.
    pub unsafe fn matches_domain(&self, domain_id: u16) -> bool {
        let owners = &*core::ptr::addr_of!(VTD_DOMAIN_OWNERS);
        context_admits_domain(
            core::ptr::read_volatile(self.entry),
            core::ptr::read_volatile(self.entry.add(1)),
            domain_id,
        ) && owners[..VTD_DOMAIN_COUNT].get(usize::from(domain_id)) == Some(&self.requester)
    }
    /// Install this context entry as the root of an IO address space.
    pub unsafe fn install_root(&self, domain_id: u16, asr_paddr: u64) -> Result<(), VtdError> {
        if self.present() {
            return Err(VtdError::OwnershipConflict);
        }
        let (base, iotlb) = invalidation_regs()?;
        let owners = &mut *core::ptr::addr_of_mut!(VTD_DOMAIN_OWNERS);
        reserve_domain(&mut owners[..VTD_DOMAIN_COUNT], domain_id, self.requester)?;
        let aw = NUM_IOPT_LEVELS - 2;
        core::ptr::write_volatile(self.entry.add(1), cte_high(aw, domain_id as u64));
        core::ptr::write_volatile(self.entry, cte_low(asr_paddr, 0, true));
        fence(Ordering::SeqCst);
        invalidate_context_and_iotlb_at(&mut MmioRegisters(base), iotlb)
            .unwrap_or_else(|error| fail_stop(error));
        Ok(())
    }
    pub unsafe fn clear(&self) -> Result<(), VtdError> {
        let domain_id = cte_domain_id(core::ptr::read_volatile(self.entry.add(1)));
        let owners = &mut *core::ptr::addr_of_mut!(VTD_DOMAIN_OWNERS);
        retire_owned_domain(&mut owners[..VTD_DOMAIN_COUNT], domain_id, self.requester, || {
            let (base, iotlb) = invalidation_regs()?;
            retire_context(
                &mut MmioRegisters(base),
                iotlb,
                || core::ptr::write_volatile(self.entry, 0),
                || core::ptr::write_volatile(self.entry.add(1), 0),
            )
            .unwrap_or_else(|error| fail_stop(error));
            Ok(())
        })
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
        return IoptLookup {
            slot: core::ptr::null_mut(),
            level: levels_remaining,
            ok: false,
        };
    }
    let n = NUM_IOPT_LEVELS;
    let shift = VTD_PT_INDEX_BITS * (n - 1 - (levels_to_resolve - levels_remaining));
    let iopt_index = (translation >> shift) & ((1 << VTD_PT_INDEX_BITS) - 1);
    let slot = (phys_to_lin(iopt_paddr) as *mut u64).add(iopt_index as usize);
    let entry = core::ptr::read_volatile(slot);
    if !pte_write(entry) || levels_remaining == 0 {
        return IoptLookup {
            slot,
            level: levels_remaining,
            ok: true,
        };
    }
    let next = pte_addr(entry);
    lookup_iopt_slot_resolve(next, translation, levels_to_resolve, levels_remaining - 1)
}

/// Top-level walk: `top_iopt_paddr` is the context ASR (paddr of the
/// top IO page table); `io_address` is byte-addressed.
pub unsafe fn lookup_iopt_slot(top_iopt_paddr: u64, io_address: u64) -> IoptLookup {
    if top_iopt_paddr == 0 {
        return IoptLookup {
            slot: core::ptr::null_mut(),
            level: 0,
            ok: false,
        };
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
    lookup_iopt_slot_resolve(
        top_iopt_paddr,
        translation,
        levels_to_resolve,
        levels_remaining,
    )
}

/// Read a PTE slot's address field (kernel-linear pointer in).
pub unsafe fn slot_addr(slot: *mut u64) -> u64 {
    pte_addr(core::ptr::read_volatile(slot))
}
/// Install a read/write PTE pointing at `paddr`.
pub unsafe fn slot_install(slot: *mut u64, paddr: u64, write: bool, read: bool) {
    retire_slot(slot, pte_new(paddr, write, read));
}
/// Zero a PTE slot. Returns only after the IOTLB no longer caches the old target.
pub unsafe fn slot_clear(slot: *mut u64) {
    retire_slot(slot, 0);
}

unsafe fn retire_slot(slot: *mut u64, entry: u64) {
    let (base, iotlb) = invalidation_regs().unwrap_or_else(|error| fail_stop(error));
    retire_leaf(&mut MmioRegisters(base), iotlb, || core::ptr::write_volatile(slot, entry))
        .unwrap_or_else(|error| fail_stop(error));
}

// ---------------------------------------------------------------------------
// Boot init. Replaces the old viability probe.
// ---------------------------------------------------------------------------

fn log_hex(v: u64) {
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

/// Discover the single segment-zero DRHD, map its register block, allocate the root
/// table, and point the unit at it. Must run after the
/// IOMMU page pool is installed (`install_iommu_pool`). Idempotent-ish:
/// safe to call once.
pub fn vtd_init() {
    let sdt_addr = crate::simpleboot::acpi_table_address();

    let dmar = match acpi::find_dmar(sdt_addr) {
        Ok(d) => d,
        Err(_) => {
            crate::arch::log("IOMMU: no DMAR table — IOMMU disabled\n");
            return;
        }
    };
    let unit = match acpi::dmar_single_drhd(dmar) {
        Some(unit) => unit,
        None => {
            crate::arch::log("IOMMU: DMAR lacks one valid DRHD for PCI segment 0\n");
            return;
        }
    };
    let base = unit.base;
    if !unsafe { unit.populate_allowed_rids(&mut *core::ptr::addr_of_mut!(VTD_ALLOWED_RIDS)) } {
        crate::arch::log("IOMMU: malformed DRHD endpoint scopes\n");
        return;
    }

    unsafe {
        paging::map_kernel_mmio_page(KERNEL_IOMMU_VBASE, base);
    }
    let off = base & 0xFFF;
    let regs = KERNEL_IOMMU_VBASE + off;
    unsafe { VTD_REGS = regs };

    let ver = unsafe { core::ptr::read_volatile((regs + VER_REG) as *const u32) };
    let cap = unsafe { core::ptr::read_volatile((regs + CAP_REG) as *const u64) };
    let ecap = unsafe { core::ptr::read_volatile((regs + ECAP_REG) as *const u64) };
    let sagaw = (cap >> 8) & 0x1F;
    let iotlb_offset = ((ecap >> 8) & 0x3ff) * 16 + IOTLB_REG;
    if ver == 0 || ver == 0xFFFF_FFFF || cap == u64::MAX
        || iotlb_offset == IOTLB_REG || (base & 0xfff) + iotlb_offset + 8 > 4096
    {
        crate::arch::log("IOMMU: VT-d register file dead — disabled\n");
        return;
    }
    if sagaw & 0x4 == 0 {
        crate::arch::log("IOMMU: VT-d lacks four-level IO page tables — disabled\n");
        return;
    }

    let Some(domains) = domain_count(cap) else {
        crate::arch::log("IOMMU: VT-d has a reserved CAP.ND encoding — disabled\n");
        return;
    };

    // numIOPTLevels = 4 (see module docs); CAP.SAGAW must advertise it.
    unsafe { NUM_IOPT_LEVELS = 4 };

    // Allocate the root table.
    let root = unsafe { alloc_iommu_page() };
    let Some(root_paddr) = root else {
        crate::arch::log("IOMMU: page pool exhausted — disabled\n");
        return;
    };
    unsafe {
        VTD_DOMAIN_COUNT = domains;
        VTD_ROOT_TABLE_PADDR = root_paddr;
        NUM_DRHU = 1;
        VTD_IOTLB_OFFSET = iotlb_offset;
        VTD_INCLUDE_ALL_RIDS = unit.include_all;
    }

    // Point the unit at the root table (SRTP). Translation is enabled
    // when a requester installs its first context; status waits are bounded.
    unsafe {
        core::ptr::write_volatile((regs + RTADDR_REG) as *mut u64, root_paddr);
        let status = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
        core::ptr::write_volatile((regs + GCMD_REG) as *mut u32, status | (1 << SRTP));
        let mut spins = 0u32;
        while spins < INVALIDATION_SPINS {
            let s = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
            if (s >> RTPS) & 1 != 0 {
                break;
            }
            spins += 1;
        }
        if spins == INVALIDATION_SPINS {
            fail_stop(VtdError::TimedOut);
        }
        invalidate_context_and_iotlb().unwrap_or_else(|error| fail_stop(error));
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
pub unsafe fn enable_translation() -> Result<(), VtdError> {
    if VTD_REGS == 0 {
        return Err(VtdError::Unavailable);
    }
    let regs = VTD_REGS;
    let status = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
    if (status >> TES) & 1 != 0 {
        return Ok(()); // already enabled
    }
    // Write TE only (SRTP bit 30 = 0 so the already-set root pointer isn't re-triggered).
    core::ptr::write_volatile((regs + GCMD_REG) as *mut u32, 1 << TE);
    let mut spins = 0u32;
    while spins < INVALIDATION_SPINS {
        let s = core::ptr::read_volatile((regs + GSTS_REG) as *const u32);
        if (s >> TES) & 1 != 0 {
            crate::arch::log("IOMMU: translation ENABLED (TE)\n");
            return Ok(());
        }
        spins += 1;
    }
    crate::arch::log("IOMMU: TE enable timed out\n");
    Err(VtdError::TimedOut)
}
