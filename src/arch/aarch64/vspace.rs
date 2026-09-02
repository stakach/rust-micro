//! AArch64 stage-1 translation tables for seL4-compatible EL0 VSpaces.
//!
//! seL4's non-hypervisor AArch64 configuration uses four levels of 4 KiB
//! tables, TTBR0_EL1 for userspace, and the MAIR indices reproduced below.
//! This kernel still executes from QEMU's low identity-mapped RAM, so the
//! initial root also contains privileged identity blocks. User mappings use
//! the same descriptor encoding as seL4 and are always non-global.

use core::arch::asm;
use core::ptr;

pub const PAGE_BITS: u32 = 12;
pub const LARGE_PAGE_BITS: u32 = 21;
pub const HUGE_PAGE_BITS: u32 = 30;
pub const ENTRIES_PER_TABLE: usize = 512;

const DESC_VALID: u64 = 1 << 0;
const DESC_TABLE_OR_PAGE: u64 = 1 << 1;
const DESC_ATTR_SHIFT: u32 = 2;
const DESC_AP_SHIFT: u32 = 6;
const DESC_SH_INNER: u64 = 3 << 8;
const DESC_AF: u64 = 1 << 10;
const DESC_NOT_GLOBAL: u64 = 1 << 11;
const DESC_PXN: u64 = 1 << 53;
const DESC_UXN: u64 = 1 << 54;
const TABLE_ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

/// MAIR_EL1 layout used by seL4's AArch64 elfloader and kernel.
pub const MAIR_EL1_VALUE: u64 = 0x0000_aaff_440c_0400;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VAddrIndices {
    pub pgd: u16,
    pub pud: u16,
    pub pd: u16,
    pub pt: u16,
    pub offset: u16,
}

pub const fn decompose_vaddr(vaddr: u64) -> VAddrIndices {
    VAddrIndices {
        pgd: ((vaddr >> 39) & 0x1ff) as u16,
        pud: ((vaddr >> 30) & 0x1ff) as u16,
        pd: ((vaddr >> 21) & 0x1ff) as u16,
        pt: ((vaddr >> 12) & 0x1ff) as u16,
        offset: (vaddr & 0xfff) as u16,
    }
}

pub const fn compose_vaddr(indices: VAddrIndices) -> u64 {
    ((indices.pgd as u64) << 39)
        | ((indices.pud as u64) << 30)
        | ((indices.pd as u64) << 21)
        | ((indices.pt as u64) << 12)
        | indices.offset as u64
}

pub const fn canonical(vaddr: u64) -> bool {
    let high = vaddr >> 47;
    high == 0 || high == 0x1ffff
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum VmRights {
    KernelOnly = 0,
    UserReadWrite = 1,
    UserReadOnly = 3,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum MemoryAttr {
    Device = 0,
    DeviceNgRE = 1,
    DeviceGRE = 2,
    NormalNonCacheable = 3,
    Normal = 4,
    NormalWriteThrough = 5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MapError {
    Alignment,
    InvalidLevel,
    OutOfRange,
}

#[repr(C, align(4096))]
pub struct PageTable(pub [u64; ENTRIES_PER_TABLE]);

impl PageTable {
    pub const fn zeroed() -> Self {
        Self([0; ENTRIES_PER_TABLE])
    }
}

pub const fn table_descriptor(table_paddr: u64) -> Result<u64, MapError> {
    if table_paddr & 0xfff != 0 {
        return Err(MapError::Alignment);
    }
    Ok((table_paddr & TABLE_ADDR_MASK) | DESC_VALID | DESC_TABLE_OR_PAGE)
}

pub const fn page_descriptor(
    paddr: u64,
    rights: VmRights,
    attr: MemoryAttr,
    executable: bool,
) -> Result<u64, MapError> {
    if paddr & 0xfff != 0 {
        return Err(MapError::Alignment);
    }
    let mut descriptor = (paddr & TABLE_ADDR_MASK)
        | DESC_VALID
        | DESC_TABLE_OR_PAGE
        | ((attr as u64) << DESC_ATTR_SHIFT)
        | ((rights as u64) << DESC_AP_SHIFT)
        | DESC_SH_INNER
        | DESC_AF
        | DESC_NOT_GLOBAL;
    if !executable {
        descriptor |= DESC_UXN;
    }
    Ok(descriptor)
}

/// Construct a level-1 (1 GiB) or level-2 (2 MiB) block descriptor.
pub const fn block_descriptor(
    paddr: u64,
    level: u8,
    rights: VmRights,
    attr: MemoryAttr,
    user_executable: bool,
    privileged_executable: bool,
) -> Result<u64, MapError> {
    let alignment_mask = match level {
        1 => (1u64 << HUGE_PAGE_BITS) - 1,
        2 => (1u64 << LARGE_PAGE_BITS) - 1,
        _ => return Err(MapError::InvalidLevel),
    };
    if paddr & alignment_mask != 0 {
        return Err(MapError::Alignment);
    }
    let mut descriptor = (paddr & !alignment_mask & TABLE_ADDR_MASK)
        | DESC_VALID
        | ((attr as u64) << DESC_ATTR_SHIFT)
        | ((rights as u64) << DESC_AP_SHIFT)
        | DESC_SH_INNER
        | DESC_AF;
    if !user_executable {
        descriptor |= DESC_UXN;
    }
    if !privileged_executable {
        descriptor |= DESC_PXN;
    }
    Ok(descriptor)
}

pub const fn descriptor_paddr(descriptor: u64, level: u8) -> Result<u64, MapError> {
    let mask = match level {
        0 | 3 => TABLE_ADDR_MASK,
        1 => TABLE_ADDR_MASK & !((1u64 << HUGE_PAGE_BITS) - 1),
        2 => TABLE_ADDR_MASK & !((1u64 << LARGE_PAGE_BITS) - 1),
        _ => return Err(MapError::InvalidLevel),
    };
    Ok(descriptor & mask)
}

static mut BOOT_L0: PageTable = PageTable::zeroed();
static mut BOOT_L1: PageTable = PageTable::zeroed();
static mut BOOT_LOW_L2: PageTable = PageTable::zeroed();

fn physical_address_size() -> u64 {
    let mmfr0: u64;
    unsafe {
        asm!("mrs {value}, id_aa64mmfr0_el1", value = out(reg) mmfr0, options(nomem, nostack));
    }
    mmfr0 & 0x7
}

fn initial_tcr_el1() -> u64 {
    const T0SZ_48_BITS: u64 = 16;
    const IRGN0_WBWA: u64 = 1 << 8;
    const ORGN0_WBWA: u64 = 1 << 10;
    const SH0_INNER: u64 = 3 << 12;
    const EPD1: u64 = 1 << 23;
    T0SZ_48_BITS | IRGN0_WBWA | ORGN0_WBWA | SH0_INNER | EPD1 | (physical_address_size() << 32)
}

/// Install the direct-boot kernel's initial stage-1 tables.
///
/// The low GiB is device memory at 2 MiB granularity. The second GiB is
/// normal privileged memory and contains QEMU RAM at 0x4000_0000, including
/// this image. Keeping the low range split leaves its individual blocks
/// available for later replacement by userspace page tables.
pub fn install_kernel_vspace() {
    unsafe {
        ptr::write_bytes((&raw mut BOOT_L0) as *mut u8, 0, size_of::<PageTable>());
        ptr::write_bytes((&raw mut BOOT_L1) as *mut u8, 0, size_of::<PageTable>());
        ptr::write_bytes((&raw mut BOOT_LOW_L2) as *mut u8, 0, size_of::<PageTable>());

        let l1 = (&raw const BOOT_L1) as u64;
        let low_l2 = (&raw const BOOT_LOW_L2) as u64;
        BOOT_L0.0[0] = table_descriptor(l1).unwrap();
        BOOT_L1.0[0] = table_descriptor(low_l2).unwrap();
        for index in 0..ENTRIES_PER_TABLE {
            BOOT_LOW_L2.0[index] = block_descriptor(
                (index as u64) << LARGE_PAGE_BITS,
                2,
                VmRights::KernelOnly,
                MemoryAttr::Device,
                false,
                false,
            )
            .unwrap();
        }
        BOOT_L1.0[1] = block_descriptor(
            1 << HUGE_PAGE_BITS,
            1,
            VmRights::KernelOnly,
            MemoryAttr::Normal,
            false,
            true,
        )
        .unwrap();

        let root = (&raw const BOOT_L0) as u64;
        let tcr = initial_tcr_el1();
        asm!(
            "dsb sy",
            "msr mair_el1, {mair}",
            "msr tcr_el1, {tcr}",
            "msr ttbr0_el1, {root}",
            "msr ttbr1_el1, xzr",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "mrs x9, sctlr_el1",
            "orr x9, x9, #(1 << 0)",
            "orr x9, x9, #(1 << 2)",
            "orr x9, x9, #(1 << 12)",
            "msr sctlr_el1, x9",
            "isb",
            mair = in(reg) MAIR_EL1_VALUE,
            tcr = in(reg) tcr,
            root = in(reg) root,
            out("x9") _,
            options(nostack),
        );
    }
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_vspace() {
        arch::log("Running AArch64 vspace tests...\n");
        address_indices_round_trip();
        descriptor_encodings_match_sel4();
        live_translation_is_enabled();
        arch::log("AArch64 vspace tests completed\n");
    }

    fn address_indices_round_trip() {
        let address = (0x12u64 << 39) | (0xabu64 << 30) | (0x34u64 << 21) | (0xcdu64 << 12) | 0x123;
        let indices = decompose_vaddr(address);
        assert_eq!(indices.pgd, 0x12);
        assert_eq!(indices.pud, 0xab);
        assert_eq!(indices.pd, 0x34);
        assert_eq!(indices.pt, 0xcd);
        assert_eq!(indices.offset, 0x123);
        assert_eq!(compose_vaddr(indices), address);
        assert!(canonical(address));
        assert!(!canonical(0x0000_8000_0000_0000));
    }

    fn descriptor_encodings_match_sel4() {
        let table = table_descriptor(0x1234_5000).unwrap();
        assert_eq!(table & 0x3, 0x3);
        assert_eq!(descriptor_paddr(table, 0).unwrap(), 0x1234_5000);

        let rw = page_descriptor(
            0x4000_0000,
            VmRights::UserReadWrite,
            MemoryAttr::Normal,
            true,
        )
        .unwrap();
        assert_eq!((rw >> DESC_AP_SHIFT) & 0x3, 1);
        assert_eq!((rw >> DESC_ATTR_SHIFT) & 0x7, 4);
        assert_ne!(rw & DESC_AF, 0);
        assert_ne!(rw & DESC_NOT_GLOBAL, 0);
        assert_eq!(rw & DESC_UXN, 0);

        let ro_nx = page_descriptor(
            0x4000_1000,
            VmRights::UserReadOnly,
            MemoryAttr::Normal,
            false,
        )
        .unwrap();
        assert_eq!((ro_nx >> DESC_AP_SHIFT) & 0x3, 3);
        assert_ne!(ro_nx & DESC_UXN, 0);
        assert_eq!(MAIR_EL1_VALUE, 0x0000_aaff_440c_0400);
    }

    fn live_translation_is_enabled() {
        let sctlr: u64;
        let mair: u64;
        let ttbr0: u64;
        let address = (&raw const BOOT_L0) as u64;
        let par: u64;
        unsafe {
            asm!(
                "mrs {sctlr}, sctlr_el1",
                "mrs {mair}, mair_el1",
                "mrs {ttbr0}, ttbr0_el1",
                "at s1e1r, {address}",
                "isb",
                "mrs {par}, par_el1",
                sctlr = out(reg) sctlr,
                mair = out(reg) mair,
                ttbr0 = out(reg) ttbr0,
                address = in(reg) address,
                par = out(reg) par,
                options(nostack),
            );
        }
        assert_ne!(sctlr & 1, 0);
        assert_eq!(mair, MAIR_EL1_VALUE);
        assert_eq!(ttbr0 & TABLE_ADDR_MASK, address & TABLE_ADDR_MASK);
        assert_eq!(par & 1, 0, "live stage-1 translation faulted");
        assert_eq!(
            (par & TABLE_ADDR_MASK) | (address & 0xfff),
            address,
            "identity translation returned the wrong physical address"
        );
    }
}
