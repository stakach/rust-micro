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
static mut EL0_SPEC_L2: PageTable = PageTable::zeroed();
static mut EL0_SPEC_L3: PageTable = PageTable::zeroed();
static mut EL0_SPEC_STACK: PageTable = PageTable::zeroed();

const EL0_SPEC_CODE_VADDR: u64 = 0x8000_0000;
const EL0_SPEC_STACK_VADDR: u64 = EL0_SPEC_CODE_VADDR + 0x1000;

core::arch::global_asm!(
    r#"
    .section .text.aarch64_el0_spec,"ax"
    .balign 4096
    .global aarch64_el0_spec_start
aarch64_el0_spec_start:
    mov x0, #'U'
    mov x7, #-12
    svc #0
    mov x0, #'Z'
    svc #1
1:
    b 1b
    .balign 4096

    .section .text.aarch64_el0_entry,"ax"
    .global aarch64_enter_el0_spec
aarch64_enter_el0_spec:
    msr sp_el0, x1
    msr elr_el1, x0
    mov x9, #0x40
    msr spsr_el1, x9
    isb
    eret
    .global aarch64_el0_spec_resume
aarch64_el0_spec_resume:
    ret
"#
);

extern "C" {
    static aarch64_el0_spec_start: u8;
    fn aarch64_enter_el0_spec(entry: u64, stack: u64);
}

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
    const ASID16: u64 = 1 << 36;
    T0SZ_48_BITS
        | IRGN0_WBWA
        | ORGN0_WBWA
        | SH0_INNER
        | EPD1
        | ASID16
        | (physical_address_size() << 32)
}

unsafe fn table_ptr(paddr: u64) -> *mut u64 {
    crate::arch::phys_to_virt(paddr) as *mut u64
}

/// Create a user VSpace root which retains this direct-boot kernel's
/// privileged mappings. `allocate` must return zeroed, 4 KiB-aligned physical
/// pages reachable through `arch::phys_to_virt`.
pub unsafe fn make_user_vspace(mut allocate: impl FnMut() -> u64) -> u64 {
    let root = allocate();
    let l1 = allocate();
    let low_l2 = allocate();
    assert_eq!(root & 0xfff, 0);
    assert_eq!(l1 & 0xfff, 0);
    assert_eq!(low_l2 & 0xfff, 0);

    ptr::write_volatile(table_ptr(root), table_descriptor(l1).unwrap());
    ptr::write_volatile(table_ptr(l1), table_descriptor(low_l2).unwrap());
    // The kernel still executes with TTBR0, so retain only the live QEMU
    // virt devices it accesses after EL0 starts. Leaving the rest of the
    // low GiB empty is essential: seL4 userspace allocators map ordinary
    // addresses such as 0x1000_0000 there.
    for index in [
        0x0800_0000usize >> LARGE_PAGE_BITS,
        0x0900_0000usize >> LARGE_PAGE_BITS,
    ] {
        ptr::write_volatile(
            table_ptr(low_l2).add(index),
            ptr::read_volatile(core::ptr::addr_of!(BOOT_LOW_L2.0[index])),
        );
    }
    ptr::write_volatile(
        table_ptr(l1).add(1),
        ptr::read_volatile(core::ptr::addr_of!(BOOT_L1.0[1])),
    );
    root
}

/// Map a seL4 small page into an allocator-backed user VSpace.
pub unsafe fn map_user_4k(
    root_paddr: u64,
    vaddr: u64,
    paddr: u64,
    writable: bool,
    executable: bool,
    mut allocate: impl FnMut() -> u64,
) -> Result<(), MapError> {
    if !canonical(vaddr) || vaddr >= (1u64 << 39) {
        return Err(MapError::OutOfRange);
    }
    if vaddr & 0xfff != 0 || paddr & 0xfff != 0 || root_paddr & 0xfff != 0 {
        return Err(MapError::Alignment);
    }
    let indices = decompose_vaddr(vaddr);
    let root = table_ptr(root_paddr);
    let root_entry = ptr::read_volatile(root.add(indices.pgd as usize));
    if root_entry & 0x3 != 0x3 {
        return Err(MapError::OutOfRange);
    }
    let l1 = table_ptr(descriptor_paddr(root_entry, 0)?);

    let l1_slot = l1.add(indices.pud as usize);
    let mut l1_entry = ptr::read_volatile(l1_slot);
    if l1_entry & DESC_VALID == 0 {
        let child = allocate();
        if child & 0xfff != 0 {
            return Err(MapError::Alignment);
        }
        l1_entry = table_descriptor(child)?;
        ptr::write_volatile(l1_slot, l1_entry);
    }
    if l1_entry & 0x3 != 0x3 {
        return Err(MapError::OutOfRange);
    }
    // A table descriptor always carries a 4 KiB-aligned address. The
    // containing level only changes the mask for block descriptors.
    let l2 = table_ptr(descriptor_paddr(l1_entry, 0)?);

    let l2_slot = l2.add(indices.pd as usize);
    let mut l2_entry = ptr::read_volatile(l2_slot);
    if l2_entry & 0x3 != 0x3 {
        let child = allocate();
        if child & 0xfff != 0 {
            return Err(MapError::Alignment);
        }
        l2_entry = table_descriptor(child)?;
        ptr::write_volatile(l2_slot, l2_entry);
    }
    let l3 = table_ptr(descriptor_paddr(l2_entry, 0)?);
    let leaf = l3.add(indices.pt as usize);
    if ptr::read_volatile(leaf) & DESC_VALID != 0 {
        return Err(MapError::OutOfRange);
    }
    ptr::write_volatile(
        leaf,
        page_descriptor(
            paddr,
            if writable {
                VmRights::UserReadWrite
            } else {
                VmRights::UserReadOnly
            },
            MemoryAttr::Normal,
            executable,
        )?,
    );
    asm!("dsb ishst", options(nostack));
    Ok(())
}

pub fn activate_user_vspace(root_paddr: u64, asid: u16) {
    let ttbr = root_paddr | ((asid as u64) << 48);
    unsafe {
        asm!(
            "dsb ish",
            "msr ttbr0_el1, {ttbr}",
            "isb",
            ttbr = in(reg) ttbr,
            options(nostack),
        );
    }
}

unsafe fn flush_vspace() {
    asm!(
        "dsb ishst",
        "tlbi vmalle1is",
        "dsb ish",
        "isb",
        options(nostack),
    );
}

/// Install a recursive AArch64 PageTable object at the first missing
/// translation level, as `decodeARMPageTableInvocation` does in seL4.
/// The returned value is the number of address bits covered by that entry.
pub unsafe fn map_page_table(
    root_paddr: u64,
    vaddr: u64,
    table_paddr: u64,
) -> Result<u32, MapError> {
    if !canonical(vaddr) || vaddr >= (1u64 << 47) {
        return Err(MapError::OutOfRange);
    }
    if root_paddr & 0xfff != 0 || table_paddr & 0xfff != 0 {
        return Err(MapError::Alignment);
    }

    let indices = decompose_vaddr(vaddr);
    let slots = [
        indices.pgd as usize,
        indices.pud as usize,
        indices.pd as usize,
    ];
    let bits_left = [39u32, 30, 21];
    let mut table = table_ptr(root_paddr);
    for level in 0..slots.len() {
        let slot = table.add(slots[level]);
        let entry = ptr::read_volatile(slot);
        if entry & DESC_VALID == 0 {
            // This direct-boot kernel currently shares TTBR0 with EL0. When
            // userspace constructs the low-address walk for a fresh VSpace,
            // seed only the privileged leaves needed to keep EL1 reachable.
            // These occupy the same levels that make_user_vspace establishes.
            if bits_left[level] == 39 && indices.pgd == 0 {
                ptr::write_volatile(
                    table_ptr(table_paddr).add(1),
                    ptr::read_volatile(core::ptr::addr_of!(BOOT_L1.0[1])),
                );
            } else if bits_left[level] == 30 && indices.pgd == 0 && indices.pud == 0 {
                for device_index in [
                    0x0800_0000usize >> LARGE_PAGE_BITS,
                    0x0900_0000usize >> LARGE_PAGE_BITS,
                ] {
                    ptr::write_volatile(
                        table_ptr(table_paddr).add(device_index),
                        ptr::read_volatile(core::ptr::addr_of!(BOOT_LOW_L2.0[device_index])),
                    );
                }
            }
            ptr::write_volatile(slot, table_descriptor(table_paddr)?);
            flush_vspace();
            return Ok(bits_left[level]);
        }
        if entry & 0x3 != 0x3 {
            return Err(MapError::OutOfRange);
        }
        table = table_ptr(descriptor_paddr(entry, 0)?);
    }
    Err(MapError::OutOfRange)
}

/// Map a frame after userspace has explicitly supplied every intermediate
/// PageTable object. `Err(bits_left)` reports the first missing level. Like
/// seL4's `performPageInvocationMap`, a valid leaf is replaced so remapping a
/// frame at the same address can update its rights and attributes.
pub unsafe fn map_frame(
    root_paddr: u64,
    vaddr: u64,
    paddr: u64,
    size_bits: u32,
    writable: bool,
    executable: bool,
    cacheable: bool,
) -> Result<(), u32> {
    if !canonical(vaddr)
        || vaddr >= (1u64 << 47)
        || !matches!(size_bits, 12 | 21 | 30)
        || vaddr & ((1u64 << size_bits) - 1) != 0
        || paddr & ((1u64 << size_bits) - 1) != 0
    {
        return Err(0);
    }

    let indices = decompose_vaddr(vaddr);
    let slots = [
        indices.pgd as usize,
        indices.pud as usize,
        indices.pd as usize,
        indices.pt as usize,
    ];
    let levels = [0u8, 1, 2, 3];
    let bits_left = [39u32, 30, 21, 12];
    let mut table = table_ptr(root_paddr);
    for index in 0..slots.len() {
        let slot = table.add(slots[index]);
        let entry = ptr::read_volatile(slot);
        if bits_left[index] == size_bits {
            let rights = if writable {
                VmRights::UserReadWrite
            } else {
                VmRights::UserReadOnly
            };
            let attr = if cacheable {
                MemoryAttr::Normal
            } else {
                MemoryAttr::Device
            };
            let descriptor = if size_bits == PAGE_BITS {
                page_descriptor(paddr, rights, attr, executable).map_err(|_| 0u32)?
            } else {
                block_descriptor(paddr, levels[index], rights, attr, executable, false)
                    .map_err(|_| 0u32)?
            };
            ptr::write_volatile(slot, descriptor);
            flush_vspace();
            return Ok(());
        }
        if entry & DESC_VALID == 0 || entry & 0x3 != 0x3 {
            return Err(bits_left[index]);
        }
        table = table_ptr(descriptor_paddr(entry, 0).map_err(|_| bits_left[index])?);
    }
    Err(0)
}

pub unsafe fn unmap_frame(root_paddr: u64, vaddr: u64, paddr: u64, size_bits: u32) -> bool {
    if !matches!(size_bits, 12 | 21 | 30) {
        return false;
    }
    let indices = decompose_vaddr(vaddr);
    let slots = [
        indices.pgd as usize,
        indices.pud as usize,
        indices.pd as usize,
        indices.pt as usize,
    ];
    let levels = [0u8, 1, 2, 3];
    let bits_left = [39u32, 30, 21, 12];
    let mut table = table_ptr(root_paddr);
    for index in 0..slots.len() {
        let slot = table.add(slots[index]);
        let entry = ptr::read_volatile(slot);
        if bits_left[index] == size_bits {
            if entry & DESC_VALID == 0 || descriptor_paddr(entry, levels[index]).ok() != Some(paddr)
            {
                return false;
            }
            ptr::write_volatile(slot, 0);
            flush_vspace();
            return true;
        }
        if entry & 0x3 != 0x3 {
            return false;
        }
        table = table_ptr(match descriptor_paddr(entry, 0) {
            Ok(address) => address,
            Err(_) => return false,
        });
    }
    false
}

pub unsafe fn frame_paddr(root_paddr: u64, vaddr: u64, size_bits: u32) -> Option<u64> {
    if !matches!(size_bits, 12 | 21 | 30) {
        return None;
    }
    let indices = decompose_vaddr(vaddr);
    let slots = [
        indices.pgd as usize,
        indices.pud as usize,
        indices.pd as usize,
        indices.pt as usize,
    ];
    let levels = [0u8, 1, 2, 3];
    let bits_left = [39u32, 30, 21, 12];
    let mut table = table_ptr(root_paddr);
    for index in 0..slots.len() {
        let entry = ptr::read_volatile(table.add(slots[index]));
        if bits_left[index] == size_bits {
            return (entry & DESC_VALID != 0)
                .then(|| descriptor_paddr(entry, levels[index]).ok())
                .flatten();
        }
        if entry & 0x3 != 0x3 {
            return None;
        }
        table = table_ptr(descriptor_paddr(entry, 0).ok()?);
    }
    None
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FrameMapping {
    pub paddr: u64,
    pub size_bits: u32,
    pub writable: bool,
}

/// Resolve the leaf covering `vaddr`, including block mappings. This mirrors
/// seL4's `lookupPTSlot` result used to validate cache-maintenance invocations.
pub unsafe fn lookup_frame(root_paddr: u64, vaddr: u64) -> Option<FrameMapping> {
    if !canonical(vaddr) || vaddr >= (1u64 << 47) || root_paddr & 0xfff != 0 {
        return None;
    }

    let indices = decompose_vaddr(vaddr);
    let slots = [
        indices.pgd as usize,
        indices.pud as usize,
        indices.pd as usize,
        indices.pt as usize,
    ];
    let levels = [0u8, 1, 2, 3];
    let bits_left = [39u32, 30, 21, 12];
    let mut table = table_ptr(root_paddr);

    for index in 0..slots.len() {
        let entry = ptr::read_volatile(table.add(slots[index]));
        if entry & DESC_VALID == 0 {
            return None;
        }

        let is_leaf = if index == 3 {
            entry & 0x3 == 0x3
        } else {
            index != 0 && entry & 0x3 == 0x1
        };
        if is_leaf {
            return Some(FrameMapping {
                paddr: descriptor_paddr(entry, levels[index]).ok()?,
                size_bits: bits_left[index],
                writable: ((entry >> DESC_AP_SHIFT) & 0x3) == VmRights::UserReadWrite as u64,
            });
        }
        if entry & 0x3 != 0x3 {
            return None;
        }
        table = table_ptr(descriptor_paddr(entry, 0).ok()?);
    }
    None
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CacheOperation {
    CleanData,
    InvalidateData,
    CleanInvalidateData,
    UnifyInstruction,
}

#[inline]
fn cache_line_size(ctr_shift: u32) -> u64 {
    let ctr: u64;
    unsafe {
        asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nomem, nostack));
    }
    4u64 << ((ctr >> ctr_shift) & 0xf)
}

#[inline]
unsafe fn for_each_cache_line(start: u64, end: u64, line_size: u64, mut op: impl FnMut(u64)) {
    let mut line = start & !(line_size - 1);
    while line < end {
        op(line);
        line += line_size;
    }
}

unsafe fn cache_maintain_range(start: u64, end: u64, operation: CacheOperation) {
    debug_assert!(start < end);
    let data_line = cache_line_size(16);

    match operation {
        CacheOperation::CleanData => {
            for_each_cache_line(start, end, data_line, |line| {
                asm!("dc cvac, {line}", line = in(reg) line, options(nostack));
            });
            asm!("dsb ish", options(nostack));
        }
        CacheOperation::InvalidateData => {
            // Preserve bytes outside a partial boundary line, as seL4's
            // invalidateCacheRange_RAM does before issuing DC IVAC.
            if start & (data_line - 1) != 0 {
                let line = start & !(data_line - 1);
                asm!("dc cvac, {line}", line = in(reg) line, options(nostack));
            }
            if end & (data_line - 1) != 0 {
                let line = (end - 1) & !(data_line - 1);
                asm!("dc cvac, {line}", line = in(reg) line, options(nostack));
            }
            asm!("dsb ish", options(nostack));
            for_each_cache_line(start, end, data_line, |line| {
                asm!("dc ivac, {line}", line = in(reg) line, options(nostack));
            });
            asm!("dsb ish", options(nostack));
        }
        CacheOperation::CleanInvalidateData => {
            for_each_cache_line(start, end, data_line, |line| {
                asm!("dc cvac, {line}", line = in(reg) line, options(nostack));
            });
            asm!("dsb ish", options(nostack));
            for_each_cache_line(start, end, data_line, |line| {
                asm!("dc civac, {line}", line = in(reg) line, options(nostack));
            });
            asm!("dsb ish", options(nostack));
        }
        CacheOperation::UnifyInstruction => {
            for_each_cache_line(start, end, data_line, |line| {
                asm!("dc cvau, {line}", line = in(reg) line, options(nostack));
            });
            asm!("dsb ish", options(nostack));
            let instruction_line = cache_line_size(0);
            for_each_cache_line(start, end, instruction_line, |line| {
                asm!("ic ivau, {line}", line = in(reg) line, options(nostack));
            });
            asm!("dsb ish", "isb", options(nostack));
        }
    }
}

/// Perform cache maintenance using addresses in the supplied VSpace. seL4
/// temporarily installs that root at EL1 for VA-based maintenance and then
/// restores the interrupted thread's root; doing the same also supports
/// invocations on a VSpace other than the caller's current one.
pub unsafe fn cache_maintain_vspace(
    root_paddr: u64,
    asid: u16,
    start: u64,
    end: u64,
    operation: CacheOperation,
) {
    if start >= end {
        return;
    }

    let old_ttbr: u64;
    asm!("mrs {ttbr}, ttbr0_el1", ttbr = out(reg) old_ttbr, options(nomem, nostack));
    let target_ttbr = root_paddr | ((asid as u64) << 48);
    if old_ttbr != target_ttbr {
        activate_user_vspace(root_paddr, asid);
    }
    cache_maintain_range(start, end, operation);
    if old_ttbr != target_ttbr {
        asm!(
            "dsb ish",
            "msr ttbr0_el1, {ttbr}",
            "isb",
            ttbr = in(reg) old_ttbr,
            options(nostack),
        );
    }
}

pub unsafe fn unmap_page_table(root_paddr: u64, vaddr: u64, child_paddr: u64) -> bool {
    let indices = decompose_vaddr(vaddr);
    let slots = [
        indices.pgd as usize,
        indices.pud as usize,
        indices.pd as usize,
    ];
    let mut table = table_ptr(root_paddr);
    for index in slots {
        let slot = table.add(index);
        let entry = ptr::read_volatile(slot);
        if entry & 0x3 != 0x3 {
            return false;
        }
        let address = match descriptor_paddr(entry, 0) {
            Ok(address) => address,
            Err(_) => return false,
        };
        if address == child_paddr {
            ptr::write_volatile(slot, 0);
            flush_vspace();
            return true;
        }
        table = table_ptr(address);
    }
    false
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

        activate_kernel_vspace();
    }
}

unsafe fn activate_kernel_vspace() {
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

/// Leave a user address space before this CPU becomes idle. Page-table
/// objects belonging to the former thread may be reclaimed by another CPU;
/// retaining that TTBR0 while executing the kernel would then make instruction
/// and data walks depend on freed memory.
pub fn park_on_kernel_root() {
    unsafe { activate_kernel_vspace() }
}

/// Install the BSP-constructed kernel tables on a secondary CPU.
pub fn install_kernel_vspace_for_ap() {
    park_on_kernel_root()
}

#[cfg(feature = "spec")]
fn map_el0_spec_pages() {
    unsafe {
        ptr::write_bytes((&raw mut EL0_SPEC_L2) as *mut u8, 0, size_of::<PageTable>());
        ptr::write_bytes((&raw mut EL0_SPEC_L3) as *mut u8, 0, size_of::<PageTable>());
        ptr::write_bytes(
            (&raw mut EL0_SPEC_STACK) as *mut u8,
            0,
            size_of::<PageTable>(),
        );

        let indices = decompose_vaddr(EL0_SPEC_CODE_VADDR);
        BOOT_L1.0[indices.pud as usize] =
            table_descriptor((&raw const EL0_SPEC_L2) as u64).unwrap();
        EL0_SPEC_L2.0[indices.pd as usize] =
            table_descriptor((&raw const EL0_SPEC_L3) as u64).unwrap();
        EL0_SPEC_L3.0[indices.pt as usize] = page_descriptor(
            core::ptr::addr_of!(aarch64_el0_spec_start) as u64,
            VmRights::UserReadWrite,
            MemoryAttr::Normal,
            true,
        )
        .unwrap();
        EL0_SPEC_L3.0[indices.pt as usize + 1] = page_descriptor(
            (&raw const EL0_SPEC_STACK) as u64,
            VmRights::UserReadWrite,
            MemoryAttr::Normal,
            false,
        )
        .unwrap();
        asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
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
        live_cache_maintenance_matches_sel4();
        live_el0_svc_round_trip();
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

    fn live_el0_svc_round_trip() {
        map_el0_spec_pages();
        crate::arch::aarch64::exceptions::begin_el0_svc_spec();
        unsafe {
            aarch64_enter_el0_spec(EL0_SPEC_CODE_VADDR, EL0_SPEC_STACK_VADDR + 0x1000);
        }
        crate::arch::aarch64::exceptions::finish_el0_svc_spec();
        arch::log("  live EL0 SVC register save/restore matches seL4\n");
    }

    fn live_cache_maintenance_matches_sel4() {
        map_el0_spec_pages();
        let root = (&raw const BOOT_L0) as u64;
        let mapping = unsafe { lookup_frame(root, EL0_SPEC_STACK_VADDR) }
            .expect("EL0 spec stack should have a leaf mapping");
        assert_eq!(mapping.paddr, (&raw const EL0_SPEC_STACK) as u64);
        assert_eq!(mapping.size_bits, PAGE_BITS);
        assert!(mapping.writable);

        let block = unsafe { lookup_frame(root, 0x4000_1234) }
            .expect("kernel RAM should retain its live 1 GiB block mapping");
        assert_eq!(block.paddr, 0x4000_0000);
        assert_eq!(block.size_bits, HUGE_PAGE_BITS);
        assert!(!block.writable);

        for operation in [
            CacheOperation::CleanData,
            CacheOperation::InvalidateData,
            CacheOperation::CleanInvalidateData,
            CacheOperation::UnifyInstruction,
        ] {
            unsafe {
                cache_maintain_vspace(
                    root,
                    0,
                    EL0_SPEC_STACK_VADDR + 1,
                    EL0_SPEC_STACK_VADDR + 129,
                    operation,
                );
            }
        }
        arch::log("  live cache maintenance matches seL4 range semantics\n");
    }
}
