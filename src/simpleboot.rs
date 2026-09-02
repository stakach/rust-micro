//! Simpleboot boot-protocol adapter.
//!
//! Simpleboot enters 64-bit kernels with Multiboot2-style arguments:
//! the magic value in the first ABI argument and the physical address
//! of the Multiboot Information tag list in the second. The loader also
//! keeps physical RAM identity-mapped, which lets early kernel code read
//! the MBI, modules, ACPI tables, and page tables before our own linear
//! map is installed.

use core::ptr::read_unaligned;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36d7_6289;

pub const MULTIBOOT_TAG_TYPE_END: u32 = 0;
pub const MULTIBOOT_TAG_TYPE_MODULE: u32 = 3;
pub const MULTIBOOT_TAG_TYPE_MMAP: u32 = 6;
pub const MULTIBOOT_TAG_TYPE_FRAMEBUFFER: u32 = 8;
pub const MULTIBOOT_TAG_TYPE_ACPI_OLD: u32 = 14;
pub const MULTIBOOT_TAG_TYPE_ACPI_NEW: u32 = 15;
pub const MULTIBOOT_TAG_TYPE_SMP: u32 = 257;
pub const MULTIBOOT_TAG_TYPE_KERNEL: u32 = 259;

pub const MULTIBOOT_MEMORY_AVAILABLE: u32 = 1;
pub const MULTIBOOT_MEMORY_ACPI_RECLAIMABLE: u32 = 3;
pub const MULTIBOOT_MEMORY_NVS: u32 = 4;

pub const FB_ARGB: u32 = 0;
pub const FB_RGBA: u32 = 1;
pub const FB_ABGR: u32 = 2;
pub const FB_BGRA: u32 = 3;

static MBI_ADDR: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static FDT_ADDR: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "aarch64")]
const FDT_BEGIN_NODE: u32 = 1;
#[cfg(target_arch = "aarch64")]
const FDT_END_NODE: u32 = 2;
#[cfg(target_arch = "aarch64")]
const FDT_PROP: u32 = 3;
#[cfg(target_arch = "aarch64")]
const FDT_NOP: u32 = 4;
#[cfg(target_arch = "aarch64")]
const FDT_END: u32 = 9;

#[inline]
fn phys_ptr(paddr: u64) -> *const u8 {
    crate::arch::phys_to_virt(paddr) as *const u8
}

#[inline]
fn read_phys_u32(paddr: u64) -> u32 {
    unsafe { read_unaligned(phys_ptr(paddr) as *const u32) }
}

#[inline]
fn read_phys_u64(paddr: u64) -> u64 {
    unsafe { read_unaligned(phys_ptr(paddr) as *const u64) }
}

/// Store and minimally validate the MBI pointer supplied by Simpleboot.
pub fn init(magic: u64, mbi_addr: u64) {
    if magic as u32 != MULTIBOOT2_BOOTLOADER_MAGIC || mbi_addr & 7 != 0 {
        halt_invalid_boot();
    }
    let total_size = read_phys_u32(mbi_addr);
    if total_size < 16 {
        halt_invalid_boot();
    }
    MBI_ADDR.store(mbi_addr, Ordering::Release);
}

/// Record the flattened-device-tree pointer supplied by QEMU's direct
/// AArch64 kernel boot protocol. Device discovery is added incrementally;
/// until PSCI enumeration lands this path intentionally exposes one BSP.
#[cfg(target_arch = "aarch64")]
pub fn init_fdt(fdt_addr: u64) {
    // An FDT header is big-endian and starts with 0xd00dfeed. Validate it
    // without requiring the full parser during the earliest boot milestone.
    if fdt_addr & 7 != 0 {
        halt_invalid_boot();
    }
    let magic = unsafe { core::ptr::read_volatile(fdt_addr as *const u32) };
    if u32::from_be(magic) != 0xd00d_feed {
        halt_invalid_boot();
    }
    FDT_ADDR.store(fdt_addr, Ordering::Release);
}

#[cfg(target_arch = "aarch64")]
pub fn fdt_addr() -> u64 {
    FDT_ADDR.load(Ordering::Acquire)
}

#[cfg(target_arch = "aarch64")]
#[derive(Copy, Clone)]
struct FdtLayout {
    base: u64,
    total_size: usize,
    structure: usize,
    structure_size: usize,
    strings: usize,
    strings_size: usize,
}

#[cfg(target_arch = "aarch64")]
fn fdt_be32(paddr: u64) -> u32 {
    u32::from_be(unsafe { read_unaligned(paddr as *const u32) })
}

#[cfg(target_arch = "aarch64")]
fn fdt_layout() -> Option<FdtLayout> {
    let base = fdt_addr();
    if base == 0 || fdt_be32(base) != 0xd00d_feed {
        return None;
    }
    let total_size = fdt_be32(base + 4) as usize;
    let structure = fdt_be32(base + 8) as usize;
    let strings = fdt_be32(base + 12) as usize;
    let strings_size = fdt_be32(base + 32) as usize;
    let structure_size = fdt_be32(base + 36) as usize;
    if total_size < 40
        || structure.checked_add(structure_size)? > total_size
        || strings.checked_add(strings_size)? > total_size
    {
        return None;
    }
    Some(FdtLayout {
        base,
        total_size,
        structure,
        structure_size,
        strings,
        strings_size,
    })
}

#[cfg(target_arch = "aarch64")]
fn bytes_equal(paddr: u64, bytes: &[u8]) -> bool {
    bytes.iter().enumerate().all(|(index, expected)| unsafe {
        core::ptr::read_volatile((paddr + index as u64) as *const u8) == *expected
    })
}

#[cfg(target_arch = "aarch64")]
fn c_string_equal(paddr: u64, available: usize, expected: &[u8]) -> bool {
    available > expected.len()
        && bytes_equal(paddr, expected)
        && unsafe { core::ptr::read_volatile((paddr + expected.len() as u64) as *const u8) == 0 }
}

#[cfg(target_arch = "aarch64")]
fn c_string_starts_with(paddr: u64, available: usize, prefix: &[u8]) -> bool {
    available >= prefix.len() && bytes_equal(paddr, prefix)
}

#[cfg(target_arch = "aarch64")]
fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|v| v & !3)
}

#[cfg(target_arch = "aarch64")]
fn for_each_fdt_property(mut callback: impl FnMut(i32, u64, usize, u64, usize, u64, usize)) {
    let Some(layout) = fdt_layout() else {
        return;
    };
    let structure_end = layout.structure + layout.structure_size;
    let mut cursor = layout.structure;
    let mut depth = -1i32;
    let mut node_name = 0u64;
    let mut node_name_available = 0usize;
    while cursor
        .checked_add(4)
        .is_some_and(|end| end <= structure_end)
    {
        let token = fdt_be32(layout.base + cursor as u64);
        cursor += 4;
        match token {
            FDT_BEGIN_NODE => {
                depth += 1;
                node_name = layout.base + cursor as u64;
                let mut length = 0usize;
                while cursor + length < structure_end
                    && unsafe {
                        core::ptr::read_volatile(
                            (layout.base + cursor as u64 + length as u64) as *const u8,
                        ) != 0
                    }
                {
                    length += 1;
                }
                if cursor + length >= structure_end {
                    return;
                }
                node_name_available = length + 1;
                let Some(next) = align4(cursor + length + 1) else {
                    return;
                };
                cursor = next;
            }
            FDT_END_NODE => depth -= 1,
            FDT_PROP => {
                if cursor.checked_add(8).is_none_or(|end| end > structure_end) {
                    return;
                }
                let length = fdt_be32(layout.base + cursor as u64) as usize;
                let name_offset = fdt_be32(layout.base + cursor as u64 + 4) as usize;
                cursor += 8;
                if name_offset >= layout.strings_size
                    || cursor
                        .checked_add(length)
                        .is_none_or(|end| end > structure_end)
                {
                    return;
                }
                callback(
                    depth,
                    node_name,
                    node_name_available,
                    layout.base + layout.strings as u64 + name_offset as u64,
                    layout.strings_size - name_offset,
                    layout.base + cursor as u64,
                    length,
                );
                let Some(next) = align4(cursor + length) else {
                    return;
                };
                cursor = next;
            }
            FDT_NOP => {}
            FDT_END => return,
            _ => return,
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn fdt_read_cells(data: u64, length: usize) -> Option<u64> {
    match length {
        4 => Some(fdt_be32(data) as u64),
        8 => Some(((fdt_be32(data) as u64) << 32) | fdt_be32(data + 4) as u64),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
fn fdt_initrd() -> Option<ModuleInfo> {
    let mut start = None;
    let mut end = None;
    for_each_fdt_property(
        |depth, node, node_available, name, available, data, length| {
            if depth != 1 || !c_string_equal(node, node_available, b"chosen") {
                return;
            }
            if c_string_equal(name, available, b"linux,initrd-start") {
                start = fdt_read_cells(data, length);
            } else if c_string_equal(name, available, b"linux,initrd-end") {
                end = fdt_read_cells(data, length);
            }
        },
    );
    match (start, end) {
        (Some(start), Some(end)) if end > start => Some(ModuleInfo { start, end }),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
fn for_each_fdt_memory(mut callback: impl FnMut(u64, u64)) {
    for_each_fdt_property(
        |depth, node, node_available, name, available, data, length| {
            if depth != 1 || !c_string_starts_with(node, node_available, b"memory@") {
                return;
            }
            if !c_string_equal(name, available, b"reg") || length < 16 {
                return;
            }
            let base = ((fdt_be32(data) as u64) << 32) | fdt_be32(data + 4) as u64;
            let size = ((fdt_be32(data + 8) as u64) << 32) | fdt_be32(data + 12) as u64;
            if size != 0 {
                callback(base, size);
            }
        },
    );
}

#[cfg(target_arch = "x86_64")]
fn halt_invalid_boot() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn halt_invalid_boot() -> ! {
    loop {}
}

#[inline]
pub fn mbi_addr() -> u64 {
    let addr = MBI_ADDR.load(Ordering::Acquire);
    assert!(addr != 0, "Simpleboot MBI pointer was not initialised");
    addr
}

#[inline]
pub fn mbi_total_size() -> usize {
    read_phys_u32(mbi_addr()) as usize
}

/// Physical byte range occupied by the MBI itself.
pub fn mbi_region() -> Option<(u64, u64)> {
    #[cfg(target_arch = "aarch64")]
    {
        let layout = fdt_layout()?;
        return Some((layout.base, layout.base + layout.total_size as u64));
    }
    #[cfg(target_arch = "x86_64")]
    {
        let start = mbi_addr();
        let size = mbi_total_size() as u64;
        start.checked_add(size).map(|end| (start, end))
    }
}

#[derive(Copy, Clone)]
pub struct TagRef {
    paddr: u64,
}

impl TagRef {
    #[inline]
    pub fn tag_type(self) -> u32 {
        self.read_u32(0)
    }

    #[inline]
    pub fn size(self) -> u32 {
        self.read_u32(4)
    }

    #[inline]
    fn read_u8(self, offset: usize) -> u8 {
        unsafe { read_unaligned(phys_ptr(self.paddr + offset as u64) as *const u8) }
    }

    #[inline]
    fn read_u32(self, offset: usize) -> u32 {
        read_phys_u32(self.paddr + offset as u64)
    }

    #[inline]
    fn read_u64(self, offset: usize) -> u64 {
        read_phys_u64(self.paddr + offset as u64)
    }
}

pub struct TagIter {
    cursor: usize,
    end: usize,
}

impl Iterator for TagIter {
    type Item = TagRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.checked_add(8)? > self.end {
            self.cursor = self.end;
            return None;
        }
        let tag = TagRef {
            paddr: self.cursor as u64,
        };
        let tag_type = tag.tag_type();
        let size = tag.size() as usize;
        if tag_type == MULTIBOOT_TAG_TYPE_END {
            self.cursor = self.end;
            return None;
        }
        if size < 8 || self.cursor.checked_add(size)? > self.end {
            self.cursor = self.end;
            return None;
        }
        self.cursor += align8(size);
        Some(tag)
    }
}

pub fn tags() -> TagIter {
    let start = mbi_addr() as usize;
    let size = mbi_total_size();
    TagIter {
        cursor: start + 8,
        end: start + size,
    }
}

#[inline]
const fn align8(value: usize) -> usize {
    (value + 7) & !7
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ModuleInfo {
    pub start: u64,
    pub end: u64,
}

pub fn first_module() -> Option<ModuleInfo> {
    #[cfg(target_arch = "aarch64")]
    {
        fdt_initrd()
    }
    #[cfg(target_arch = "x86_64")]
    {
        for tag in tags() {
            if tag.tag_type() == MULTIBOOT_TAG_TYPE_MODULE && tag.size() >= 16 {
                let start = tag.read_u32(8) as u64;
                let end = tag.read_u32(12) as u64;
                if end > start {
                    return Some(ModuleInfo { start, end });
                }
            }
        }
        None
    }
}

pub fn for_each_module_region(mut f: impl FnMut(u64, u64)) {
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(module) = fdt_initrd() {
            f(module.start, module.end);
        }
        return;
    }
    #[cfg(target_arch = "x86_64")]
    for tag in tags() {
        if tag.tag_type() == MULTIBOOT_TAG_TYPE_MODULE && tag.size() >= 16 {
            let start = tag.read_u32(8) as u64;
            let end = tag.read_u32(12) as u64;
            if end > start {
                f(start, end);
            }
        }
    }
}

pub fn for_each_kernel_region(mut f: impl FnMut(u64, u64)) {
    #[cfg(target_arch = "aarch64")]
    {
        extern "C" {
            static _arm64_image_start: u8;
            static __kernel_end: u8;
        }
        f(
            core::ptr::addr_of!(_arm64_image_start) as u64,
            core::ptr::addr_of!(__kernel_end) as u64,
        );
        return;
    }
    #[cfg(target_arch = "x86_64")]
    for tag in tags() {
        if tag.tag_type() == MULTIBOOT_TAG_TYPE_KERNEL && tag.size() >= 16 {
            let start = tag.read_u32(8) as u64;
            let end = tag.read_u32(12) as u64;
            if end > start {
                f(start, end);
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

pub fn for_each_mmap_entry(mut f: impl FnMut(MMapEntry)) {
    #[cfg(target_arch = "aarch64")]
    {
        for_each_fdt_memory(|base_addr, length| {
            f(MMapEntry {
                base_addr,
                length,
                entry_type: MULTIBOOT_MEMORY_AVAILABLE,
                reserved: 0,
            });
        });
        return;
    }
    #[cfg(target_arch = "x86_64")]
    for tag in tags() {
        if tag.tag_type() != MULTIBOOT_TAG_TYPE_MMAP || tag.size() < 16 {
            continue;
        }
        let entry_size = tag.read_u32(8) as usize;
        if entry_size < 24 {
            continue;
        }
        let mut off = 16usize;
        let tag_size = tag.size() as usize;
        while off
            .checked_add(24)
            .map(|end| end <= tag_size)
            .unwrap_or(false)
        {
            f(MMapEntry {
                base_addr: tag.read_u64(off),
                length: tag.read_u64(off + 8),
                entry_type: tag.read_u32(off + 16),
                reserved: tag.read_u32(off + 20),
            });
            off = match off.checked_add(entry_size) {
                Some(next) => next,
                None => break,
            };
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SmpInfo {
    pub numcores: u32,
    pub running: u32,
    pub bspid: u32,
}

pub fn smp_info() -> Option<SmpInfo> {
    #[cfg(target_arch = "aarch64")]
    if MBI_ADDR.load(Ordering::Acquire) == 0 {
        return None;
    }
    for tag in tags() {
        if tag.tag_type() == MULTIBOOT_TAG_TYPE_SMP && tag.size() >= 20 {
            return Some(SmpInfo {
                numcores: tag.read_u32(8),
                running: tag.read_u32(12),
                bspid: tag.read_u32(16),
            });
        }
    }
    None
}

/// Total number of CPU cores Simpleboot started for this kernel.
pub fn get_num_cores() -> u16 {
    smp_info()
        .map(|info| {
            let running = info.running.max(1);
            let total = info.numcores.max(running);
            running.min(total).min(u16::MAX as u32) as u16
        })
        .unwrap_or(1)
}

/// Get the bootstrap processor's APIC ID.
pub fn get_bootstrap_processor_id() -> u16 {
    if let Some(info) = smp_info() {
        return info.bspid.min(u16::MAX as u32) as u16;
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::get_cpu_id() as u16
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[cfg(target_arch = "x86_64")]
const RTC_SECONDS: u8 = 0x00;
#[cfg(target_arch = "x86_64")]
const RTC_MINUTES: u8 = 0x02;
#[cfg(target_arch = "x86_64")]
const RTC_HOURS: u8 = 0x04;
#[cfg(target_arch = "x86_64")]
const RTC_DAY: u8 = 0x07;
#[cfg(target_arch = "x86_64")]
const RTC_MONTH: u8 = 0x08;
#[cfg(target_arch = "x86_64")]
const RTC_YEAR: u8 = 0x09;
#[cfg(target_arch = "x86_64")]
const RTC_STATUS_A: u8 = 0x0a;
#[cfg(target_arch = "x86_64")]
const RTC_STATUS_B: u8 = 0x0b;
#[cfg(target_arch = "x86_64")]
const RTC_STATUS_D: u8 = 0x0d;
#[cfg(target_arch = "x86_64")]
const RTC_UPDATE_IN_PROGRESS: u8 = 1 << 7;
#[cfg(target_arch = "x86_64")]
const RTC_VALID: u8 = 1 << 7;
#[cfg(target_arch = "x86_64")]
const CMOS_NMI_DISABLE: u8 = 1 << 7;
#[cfg(target_arch = "x86_64")]
const MAX_RTC_UPDATE_POLLS: usize = 128;
#[cfg(target_arch = "x86_64")]
const MAX_RTC_STABLE_READS: usize = 4;

#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

#[cfg(target_arch = "x86_64")]
fn cmos_read(index_port: u16, data_port: u16, register: u8) -> u8 {
    unsafe {
        outb(index_port, register | CMOS_NMI_DISABLE);
        inb(data_port)
    }
}

#[cfg(target_arch = "x86_64")]
fn rtc_update_complete(index_port: u16, data_port: u16) -> bool {
    for _ in 0..MAX_RTC_UPDATE_POLLS {
        if cmos_read(index_port, data_port, RTC_STATUS_A) & RTC_UPDATE_IN_PROGRESS == 0 {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "x86_64")]
fn read_rtc_registers(
    index_port: u16,
    data_port: u16,
    century_register: u8,
) -> bootstrap_clock::PcRtcRegisters {
    bootstrap_clock::PcRtcRegisters {
        second: cmos_read(index_port, data_port, RTC_SECONDS),
        minute: cmos_read(index_port, data_port, RTC_MINUTES),
        hour: cmos_read(index_port, data_port, RTC_HOURS),
        day: cmos_read(index_port, data_port, RTC_DAY),
        month: cmos_read(index_port, data_port, RTC_MONTH),
        year: cmos_read(index_port, data_port, RTC_YEAR),
        century: cmos_read(index_port, data_port, century_register),
    }
}

/// Simpleboot has no wall-clock MBI tag. Publish a stable snapshot from the ACPI-declared PC RTC;
/// platforms without a valid RTC and century register remain explicitly unsupported.
pub fn wall_clock_snapshot() -> Option<bootstrap_clock::WallClockSnapshot> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let rtc = crate::arch::x86_64::acpi::find_pc_rtc(acpi_table_address()).ok()?;
        let century_register = rtc.century_register.filter(|register| *register <= 0x7f)?;
        let snapshot = (|| {
            if cmos_read(rtc.index_port, rtc.data_port, RTC_STATUS_D) & RTC_VALID == 0
                || !rtc_update_complete(rtc.index_port, rtc.data_port)
            {
                return None;
            }
            let status_b = cmos_read(rtc.index_port, rtc.data_port, RTC_STATUS_B);
            for _ in 0..MAX_RTC_STABLE_READS {
                let first = read_rtc_registers(rtc.index_port, rtc.data_port, century_register);
                if cmos_read(rtc.index_port, rtc.data_port, RTC_STATUS_A) & RTC_UPDATE_IN_PROGRESS
                    != 0
                {
                    if !rtc_update_complete(rtc.index_port, rtc.data_port) {
                        return None;
                    }
                    continue;
                }
                let second = read_rtc_registers(rtc.index_port, rtc.data_port, century_register);
                if first == second {
                    return bootstrap_clock::decode_pc_rtc_utc(first, status_b).ok();
                }
            }
            None
        })();
        unsafe { outb(rtc.index_port, 0) };
        snapshot
    }
}

#[cfg(target_arch = "x86_64")]
pub fn acpi_table_address() -> u64 {
    let mut fallback_rsdt = 0u64;
    for tag in tags() {
        match tag.tag_type() {
            MULTIBOOT_TAG_TYPE_ACPI_NEW if tag.size() >= 44 => {
                let rsdt = tag.read_u32(24) as u64;
                let xsdt = tag.read_u64(32);
                return if xsdt != 0 { xsdt } else { rsdt };
            }
            MULTIBOOT_TAG_TYPE_ACPI_OLD if tag.size() >= 28 => {
                fallback_rsdt = tag.read_u32(24) as u64;
            }
            _ => {}
        }
    }
    fallback_rsdt
}

/// Linear-framebuffer geometry as reported by Simpleboot.
#[cfg(feature = "extern-rootserver")]
#[derive(Copy, Clone, Debug)]
pub struct FramebufferInfo {
    pub paddr: u64,
    pub size: u32,
    pub width: u32,
    pub height: u32,
    pub scanline: u32,
    pub fb_type: u8,
}

#[cfg(feature = "extern-rootserver")]
pub fn framebuffer_info() -> Option<FramebufferInfo> {
    for tag in tags() {
        if tag.tag_type() != MULTIBOOT_TAG_TYPE_FRAMEBUFFER || tag.size() < 38 {
            continue;
        }
        let paddr = tag.read_u64(8);
        let scanline = tag.read_u32(16);
        let width = tag.read_u32(20);
        let height = tag.read_u32(24);
        let bpp = tag.read_u8(28);
        let framebuffer_type = tag.read_u8(29);
        let red_pos = tag.read_u8(32);
        let red_size = tag.read_u8(33);
        let green_pos = tag.read_u8(34);
        let green_size = tag.read_u8(35);
        let blue_pos = tag.read_u8(36);
        let blue_size = tag.read_u8(37);
        let size = scanline.checked_mul(height)?;
        if paddr == 0 || size == 0 || width == 0 || height == 0 {
            return None;
        }
        let fb_type = framebuffer_type_from_masks(
            bpp,
            framebuffer_type,
            red_pos,
            red_size,
            green_pos,
            green_size,
            blue_pos,
            blue_size,
        )?;
        return Some(FramebufferInfo {
            paddr,
            size,
            width,
            height,
            scanline,
            fb_type,
        });
    }
    None
}

#[cfg(feature = "extern-rootserver")]
fn framebuffer_type_from_masks(
    bpp: u8,
    framebuffer_type: u8,
    red_pos: u8,
    red_size: u8,
    green_pos: u8,
    green_size: u8,
    blue_pos: u8,
    blue_size: u8,
) -> Option<u8> {
    if bpp != 32 || framebuffer_type != 1 || red_size != 8 || green_size != 8 || blue_size != 8 {
        return None;
    }
    match (red_pos, green_pos, blue_pos) {
        (16, 8, 0) => Some(FB_ARGB as u8),
        (24, 16, 8) => Some(FB_RGBA as u8),
        (0, 8, 16) => Some(FB_ABGR as u8),
        (8, 16, 24) => Some(FB_BGRA as u8),
        _ => None,
    }
}
