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

#[inline]
fn phys_ptr(paddr: u64) -> *const u8 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let base = crate::arch::x86_64::paging::LINEAR_MAP_BASE;
        if base != 0 {
            return crate::arch::x86_64::paging::phys_to_lin(paddr) as *const u8;
        }
    }
    paddr as *const u8
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
    let start = mbi_addr();
    let size = mbi_total_size() as u64;
    start.checked_add(size).map(|end| (start, end))
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

pub fn for_each_module_region(mut f: impl FnMut(u64, u64)) {
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

/// Simpleboot does not publish a wall-clock timestamp in the MBI.
pub fn wall_clock_snapshot() -> Option<bootstrap_clock::WallClockSnapshot> {
    None
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
        let red_pos = tag.read_u8(32);
        let green_pos = tag.read_u8(34);
        let blue_pos = tag.read_u8(36);
        let size = scanline.checked_mul(height)?;
        if paddr == 0 || size == 0 || width == 0 || height == 0 {
            return None;
        }
        Some(FramebufferInfo {
            paddr,
            size,
            width,
            height,
            scanline,
            fb_type: framebuffer_type_from_masks(bpp, red_pos, green_pos, blue_pos),
        });
    }
    None
}

#[cfg(feature = "extern-rootserver")]
fn framebuffer_type_from_masks(bpp: u8, red_pos: u8, green_pos: u8, blue_pos: u8) -> u8 {
    if bpp < 24 || green_pos != 8 {
        return FB_BGRA as u8;
    }
    match (red_pos, blue_pos) {
        (16, 0) => FB_BGRA as u8,
        (0, 16) => FB_RGBA as u8,
        (8, 24) => FB_ARGB as u8,
        (24, 8) => FB_ABGR as u8,
        _ => FB_BGRA as u8,
    }
}
