//! Minimal ELF64 parser — Phase 29b.
//!
//! The kernel reads its bundled rootserver ELF (see
//! `rootserver_image.rs`) and walks the program-header table to
//! find each `PT_LOAD` segment. The output drives Phase 29c, which
//! allocates user pages, copies the segment data, and maps them at
//! the linker-chosen vaddrs in the rootserver's VSpace.
//!
//! Only the subset we need: ELF64, little-endian, x86_64, static
//! (no dynamic relocation, no interpreter). Anything richer would
//! pull in a real ELF crate; we avoid that here.

use crate::types::seL4_Word as Word;

// ---------------------------------------------------------------------------
// Constants from the ELF spec.
// ---------------------------------------------------------------------------

const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;

const ELFMAG0: u8 = 0x7f;
const ELFMAG1: u8 = b'E';
const ELFMAG2: u8 = b'L';
const ELFMAG3: u8 = b'F';

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;

/// Segment flag bits (program-header `p_flags`).
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

// ---------------------------------------------------------------------------
// On-disk layout (64-bit, little-endian).
// ---------------------------------------------------------------------------

/// 64-byte ELF64 file header.
#[repr(C, packed)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// 56-byte ELF64 program header.
#[repr(C, packed)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

// ---------------------------------------------------------------------------
// Decoded shapes.
// ---------------------------------------------------------------------------

/// Outcome of parsing the ELF header. `entry` is the user-mode
/// entry point (= `e_entry`); the segment iterator yields one
/// `LoadSegment` per `PT_LOAD` program header.
#[derive(Copy, Clone, Debug)]
pub struct Image<'a> {
    bytes: &'a [u8],
    pub entry: Word,
    phoff: u64,
    phnum: u16,
}

/// One loadable segment.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub vaddr: Word,
    pub file_off: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub flags: u32,
}

impl LoadSegment {
    pub fn writable(&self) -> bool { (self.flags & PF_W) != 0 }
    pub fn executable(&self) -> bool { (self.flags & PF_X) != 0 }
    pub fn readable(&self) -> bool { (self.flags & PF_R) != 0 }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ElfError {
    NotEnoughBytes,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    BadVersion,
    NotX86_64,
    NotExecutable,
    BadPhdrSize,
}

// ---------------------------------------------------------------------------
// Parser entry.
// ---------------------------------------------------------------------------

pub fn parse(bytes: &[u8]) -> Result<Image<'_>, ElfError> {
    if bytes.len() < core::mem::size_of::<Elf64Ehdr>() {
        return Err(ElfError::NotEnoughBytes);
    }
    let h_ptr = bytes.as_ptr() as *const Elf64Ehdr;

    let ident: [u8; 16] = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_ident))
    };
    if ident[EI_MAG0] != ELFMAG0
        || ident[EI_MAG1] != ELFMAG1
        || ident[EI_MAG2] != ELFMAG2
        || ident[EI_MAG3] != ELFMAG3
    {
        return Err(ElfError::BadMagic);
    }
    if ident[EI_CLASS] != ELFCLASS64 {
        return Err(ElfError::NotElf64);
    }
    if ident[EI_DATA] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if ident[EI_VERSION] != EV_CURRENT {
        return Err(ElfError::BadVersion);
    }

    let e_machine = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_machine))
    };
    if e_machine != EM_X86_64 {
        return Err(ElfError::NotX86_64);
    }
    let e_type = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_type))
    };
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError::NotExecutable);
    }
    let e_phentsize = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_phentsize))
    };
    if e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
        return Err(ElfError::BadPhdrSize);
    }

    let entry = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_entry))
    };
    let phoff = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_phoff))
    };
    let phnum = unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_phnum))
    };

    let need_end = phoff
        .checked_add(phnum as u64 * e_phentsize as u64)
        .ok_or(ElfError::NotEnoughBytes)?;
    if (need_end as usize) > bytes.len() {
        return Err(ElfError::NotEnoughBytes);
    }

    Ok(Image { bytes, entry, phoff, phnum })
}

impl<'a> Image<'a> {
    /// Iterator over `PT_LOAD` segments. We don't expose other
    /// program-header types — the kernel only loads loadable
    /// segments and the rest (e.g. `PT_GNU_STACK`) are ignored.
    pub fn load_segments(&self) -> LoadSegments<'a> {
        LoadSegments { bytes: self.bytes, phoff: self.phoff, remaining: self.phnum }
    }
}

pub struct LoadSegments<'a> {
    bytes: &'a [u8],
    phoff: u64,
    remaining: u16,
}

impl<'a> Iterator for LoadSegments<'a> {
    type Item = LoadSegment;

    fn next(&mut self) -> Option<Self::Item> {
        let phdr_size = core::mem::size_of::<Elf64Phdr>();
        while self.remaining > 0 {
            let off = self.phoff as usize;
            self.phoff += phdr_size as u64;
            self.remaining -= 1;
            if off + phdr_size > self.bytes.len() {
                return None;
            }
            let p_ptr = unsafe {
                self.bytes.as_ptr().add(off) as *const Elf64Phdr
            };
            let p_type = unsafe {
                core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_type))
            };
            if p_type != PT_LOAD {
                continue;
            }
            unsafe {
                return Some(LoadSegment {
                    vaddr: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_vaddr)),
                    file_off: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_offset)),
                    file_size: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_filesz)),
                    mem_size: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_memsz)),
                    flags: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_flags)),
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_elf() {
        arch::log("Running ELF parser tests...\n");
        rejects_bogus_inputs();
        parses_embedded_rootserver();
        rootserver_segments_have_known_shape();
        arch::log("ELF parser tests completed\n");
    }

    #[inline(never)]
    fn rejects_bogus_inputs() {
        // Empty input.
        assert!(matches!(parse(&[]), Err(ElfError::NotEnoughBytes)));

        // Non-ELF magic.
        let mut not_elf = [0u8; 64];
        not_elf[0] = b'M';
        assert!(matches!(parse(&not_elf), Err(ElfError::BadMagic)));

        // Valid magic, wrong class (32-bit).
        let mut bad_class = [0u8; 64];
        bad_class[0] = ELFMAG0;
        bad_class[1] = ELFMAG1;
        bad_class[2] = ELFMAG2;
        bad_class[3] = ELFMAG3;
        bad_class[EI_CLASS] = 1; // ELFCLASS32
        bad_class[EI_DATA] = ELFDATA2LSB;
        bad_class[EI_VERSION] = EV_CURRENT;
        assert!(matches!(parse(&bad_class), Err(ElfError::NotElf64)));

        arch::log("  ✓ ELF parser rejects bogus inputs\n");
    }

    #[inline(never)]
    fn parses_embedded_rootserver() {
        let img = parse(crate::rootserver_image::rootserver_elf())
            .expect("rootserver ELF parses");
        // The linker script pins the image at 0x100_0040_0000
        // (PML4[2] + 4 MiB). The exact `_start` offset within the
        // text segment depends on what other code the linker
        // emitted ahead of it (panic_handler tables etc), but it
        // must lie within the linker-chosen vaddr range.
        const BASE: u64 = 0x0000_0100_0040_0000;
        const MAX:  u64 = BASE + 0x10_0000; // 1 MiB headroom
        assert!(img.entry >= BASE && img.entry < MAX,
            "rootserver entry {:#x} should be within [{:#x}, {:#x})",
            img.entry, BASE, MAX);
        arch::log("  ✓ embedded rootserver ELF parses + entry within link.ld range\n");
    }

    #[inline(never)]
    fn rootserver_segments_have_known_shape() {
        let img = parse(crate::rootserver_image::rootserver_elf()).unwrap();
        let mut count = 0u32;
        let mut saw_text = false;
        for seg in img.load_segments() {
            count += 1;
            // Every PT_LOAD must be readable.
            assert!(seg.readable(), "PT_LOAD segments must be readable");
            // No segment should be writable + executable simultaneously.
            assert!(!(seg.writable() && seg.executable()),
                "W+X segment violates W^X");
            // The text segment is at the entry address.
            if seg.vaddr <= img.entry
                && seg.vaddr + seg.mem_size > img.entry
                && seg.executable()
            {
                saw_text = true;
            }
        }
        assert!(count >= 1, "rootserver ELF must have at least one PT_LOAD");
        assert!(saw_text, "must have an executable PT_LOAD covering the entry");
        arch::log("  ✓ rootserver ELF segments are well-formed\n");
    }
}
