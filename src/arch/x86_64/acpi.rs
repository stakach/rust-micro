//! Phase 12e — minimal ACPI table parsing.
//!
//! Walks the ACPI Root System Descriptor (RSDP → RSDT/XSDT → MADT)
//! to discover CPU count and the IOAPIC base address. We don't bring
//! in the AML interpreter or any of the other higher-level ACPI
//! cruft — just the fixed-format tables seL4 actually consumes for
//! SMP enumeration and interrupt-controller setup.
//!
//! BOOTBOOT hands us the RSDP pointer in `BOOTBOOT.arch.x86_64.acpi_ptr`.
//! Tables live at low physical addresses; we read them through the
//! identity mapping BOOTBOOT preserves for the loader range. (When
//! that mapping isn't there we'd fault — same caveat as the LAPIC
//! driver. QEMU + BOOTBOOT in default config does keep low memory
//! mapped, which the spec confirms.)

use core::ptr::read_unaligned;

// ---------------------------------------------------------------------------
// RSDP — Root System Descriptor Pointer.
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Rsdp {
    pub signature: [u8; 8], // "RSD PTR "
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,  // physical addr of RSDT (revision 0)
    // Below fields exist only in rev ≥ 2 (XSDP):
    pub length: u32,
    pub xsdt_address: u64,  // physical addr of XSDT
    pub extended_checksum: u8,
    pub _reserved: [u8; 3],
}

const RSDP_SIG: &[u8; 8] = b"RSD PTR ";

/// Validate an RSDP's signature and checksum.
pub fn validate_rsdp(rsdp_addr: u64) -> Result<&'static Rsdp, AcpiError> {
    if rsdp_addr == 0 {
        return Err(AcpiError::NoTable);
    }
    let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };
    if rsdp.signature != *RSDP_SIG {
        return Err(AcpiError::BadSignature);
    }
    // Revision 0 only checksums the first 20 bytes.
    let rev0_bytes = unsafe {
        core::slice::from_raw_parts(rsdp_addr as *const u8, 20)
    };
    if checksum8(rev0_bytes) != 0 {
        return Err(AcpiError::BadChecksum);
    }
    Ok(rsdp)
}

// ---------------------------------------------------------------------------
// SDT (System Description Table) header.
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

pub fn validate_sdt(addr: u64) -> Result<&'static SdtHeader, AcpiError> {
    if addr == 0 {
        return Err(AcpiError::NoTable);
    }
    let hdr = unsafe { &*(addr as *const SdtHeader) };
    let bytes = unsafe {
        core::slice::from_raw_parts(addr as *const u8, hdr.length as usize)
    };
    if checksum8(bytes) != 0 {
        return Err(AcpiError::BadChecksum);
    }
    Ok(hdr)
}

// ---------------------------------------------------------------------------
// MADT — Multiple APIC Description Table.
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct MadtHeader {
    pub sdt: SdtHeader,
    pub local_apic_addr: u32,
    pub flags: u32,
}

pub const MADT_SIGNATURE: &[u8; 4] = b"APIC";

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MadtEntry {
    /// CPU local APIC. 8259 PIC-style processor entry.
    LocalApic { processor_id: u8, apic_id: u8, flags: u32 },
    /// I/O APIC.
    IoApic { ioapic_id: u8, address: u32, gsi_base: u32 },
    /// Interrupt source override (e.g. PIT-on-IRQ-0 maps to GSI 2).
    IntSourceOverride { bus: u8, source: u8, gsi: u32, flags: u16 },
    /// Anything else we don't decode yet.
    Other { kind: u8, len: u8 },
}

/// Walk the MADT entries, calling `f` once per entry. Returns the
/// number of entries iterated.
pub fn iter_madt_entries<F: FnMut(MadtEntry)>(madt: &MadtHeader, mut f: F) -> usize {
    let total_len = madt.sdt.length as usize;
    let header_len = core::mem::size_of::<MadtHeader>();
    let madt_addr = madt as *const MadtHeader as u64;
    let mut offset = header_len;
    let mut n = 0;
    while offset + 2 <= total_len {
        let kind: u8 = unsafe { read_unaligned((madt_addr + offset as u64) as *const u8) };
        let len: u8 = unsafe { read_unaligned((madt_addr + (offset + 1) as u64) as *const u8) };
        if len < 2 || offset + len as usize > total_len {
            break;
        }
        let entry_addr = madt_addr + offset as u64;
        let entry = match kind {
            0 => unsafe {
                let processor_id = read_unaligned((entry_addr + 2) as *const u8);
                let apic_id = read_unaligned((entry_addr + 3) as *const u8);
                let flags = read_unaligned((entry_addr + 4) as *const u32);
                MadtEntry::LocalApic { processor_id, apic_id, flags }
            },
            1 => unsafe {
                let ioapic_id = read_unaligned((entry_addr + 2) as *const u8);
                let address = read_unaligned((entry_addr + 4) as *const u32);
                let gsi_base = read_unaligned((entry_addr + 8) as *const u32);
                MadtEntry::IoApic { ioapic_id, address, gsi_base }
            },
            2 => unsafe {
                let bus = read_unaligned((entry_addr + 2) as *const u8);
                let source = read_unaligned((entry_addr + 3) as *const u8);
                let gsi = read_unaligned((entry_addr + 4) as *const u32);
                let flags = read_unaligned((entry_addr + 8) as *const u16);
                MadtEntry::IntSourceOverride { bus, source, gsi, flags }
            },
            _ => MadtEntry::Other { kind, len },
        };
        f(entry);
        n += 1;
        offset += len as usize;
    }
    n
}

// ---------------------------------------------------------------------------
// Errors and helpers.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AcpiError {
    NoTable,
    BadSignature,
    BadChecksum,
}

fn checksum8(bytes: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for b in bytes {
        sum = sum.wrapping_add(*b);
    }
    sum
}

/// Top-level helper: from BOOTBOOT's `acpi_ptr`, find the MADT.
///
/// Note: the loader hands us the (X)SDT physical address directly
/// in `BOOTBOOT.arch.x86_64.acpi_ptr` — RSDP scanning happens
/// inside the loader. We accept either an RSDT (32-bit entries) or
/// an XSDT (64-bit entries) and walk accordingly.
pub fn find_madt(sdt_addr: u64) -> Result<&'static MadtHeader, AcpiError> {
    let hdr = validate_sdt(sdt_addr)?;
    let sig: [u8; 4] = unsafe { read_unaligned(&raw const hdr.signature) };
    let length: u32 = unsafe { read_unaligned(&raw const hdr.length) };
    let entry_size: usize = match &sig {
        b"RSDT" => 4,
        b"XSDT" => 8,
        _ => return Err(AcpiError::BadSignature),
    };
    let entries_base = sdt_addr + core::mem::size_of::<SdtHeader>() as u64;
    let entry_count = (length as usize - core::mem::size_of::<SdtHeader>()) / entry_size;
    for i in 0..entry_count {
        let entry_addr = entries_base + (i as u64) * entry_size as u64;
        let table_addr: u64 = match entry_size {
            4 => (unsafe { read_unaligned(entry_addr as *const u32) }) as u64,
            _ => unsafe { read_unaligned(entry_addr as *const u64) },
        };
        if let Ok(hdr2) = validate_sdt(table_addr) {
            let sig2: [u8; 4] = unsafe { read_unaligned(&raw const hdr2.signature) };
            if sig2 == *MADT_SIGNATURE {
                return Ok(unsafe { &*(table_addr as *const MadtHeader) });
            }
        }
    }
    Err(AcpiError::NoTable)
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::bootboot::*;

    pub fn test_acpi() {
        arch::log("Running ACPI tests...\n");
        bootboot_provides_sdt_pointer();
        sdt_signature_is_rsdt_or_xsdt();
        rsdt_walks_to_madt();
        madt_lists_at_least_one_lapic();
        arch::log("ACPI tests completed\n");
    }

    fn rsdp_addr() -> u64 {
        let bootboot = unsafe { &*(BOOTBOOT_INFO as *const BOOTBOOT) };
        unsafe { bootboot.arch.x86_64 }.acpi_ptr
    }

    #[inline(never)]
    fn bootboot_provides_sdt_pointer() {
        let p = rsdp_addr();
        assert!(p != 0, "BOOTBOOT must hand us the (X)SDT physical address");
        arch::log("  ✓ BOOTBOOT.arch.x86.acpi_ptr is non-null\n");
    }

    #[inline(never)]
    fn sdt_signature_is_rsdt_or_xsdt() {
        let hdr = validate_sdt(rsdp_addr()).expect("SDT must validate");
        let sig: [u8; 4] = unsafe { core::ptr::read_unaligned(&raw const hdr.signature) };
        assert!(
            sig == *b"RSDT" || sig == *b"XSDT",
            "BOOTBOOT acpi_ptr should land on an RSDT or XSDT",
        );
        arch::log("  ✓ acpi_ptr lands on an RSDT or XSDT\n");
    }

    #[inline(never)]
    fn rsdt_walks_to_madt() {
        let madt = find_madt(rsdp_addr()).expect("MADT must be findable from RSDT");
        // The header is packed — pull values out via raw pointer
        // reads to avoid taking unaligned references.
        let madt_ptr = madt as *const MadtHeader;
        let sig: [u8; 4] = unsafe {
            core::ptr::read_unaligned(madt_ptr.cast::<SdtHeader>())
                .signature
        };
        assert_eq!(sig, *b"APIC");
        let lapic_addr: u32 = unsafe {
            core::ptr::read_unaligned(
                (madt_ptr as *const u8).add(core::mem::size_of::<SdtHeader>())
                    as *const u32,
            )
        };
        assert_eq!(lapic_addr, 0xFEE0_0000);
        arch::log("  ✓ MADT found via RSDT walk; LAPIC addr = 0xFEE00000\n");
    }

    #[inline(never)]
    fn madt_lists_at_least_one_lapic() {
        let madt = find_madt(rsdp_addr()).unwrap();
        let mut n_lapic = 0;
        let mut n_ioapic = 0;
        iter_madt_entries(madt, |e| match e {
            MadtEntry::LocalApic { .. } => n_lapic += 1,
            MadtEntry::IoApic { .. } => n_ioapic += 1,
            _ => {}
        });
        assert!(n_lapic >= 1, "MADT must list ≥ 1 LocalApic entry");
        assert!(n_ioapic >= 1, "MADT must list ≥ 1 IoApic entry");
        arch::log("  ✓ MADT lists ≥1 LocalApic + ≥1 IoApic\n");
    }
}
