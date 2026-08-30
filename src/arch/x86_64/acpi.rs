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
    pub rsdt_address: u32, // physical addr of RSDT (revision 0)
    // Below fields exist only in rev ≥ 2 (XSDP):
    pub length: u32,
    pub xsdt_address: u64, // physical addr of XSDT
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
    let rev0_bytes = unsafe { core::slice::from_raw_parts(rsdp_addr as *const u8, 20) };
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
    let length = unsafe { read_unaligned(&raw const hdr.length) } as usize;
    if length < core::mem::size_of::<SdtHeader>() {
        return Err(AcpiError::BadLength);
    }
    let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, length) };
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
    LocalApic {
        processor_id: u8,
        apic_id: u8,
        flags: u32,
    },
    /// I/O APIC.
    IoApic {
        ioapic_id: u8,
        address: u32,
        gsi_base: u32,
    },
    /// Interrupt source override (e.g. PIT-on-IRQ-0 maps to GSI 2).
    IntSourceOverride {
        bus: u8,
        source: u8,
        gsi: u32,
        flags: u16,
    },
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
                MadtEntry::LocalApic {
                    processor_id,
                    apic_id,
                    flags,
                }
            },
            1 => unsafe {
                let ioapic_id = read_unaligned((entry_addr + 2) as *const u8);
                let address = read_unaligned((entry_addr + 4) as *const u32);
                let gsi_base = read_unaligned((entry_addr + 8) as *const u32);
                MadtEntry::IoApic {
                    ioapic_id,
                    address,
                    gsi_base,
                }
            },
            2 => unsafe {
                let bus = read_unaligned((entry_addr + 2) as *const u8);
                let source = read_unaligned((entry_addr + 3) as *const u8);
                let gsi = read_unaligned((entry_addr + 4) as *const u32);
                let flags = read_unaligned((entry_addr + 8) as *const u16);
                MadtEntry::IntSourceOverride {
                    bus,
                    source,
                    gsi,
                    flags,
                }
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
// DMAR — DMA Remapping table (Intel VT-d IOMMU). Present when QEMU is
// launched with `-machine q35 -device intel-iommu`.
// ---------------------------------------------------------------------------

pub const DMAR_SIGNATURE: &[u8; 4] = b"DMAR";

/// Walk the loader-provided RSDT/XSDT for one checksummed table signature.
pub fn find_table(sdt_addr: u64, wanted: &[u8; 4]) -> Result<u64, AcpiError> {
    let hdr = validate_sdt(sdt_addr)?;
    let sig: [u8; 4] = unsafe { read_unaligned(&raw const hdr.signature) };
    let length: u32 = unsafe { read_unaligned(&raw const hdr.length) };
    let entry_size: usize = match &sig {
        b"RSDT" => 4,
        b"XSDT" => 8,
        _ => return Err(AcpiError::BadSignature),
    };
    let header_size = core::mem::size_of::<SdtHeader>();
    let entries_base = sdt_addr + header_size as u64;
    let entry_count = (length as usize - header_size) / entry_size;
    for i in 0..entry_count {
        let entry_addr = entries_base + (i as u64) * entry_size as u64;
        let table_addr: u64 = match entry_size {
            4 => (unsafe { read_unaligned(entry_addr as *const u32) }) as u64,
            _ => unsafe { read_unaligned(entry_addr as *const u64) },
        };
        if let Ok(candidate) = validate_sdt(table_addr) {
            let candidate_signature: [u8; 4] =
                unsafe { read_unaligned(&raw const candidate.signature) };
            if candidate_signature == *wanted {
                return Ok(table_addr);
            }
        }
    }
    Err(AcpiError::NoTable)
}

/// Walk the RSDT/XSDT for the DMAR table; returns its physical address.
pub fn find_dmar(sdt_addr: u64) -> Result<u64, AcpiError> {
    find_table(sdt_addr, DMAR_SIGNATURE)
}

pub const FADT_SIGNATURE: &[u8; 4] = b"FACP";
const FADT_CENTURY_OFFSET: u64 = 108;
const FADT_IAPC_BOOT_ARCH_OFFSET: u64 = 109;
const FADT_IAPC_CMOS_RTC_NOT_PRESENT: u16 = 1 << 5;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PcRtcInfo {
    pub index_port: u16,
    pub data_port: u16,
    pub century_register: Option<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AcpiRootTableKind {
    Rsdt,
    Xsdt,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AcpiRootTableInfo {
    pub paddr: u64,
    pub length: u32,
    pub kind: AcpiRootTableKind,
}

/// Validate the loader-provided ACPI root table and retain its real physical extent for the initial
/// root task. BOOTBOOT has already consumed the RSDP and publishes the selected RSDT/XSDT address.
pub fn root_table_info(sdt_addr: u64) -> Result<AcpiRootTableInfo, AcpiError> {
    let header = validate_sdt(sdt_addr)?;
    let signature: [u8; 4] = unsafe { read_unaligned(&raw const header.signature) };
    let kind = match &signature {
        b"RSDT" => AcpiRootTableKind::Rsdt,
        b"XSDT" => AcpiRootTableKind::Xsdt,
        _ => return Err(AcpiError::BadSignature),
    };
    Ok(AcpiRootTableInfo {
        paddr: sdt_addr,
        length: unsafe { read_unaligned(&raw const header.length) },
        kind,
    })
}

/// Discover the fixed ACPI PC RTC resource. The FADT explicitly reports when CMOS RTC hardware is
/// absent; the optional century byte is used only when firmware publishes a non-zero register.
pub fn find_pc_rtc(sdt_addr: u64) -> Result<PcRtcInfo, AcpiError> {
    let fadt_addr = find_table(sdt_addr, FADT_SIGNATURE)?;
    let header = validate_sdt(fadt_addr)?;
    let length = unsafe { read_unaligned(&raw const header.length) } as u64;
    if length <= FADT_IAPC_BOOT_ARCH_OFFSET + 1 {
        return Err(AcpiError::BadLength);
    }
    let boot_arch =
        unsafe { read_unaligned((fadt_addr + FADT_IAPC_BOOT_ARCH_OFFSET) as *const u16) };
    if boot_arch & FADT_IAPC_CMOS_RTC_NOT_PRESENT != 0 {
        return Err(AcpiError::NoTable);
    }
    let century = unsafe { read_unaligned((fadt_addr + FADT_CENTURY_OFFSET) as *const u8) };
    Ok(PcRtcInfo {
        index_port: 0x70,
        data_port: 0x71,
        century_register: (century != 0).then_some(century),
    })
}

/// Parse the DMAR remapping structures for the first DRHD (DMA
/// Remapping Hardware unit Definition, type 0) and return its IOMMU
/// register base physical address. Layout after the 36-byte SDT header:
/// host_addr_width(u8), flags(u8), reserved[10]; then remapping
/// structures each `type(u16) length(u16) ...`; DRHD has the 64-bit
/// register base at struct-offset +8.
pub fn dmar_first_drhd_base(dmar_addr: u64) -> Option<u64> {
    let total_len =
        unsafe { read_unaligned(&raw const (*(dmar_addr as *const SdtHeader)).length) } as usize;
    let mut off = core::mem::size_of::<SdtHeader>() + 12; // +host_addr_width/flags/resv
    while off + 4 <= total_len {
        let ty: u16 = unsafe { read_unaligned((dmar_addr + off as u64) as *const u16) };
        let len: u16 = unsafe { read_unaligned((dmar_addr + (off + 2) as u64) as *const u16) };
        if len < 4 || off + len as usize > total_len {
            break;
        }
        if ty == 0 {
            // DRHD — register base at +8.
            let base: u64 = unsafe { read_unaligned((dmar_addr + (off + 8) as u64) as *const u64) };
            return Some(base);
        }
        off += len as usize;
    }
    None
}

// ---------------------------------------------------------------------------
// Errors and helpers.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AcpiError {
    NoTable,
    BadSignature,
    BadChecksum,
    BadLength,
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
    let table = find_table(sdt_addr, MADT_SIGNATURE)?;
    Ok(unsafe { &*(table as *const MadtHeader) })
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
        let sig: [u8; 4] =
            unsafe { core::ptr::read_unaligned(madt_ptr.cast::<SdtHeader>()).signature };
        assert_eq!(sig, *b"APIC");
        let lapic_addr: u32 = unsafe {
            core::ptr::read_unaligned(
                (madt_ptr as *const u8).add(core::mem::size_of::<SdtHeader>()) as *const u32,
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
