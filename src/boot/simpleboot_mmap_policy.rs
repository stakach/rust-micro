//! Checked, page-granular interpretation of Simpleboot's memory map.
//!
//! This module is pure so admission can be tested before any page-table effect.

use super::direct_map_policy::{FirmwareKind, FirmwareRange, PhysicalRange};

pub const MAX_SIMPLEBOOT_MMAP_ENTRIES: usize = 240;
const PAGE_SIZE: u64 = 4096;
const MULTIBOOT_AVAILABLE: u32 = 1;
const MULTIBOOT_ACPI_RECLAIMABLE: u32 = 3;
const MULTIBOOT_ACPI_NVS: u32 = 4;
const EFI_MEMORY_MAPPED_IO: u32 = 11;
const EFI_MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawMmapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConvertError {
    TooManyEntries,
    InvalidEntry,
    AmbiguousOverlap,
    OutputTooSmall,
}

/// The firmware's byte-exact classification, before page normalization.
pub fn classify_simpleboot_kind(raw: RawMmapEntry) -> Result<FirmwareKind, ConvertError> {
    let native_mmio =
        raw.reserved == EFI_MEMORY_MAPPED_IO || raw.reserved == EFI_MEMORY_MAPPED_IO_PORT_SPACE;
    let kind = match raw.entry_type {
        MULTIBOOT_AVAILABLE if native_mmio => return Err(ConvertError::InvalidEntry),
        MULTIBOOT_AVAILABLE => FirmwareKind::Ram,
        MULTIBOOT_ACPI_RECLAIMABLE | MULTIBOOT_ACPI_NVS if native_mmio => {
            return Err(ConvertError::InvalidEntry);
        }
        MULTIBOOT_ACPI_RECLAIMABLE | MULTIBOOT_ACPI_NVS => FirmwareKind::AcpiRam,
        _ if native_mmio => FirmwareKind::Mmio,
        _ => FirmwareKind::Reserved,
    };
    Ok(kind)
}

fn convert_entry(raw: RawMmapEntry) -> Result<Option<FirmwareRange>, ConvertError> {
    let end = raw
        .base_addr
        .checked_add(raw.length)
        .filter(|end| *end > raw.base_addr)
        .ok_or(ConvertError::InvalidEntry)?;
    let kind = classify_simpleboot_kind(raw)?;
    let (start, end) = match kind {
        // A partial RAM page is never admitted: its other bytes may belong to a device.
        FirmwareKind::Ram | FirmwareKind::AcpiRam => (
            raw.base_addr
                .checked_add(PAGE_SIZE - 1)
                .ok_or(ConvertError::InvalidEntry)?
                & !(PAGE_SIZE - 1),
            end & !(PAGE_SIZE - 1),
        ),
        // Every page touched by reserved or device memory is excluded.
        FirmwareKind::Reserved | FirmwareKind::Mmio => (
            raw.base_addr & !(PAGE_SIZE - 1),
            end.checked_add(PAGE_SIZE - 1)
                .ok_or(ConvertError::InvalidEntry)?
                & !(PAGE_SIZE - 1),
        ),
    };
    if start >= end {
        return Ok(None);
    }
    Ok(Some(FirmwareRange {
        range: PhysicalRange { start, end },
        kind,
    }))
}

/// Validate the whole raw map and output capacity before changing `output`.
/// Callers must reject a source iterator that yields more than the fixed limit.
pub fn convert_simpleboot_mmap(
    raw: &[RawMmapEntry],
    output: &mut [FirmwareRange],
) -> Result<usize, ConvertError> {
    if raw.len() > MAX_SIMPLEBOOT_MMAP_ENTRIES {
        return Err(ConvertError::TooManyEntries);
    }
    let mut count = 0usize;
    for (index, entry) in raw.iter().copied().enumerate() {
        let Some(converted) = convert_entry(entry)? else {
            continue;
        };
        for prior in &raw[..index] {
            let Some(previous) = convert_entry(*prior)? else {
                continue;
            };
            if converted.range.start < previous.range.end
                && previous.range.start < converted.range.end
            {
                return Err(ConvertError::AmbiguousOverlap);
            }
        }
        count += 1;
    }
    if count > output.len() {
        return Err(ConvertError::OutputTooSmall);
    }
    let mut written = 0;
    for entry in raw.iter().copied() {
        if let Some(converted) = convert_entry(entry)? {
            output[written] = converted;
            written += 1;
        }
    }
    Ok(written)
}
