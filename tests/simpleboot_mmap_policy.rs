//! Host contracts for checked Simpleboot memory-map conversion.
//!
//! Native paging must not consume an incomplete or contradictory memory map.

#[allow(dead_code)]
#[path = "../src/boot/direct_map_policy.rs"]
mod direct_map_policy;
#[path = "../src/boot/simpleboot_mmap_policy.rs"]
mod simpleboot_mmap_policy;

use direct_map_policy::{FirmwareKind, FirmwareRange, PhysicalRange};
use simpleboot_mmap_policy::{
    convert_simpleboot_mmap, ConvertError, RawMmapEntry, MAX_SIMPLEBOOT_MMAP_ENTRIES,
};

const KIB4: u64 = 1 << 12;
const GIB1: u64 = 1 << 30;
const AVAILABLE: u32 = 1;
const BIOS_RESERVED: u32 = 2;
const ACPI_RECLAIMABLE: u32 = 3;
const ACPI_NVS: u32 = 4;
const EFI_MMIO: u32 = 11;
const EFI_MMIO_PORT_SPACE: u32 = 12;

fn raw(start: u64, length: u64, entry_type: u32, reserved: u32) -> RawMmapEntry {
    RawMmapEntry {
        base_addr: start,
        length,
        entry_type,
        reserved,
    }
}

fn mapped(start: u64, end: u64, kind: FirmwareKind) -> FirmwareRange {
    FirmwareRange {
        range: PhysicalRange { start, end },
        kind,
    }
}

fn output() -> [FirmwareRange; MAX_SIMPLEBOOT_MMAP_ENTRIES] {
    [mapped(u64::MAX, u64::MAX, FirmwareKind::Reserved); MAX_SIMPLEBOOT_MMAP_ENTRIES]
}

#[test]
fn multiboot_and_efi_types_preserve_ram_acpi_and_both_mmio_classes() {
    let entries = [
        raw(0, GIB1, AVAILABLE, 7),
        raw(GIB1, GIB1, BIOS_RESERVED, 0),
        raw(2 * GIB1, GIB1, BIOS_RESERVED, EFI_MMIO),
        raw(3 * GIB1, GIB1, BIOS_RESERVED, EFI_MMIO_PORT_SPACE),
        raw(4 * GIB1, GIB1, ACPI_RECLAIMABLE, 9),
        raw(5 * GIB1, GIB1, ACPI_NVS, 10),
    ];
    let mut converted = output();
    let count = convert_simpleboot_mmap(&entries, &mut converted).unwrap();
    assert_eq!(
        &converted[..count],
        &[
            mapped(0, GIB1, FirmwareKind::Ram),
            mapped(GIB1, 2 * GIB1, FirmwareKind::Reserved),
            mapped(2 * GIB1, 3 * GIB1, FirmwareKind::Mmio),
            mapped(3 * GIB1, 4 * GIB1, FirmwareKind::Mmio),
            mapped(4 * GIB1, 5 * GIB1, FirmwareKind::AcpiRam),
            mapped(5 * GIB1, 6 * GIB1, FirmwareKind::AcpiRam),
        ]
    );
}

#[test]
fn bios_reserved_without_native_type_stays_ambiguous_and_unmapped() {
    let mut converted = output();
    let count = convert_simpleboot_mmap(&[raw(0xA0000, 0x60000, BIOS_RESERVED, 0)], &mut converted)
        .unwrap();
    assert_eq!(
        &converted[..count],
        &[mapped(0xA0000, 0x100000, FirmwareKind::Reserved)]
    );
}

#[test]
fn partial_ram_pages_are_dropped_and_device_pages_are_excluded_outward() {
    let entries = [
        raw(0x1800, 0x3000, AVAILABLE, 0),
        raw(0x4801, 0x1000, BIOS_RESERVED, EFI_MMIO),
        raw(0x8001, 0x1000, BIOS_RESERVED, 0),
    ];
    let mut converted = output();
    let count = convert_simpleboot_mmap(&entries, &mut converted).unwrap();
    assert_eq!(
        &converted[..count],
        &[
            mapped(2 * KIB4, 4 * KIB4, FirmwareKind::Ram),
            mapped(4 * KIB4, 6 * KIB4, FirmwareKind::Mmio),
            mapped(8 * KIB4, 10 * KIB4, FirmwareKind::Reserved),
        ]
    );
}

#[test]
fn overflowing_or_contradictory_entry_fails_without_partial_output() {
    for entries in [
        [
            raw(0, KIB4, AVAILABLE, 0),
            raw(u64::MAX - 8, 16, BIOS_RESERVED, 0),
        ],
        [
            raw(0, KIB4, AVAILABLE, 0),
            raw(KIB4, KIB4, AVAILABLE, EFI_MMIO),
        ],
    ] {
        let mut converted = output();
        let before = converted;
        assert_eq!(
            convert_simpleboot_mmap(&entries, &mut converted),
            Err(ConvertError::InvalidEntry)
        );
        assert_eq!(converted, before);
    }
}

#[test]
fn more_than_240_entries_fails_instead_of_silently_truncating() {
    let entries = [raw(0, KIB4, BIOS_RESERVED, 0); MAX_SIMPLEBOOT_MMAP_ENTRIES + 1];
    let mut converted = output();
    let before = converted;
    assert_eq!(
        convert_simpleboot_mmap(&entries, &mut converted),
        Err(ConvertError::TooManyEntries)
    );
    assert_eq!(converted, before);
}

#[test]
fn page_rounding_cannot_turn_a_ram_device_collision_into_success() {
    let entries = [
        raw(0, 2 * KIB4, AVAILABLE, 0),
        raw(2 * KIB4 - 1, 2, BIOS_RESERVED, EFI_MMIO),
    ];
    let mut converted = output();
    let before = converted;
    assert_eq!(
        convert_simpleboot_mmap(&entries, &mut converted),
        Err(ConvertError::AmbiguousOverlap)
    );
    assert_eq!(converted, before);
}
