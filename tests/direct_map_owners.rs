//! Boot-owned RAM in firmware-reserved descriptors must be explicit and bounded.

#[path = "../src/boot/direct_map_owners.rs"]
mod direct_map_owners;
#[path = "../src/boot/direct_map_policy.rs"]
mod direct_map_policy;

use direct_map_owners::collect_reserved_ram;
use direct_map_policy::{FirmwareKind, FirmwareRange, PhysicalRange, PlanError};

const KIB4: u64 = 4096;
const MIB1: u64 = 1 << 20;

fn range(start: u64, end: u64) -> PhysicalRange {
    PhysicalRange { start, end }
}

fn entry(start: u64, end: u64, kind: FirmwareKind) -> FirmwareRange {
    FirmwareRange {
        range: range(start, end),
        kind,
    }
}

#[test]
fn reserved_owner_intersections_are_unioned_without_admitting_device_pages() {
    let firmware = [
        entry(0, MIB1, FirmwareKind::Ram),
        entry(MIB1, 2 * MIB1, FirmwareKind::Reserved),
        entry(2 * MIB1, 3 * MIB1, FirmwareKind::Mmio),
        entry(3 * MIB1, 4 * MIB1, FirmwareKind::Reserved),
    ];
    let owners = [
        range(MIB1 - KIB4, MIB1 + 3 * KIB4),
        range(MIB1 + 2 * KIB4, MIB1 + 8 * KIB4),
        range(3 * MIB1, 3 * MIB1 + KIB4),
    ];
    let sentinel = range(u64::MAX, u64::MAX);
    let mut output = [sentinel; 4];
    let count = collect_reserved_ram(&firmware, &owners, &mut output).unwrap();
    assert_eq!(
        &output[..count],
        &[
            range(MIB1, MIB1 + 8 * KIB4),
            range(3 * MIB1, 3 * MIB1 + KIB4)
        ]
    );
    assert_eq!(&output[count..], &[sentinel; 2]);
}

#[test]
fn malformed_owner_device_collision_and_capacity_refuse_atomically() {
    let firmware = [
        entry(0, MIB1, FirmwareKind::Ram),
        entry(MIB1, 2 * MIB1, FirmwareKind::Reserved),
        entry(2 * MIB1, 3 * MIB1, FirmwareKind::Mmio),
        entry(3 * MIB1, 4 * MIB1, FirmwareKind::Reserved),
    ];
    let sentinel = range(u64::MAX, u64::MAX);
    for (owners, expected) in [
        (vec![range(MIB1 + 1, MIB1 + KIB4)], PlanError::InvalidRange),
        (
            vec![range(2 * MIB1, 2 * MIB1 + KIB4)],
            PlanError::AmbiguousOverlap,
        ),
        (
            vec![range(4 * MIB1, 4 * MIB1 + KIB4)],
            PlanError::UnprovenReservedRam,
        ),
        (
            vec![range(MIB1, MIB1 + KIB4), range(3 * MIB1, 3 * MIB1 + KIB4)],
            PlanError::OutputTooSmall,
        ),
    ] {
        let mut output = [sentinel; 1];
        assert_eq!(
            collect_reserved_ram(&firmware, &owners, &mut output),
            Err(expected)
        );
        assert_eq!(output, [sentinel]);
    }
}

#[test]
fn ordinary_and_acpi_ram_need_no_reserved_alias() {
    let firmware = [
        entry(0, MIB1, FirmwareKind::Ram),
        entry(MIB1, 2 * MIB1, FirmwareKind::AcpiRam),
    ];
    let sentinel = range(u64::MAX, u64::MAX);
    let mut output = [sentinel; 1];
    assert_eq!(
        collect_reserved_ram(
            &firmware,
            &[range(0, KIB4), range(MIB1, MIB1 + KIB4)],
            &mut output
        ),
        Ok(0)
    );
    assert_eq!(output, [sentinel]);
}
