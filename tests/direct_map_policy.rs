//! Host contracts for the kernel physical direct-map admission plan.
//!
//! This pure policy must finish validation and sizing before page-table writes.

#[path = "../src/boot/direct_map_policy.rs"]
mod direct_map_policy;

use direct_map_policy::{
    plan_direct_map, FirmwareKind, FirmwareRange, MapLeaf, PageSize, PhysicalRange, PlanError,
};

const KIB4: u64 = 1 << 12;
const MIB2: u64 = 1 << 21;
const GIB1: u64 = 1 << 30;
const LIMIT: u64 = 8 * GIB1;

fn range(start: u64, end: u64) -> PhysicalRange {
    PhysicalRange { start, end }
}

fn firmware(start: u64, end: u64, kind: FirmwareKind) -> FirmwareRange {
    FirmwareRange {
        range: range(start, end),
        kind,
    }
}

fn leaf(start: u64, size: PageSize) -> MapLeaf {
    MapLeaf { start, size }
}

fn output() -> [MapLeaf; 16] {
    [leaf(u64::MAX, PageSize::Size4K); 16]
}

#[test]
fn usable_and_acpi_ram_are_mapped_but_reserved_and_mmio_holes_are_not() {
    let map = [
        firmware(0, GIB1, FirmwareKind::Ram),
        firmware(GIB1, 2 * GIB1, FirmwareKind::Reserved),
        firmware(2 * GIB1, 2 * GIB1 + MIB2, FirmwareKind::AcpiRam),
        firmware(2 * GIB1 + MIB2, 4 * GIB1, FirmwareKind::Mmio),
        // Rootserver RAM above the PCI hole must remain reachable.
        firmware(4 * GIB1, 5 * GIB1, FirmwareKind::Ram),
    ];
    let mut leaves = output();
    let count = plan_direct_map(&map, &[], &[], LIMIT, &mut leaves).unwrap();
    assert_eq!(
        &leaves[..count],
        &[
            leaf(0, PageSize::Size1G),
            leaf(2 * GIB1, PageSize::Size2M),
            leaf(4 * GIB1, PageSize::Size1G),
        ]
    );
}

#[test]
fn only_explicitly_identified_reserved_ram_gets_an_alias() {
    let map = [firmware(8 * MIB2, 10 * MIB2, FirmwareKind::Reserved)];
    let mut leaves = output();
    let count = plan_direct_map(
        &map,
        &[range(8 * MIB2, 8 * MIB2 + KIB4)],
        &[],
        LIMIT,
        &mut leaves,
    )
    .unwrap();
    assert_eq!(&leaves[..count], &[leaf(8 * MIB2, PageSize::Size4K)]);
}

#[test]
fn framebuffer_inside_pci_bar_is_one_unmapped_device_hole() {
    let map = [
        firmware(0, MIB2, FirmwareKind::Ram),
        firmware(MIB2, 2 * MIB2, FirmwareKind::Reserved),
        firmware(2 * MIB2, 3 * MIB2, FirmwareKind::Ram),
    ];
    // A framebuffer is commonly a subrange of its containing PCI BAR.
    let devices = [range(MIB2, 2 * MIB2), range(MIB2 + KIB4, MIB2 + 3 * KIB4)];
    let mut leaves = output();
    let count = plan_direct_map(&map, &[], &devices, LIMIT, &mut leaves).unwrap();
    assert_eq!(
        &leaves[..count],
        &[leaf(0, PageSize::Size2M), leaf(2 * MIB2, PageSize::Size2M)]
    );
}

#[test]
fn ram_edges_split_at_four_kib_two_mebibyte_and_one_gibibyte() {
    let map = [
        firmware(GIB1 - KIB4, GIB1, FirmwareKind::Ram),
        firmware(GIB1, 2 * GIB1, FirmwareKind::Ram),
        firmware(2 * GIB1, 2 * GIB1 + MIB2, FirmwareKind::Ram),
        firmware(2 * GIB1 + MIB2, 2 * GIB1 + MIB2 + KIB4, FirmwareKind::Mmio),
        firmware(
            2 * GIB1 + MIB2 + KIB4,
            2 * GIB1 + MIB2 + 2 * KIB4,
            FirmwareKind::Ram,
        ),
    ];
    let mut leaves = output();
    let count = plan_direct_map(&map, &[], &[], LIMIT, &mut leaves).unwrap();
    assert_eq!(
        &leaves[..count],
        &[
            leaf(GIB1 - KIB4, PageSize::Size4K),
            leaf(GIB1, PageSize::Size1G),
            leaf(2 * GIB1, PageSize::Size2M),
            leaf(2 * GIB1 + MIB2 + KIB4, PageSize::Size4K),
        ]
    );
}

#[test]
fn firmware_ram_past_direct_map_limit_is_clipped_once() {
    let map = [firmware(7 * GIB1, 9 * GIB1, FirmwareKind::Ram)];
    let mut leaves = output();
    let count = plan_direct_map(&map, &[], &[], LIMIT, &mut leaves).unwrap();
    assert_eq!(&leaves[..count], &[leaf(7 * GIB1, PageSize::Size1G)]);
}

#[test]
fn ambiguous_ram_device_or_firmware_overlaps_fail_before_output_changes() {
    let cases: [(&[FirmwareRange], &[PhysicalRange], &[PhysicalRange]); 3] = [
        (
            &[firmware(0, MIB2, FirmwareKind::Ram)],
            &[],
            &[range(KIB4, 2 * KIB4)],
        ),
        (
            &[firmware(0, MIB2, FirmwareKind::Reserved)],
            &[range(KIB4, 2 * KIB4)],
            &[range(KIB4, 2 * KIB4)],
        ),
        (
            &[
                firmware(0, MIB2, FirmwareKind::Ram),
                firmware(MIB2 - KIB4, 2 * MIB2, FirmwareKind::Reserved),
            ],
            &[],
            &[],
        ),
    ];
    for (map, reserved_ram, devices) in cases {
        let mut leaves = output();
        let before = leaves;
        assert_eq!(
            plan_direct_map(map, reserved_ram, devices, LIMIT, &mut leaves),
            Err(PlanError::AmbiguousOverlap)
        );
        assert_eq!(leaves, before, "failure must precede page-table effects");
    }
}
