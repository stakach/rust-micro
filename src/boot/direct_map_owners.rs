//! Page-aligned boot owners inside firmware-reserved RAM.
//!
//! The MBI, modules, kernel image, and loader page tables may cross firmware
//! descriptors or overlap each other. A sparse direct map needs their union,
//! but must never infer RAM from an MMIO descriptor or an unreported hole.

use super::direct_map_policy::{
    valid_range, FirmwareKind, FirmwareRange, PhysicalRange, PlanError,
};

const MAX_RESERVED_RAM_RANGES: usize = 128;
const EMPTY: PhysicalRange = PhysicalRange { start: 0, end: 0 };

fn insert_union(
    ranges: &mut [PhysicalRange; MAX_RESERVED_RAM_RANGES],
    count: &mut usize,
    mut range: PhysicalRange,
) -> Result<(), PlanError> {
    let mut index = 0;
    while index < *count {
        let current = ranges[index];
        if range.start <= current.end && current.start <= range.end {
            range.start = range.start.min(current.start);
            range.end = range.end.max(current.end);
            *count -= 1;
            ranges[index] = ranges[*count];
        } else {
            index += 1;
        }
    }
    if *count == ranges.len() {
        return Err(PlanError::OutputTooSmall);
    }
    ranges[*count] = range;
    *count += 1;
    Ok(())
}

/// Intersect explicit boot-owned physical pages with reserved firmware RAM.
///
/// All owner pages must be covered by a firmware descriptor; device overlap
/// and gaps refuse the whole result. Output is published only after the full
/// union and capacity check pass.
pub fn collect_reserved_ram(
    firmware: &[FirmwareRange],
    owners: &[PhysicalRange],
    output: &mut [PhysicalRange],
) -> Result<usize, PlanError> {
    for (index, entry) in firmware.iter().enumerate() {
        if !valid_range(entry.range) {
            return Err(PlanError::InvalidRange);
        }
        if firmware[..index]
            .iter()
            .any(|prior| prior.range.overlaps(entry.range))
        {
            return Err(PlanError::AmbiguousOverlap);
        }
    }
    let mut staged = [EMPTY; MAX_RESERVED_RAM_RANGES];
    let mut count = 0;
    for owner in owners.iter().copied() {
        if !valid_range(owner) {
            return Err(PlanError::InvalidRange);
        }
        let mut at = owner.start;
        while at < owner.end {
            let entry = firmware
                .iter()
                .find(|entry| entry.range.start <= at && at < entry.range.end)
                .ok_or(PlanError::UnprovenReservedRam)?;
            let end = owner.end.min(entry.range.end);
            match entry.kind {
                FirmwareKind::Ram | FirmwareKind::AcpiRam => {}
                FirmwareKind::Reserved => {
                    insert_union(&mut staged, &mut count, PhysicalRange { start: at, end })?
                }
                FirmwareKind::Mmio => return Err(PlanError::AmbiguousOverlap),
            }
            at = end;
        }
    }
    if count > output.len() {
        return Err(PlanError::OutputTooSmall);
    }
    staged[..count].sort_unstable_by_key(|range| range.start);
    output[..count].copy_from_slice(&staged[..count]);
    Ok(count)
}
