//! Pure physical-address admission and leaf sizing for the kernel direct map.
//!
//! Input ranges are page aligned. The caller must identify retained RAM inside
//! firmware-reserved areas and page-round device apertures before invoking this
//! policy. No page table is touched until the complete plan fits the output.

const PAGE_4K: u64 = 1 << 12;
const PAGE_2M: u64 = 1 << 21;
const PAGE_1G: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    pub start: u64,
    pub end: u64,
}

impl PhysicalRange {
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareKind {
    Ram,
    AcpiRam,
    Reserved,
    Mmio,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareRange {
    pub range: PhysicalRange,
    pub kind: FirmwareKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageSize {
    Size4K,
    Size2M,
    Size1G,
}

impl PageSize {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size4K => PAGE_4K,
            Self::Size2M => PAGE_2M,
            Self::Size1G => PAGE_1G,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapLeaf {
    pub start: u64,
    pub size: PageSize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    InvalidRange,
    AmbiguousOverlap,
    UnprovenReservedRam,
    OutputTooSmall,
    PoolExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableDemand {
    pub pdpt_pages: usize,
    pub pd_pages: usize,
    pub pt_pages: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TablePool {
    pub used: usize,
    pub reserved: usize,
    pub capacity: usize,
}

/// Count table pages for a direct map before any page-table allocation.
///
/// One PML4 slot has one PDPT. A 1 GiB leaf ends there; smaller leaves
/// share one PD per 1 GiB window, and 4 KiB leaves share one PT per 2 MiB
/// window. `pool.reserved` accounts for early mappings outside this map.
/// The output changes only after the checked map and whole pool fit.
pub fn count_direct_map_tables(
    firmware: &[FirmwareRange],
    reserved_ram: &[PhysicalRange],
    devices: &[PhysicalRange],
    limit: u64,
    pool: TablePool,
    output: &mut TableDemand,
) -> Result<(), PlanError> {
    // This policy budgets one PDPT/PML4 slot, which covers at most 512 GiB.
    if limit > 512 * PAGE_1G {
        return Err(PlanError::InvalidRange);
    }
    validate(firmware, reserved_ram, devices, limit)?;
    let mut demand = TableDemand {
        pdpt_pages: 1,
        pd_pages: 0,
        pt_pages: 0,
    };
    let mut last_pd_window = None;
    let mut last_pt_window = None;
    walk_leaves(firmware, reserved_ram, limit, |leaf| {
        if leaf.size != PageSize::Size1G {
            let window = leaf.start / PAGE_1G;
            if last_pd_window != Some(window) {
                demand.pd_pages = demand
                    .pd_pages
                    .checked_add(1)
                    .ok_or(PlanError::PoolExhausted)?;
                last_pd_window = Some(window);
            }
        }
        if leaf.size == PageSize::Size4K {
            let window = leaf.start / PAGE_2M;
            if last_pt_window != Some(window) {
                demand.pt_pages = demand
                    .pt_pages
                    .checked_add(1)
                    .ok_or(PlanError::PoolExhausted)?;
                last_pt_window = Some(window);
            }
        }
        Ok(())
    })?;
    let total = pool
        .used
        .checked_add(pool.reserved)
        .and_then(|pages| pages.checked_add(demand.pdpt_pages))
        .and_then(|pages| pages.checked_add(demand.pd_pages))
        .and_then(|pages| pages.checked_add(demand.pt_pages))
        .ok_or(PlanError::PoolExhausted)?;
    if total > pool.capacity {
        return Err(PlanError::PoolExhausted);
    }
    *output = demand;
    Ok(())
}

fn valid_range(range: PhysicalRange) -> bool {
    range.start < range.end && (range.start | range.end) & (PAGE_4K - 1) == 0
}

fn admitted_ranges<'a>(
    firmware: &'a [FirmwareRange],
    reserved_ram: &'a [PhysicalRange],
) -> impl Iterator<Item = PhysicalRange> + 'a {
    firmware
        .iter()
        .filter_map(|entry| match entry.kind {
            FirmwareKind::Ram | FirmwareKind::AcpiRam => Some(entry.range),
            FirmwareKind::Reserved | FirmwareKind::Mmio => None,
        })
        .chain(reserved_ram.iter().copied())
}

fn reserved_firmware_covers(range: PhysicalRange, firmware: &[FirmwareRange]) -> bool {
    let mut at = range.start;
    while at < range.end {
        let Some(cover) = firmware.iter().find(|entry| {
            entry.kind == FirmwareKind::Reserved && entry.range.start <= at && at < entry.range.end
        }) else {
            return false;
        };
        at = cover.range.end.min(range.end);
    }
    true
}

fn validate(
    firmware: &[FirmwareRange],
    reserved_ram: &[PhysicalRange],
    devices: &[PhysicalRange],
    limit: u64,
) -> Result<(), PlanError> {
    if limit & (PAGE_4K - 1) != 0 {
        return Err(PlanError::InvalidRange);
    }
    for (i, entry) in firmware.iter().enumerate() {
        if !valid_range(entry.range) {
            return Err(PlanError::InvalidRange);
        }
        // Firmware overlap is ambiguous even when both entries advertise RAM:
        // a second descriptor may conceal a different physical owner.
        if firmware[..i]
            .iter()
            .any(|prior| prior.range.overlaps(entry.range))
        {
            return Err(PlanError::AmbiguousOverlap);
        }
    }
    for (i, range) in reserved_ram.iter().copied().enumerate() {
        if !valid_range(range) {
            return Err(PlanError::InvalidRange);
        }
        if reserved_ram[..i].iter().any(|prior| prior.overlaps(range)) {
            return Err(PlanError::AmbiguousOverlap);
        }
        if !reserved_firmware_covers(range, firmware) {
            return Err(PlanError::UnprovenReservedRam);
        }
    }
    for device in devices.iter().copied() {
        if !valid_range(device) {
            return Err(PlanError::InvalidRange);
        }
        if admitted_ranges(firmware, reserved_ram).any(|ram| device.overlaps(ram)) {
            return Err(PlanError::AmbiguousOverlap);
        }
    }
    Ok(())
}

fn next_run(
    firmware: &[FirmwareRange],
    reserved_ram: &[PhysicalRange],
    cursor: u64,
    limit: u64,
) -> Option<PhysicalRange> {
    if cursor >= limit {
        return None;
    }
    let first = admitted_ranges(firmware, reserved_ram)
        .filter(|range| range.end > cursor && range.start < limit)
        .min_by_key(|range| range.start.max(cursor))?;
    let start = first.start.max(cursor);
    let mut end = first.end.min(limit);
    // Coalesce adjacent admitted ranges without allocating a temporary list.
    loop {
        let previous = end;
        for range in admitted_ranges(firmware, reserved_ram) {
            if range.start <= end && range.end > end {
                end = range.end.min(limit);
            }
        }
        if end == previous {
            break;
        }
    }
    Some(PhysicalRange { start, end })
}

fn walk_leaves(
    firmware: &[FirmwareRange],
    reserved_ram: &[PhysicalRange],
    limit: u64,
    mut emit: impl FnMut(MapLeaf) -> Result<(), PlanError>,
) -> Result<(), PlanError> {
    let mut cursor = 0;
    while let Some(run) = next_run(firmware, reserved_ram, cursor, limit) {
        let mut at = run.start;
        while at < run.end {
            let remaining = run.end - at;
            let size = if at & (PAGE_1G - 1) == 0 && remaining >= PAGE_1G {
                PageSize::Size1G
            } else if at & (PAGE_2M - 1) == 0 && remaining >= PAGE_2M {
                PageSize::Size2M
            } else {
                PageSize::Size4K
            };
            emit(MapLeaf { start: at, size })?;
            at += size.bytes();
        }
        cursor = run.end;
    }
    Ok(())
}

/// Validate all sources, count leaves, then fill `output` atomically with respect
/// to admission and capacity errors. Missing firmware coverage remains a hole.
pub fn plan_direct_map(
    firmware: &[FirmwareRange],
    reserved_ram: &[PhysicalRange],
    devices: &[PhysicalRange],
    limit: u64,
    output: &mut [MapLeaf],
) -> Result<usize, PlanError> {
    validate(firmware, reserved_ram, devices, limit)?;
    let mut count = 0usize;
    walk_leaves(firmware, reserved_ram, limit, |_| {
        count = count.checked_add(1).ok_or(PlanError::OutputTooSmall)?;
        Ok(())
    })?;
    if count > output.len() {
        return Err(PlanError::OutputTooSmall);
    }
    let mut written = 0;
    walk_leaves(firmware, reserved_ram, limit, |leaf| {
        output[written] = leaf;
        written += 1;
        Ok(())
    })?;
    Ok(written)
}
