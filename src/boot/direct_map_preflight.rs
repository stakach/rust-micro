//! First-install direct-map capacity preflight over checked firmware and boot owners.

use super::{direct_map_owners, direct_map_policy};
use super::{
    read_simpleboot_firmware_map, visit_live_page_tables, BootError, MAX_BOOT_MMAP_ENTRIES,
    MAX_RESERVED_REGIONS,
};

#[cfg(target_arch = "x86_64")]
fn push_boot_owner(
    out: &mut [direct_map_policy::PhysicalRange],
    count: &mut usize,
    start: u64,
    end: u64,
) -> Result<(), BootError> {
    if end <= start {
        return Err(BootError::InvalidMemoryMap);
    }
    let rounded_end = end.checked_add(4095).ok_or(BootError::InvalidMemoryMap)? & !4095;
    if *count == out.len() {
        return Err(BootError::TooManyRegions);
    }
    out[*count] = direct_map_policy::PhysicalRange {
        start: start & !4095,
        end: rounded_end,
    };
    *count += 1;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn collect_boot_owner_ranges(
    out: &mut [direct_map_policy::PhysicalRange],
) -> Result<usize, BootError> {
    let mut count = 0;
    let (start, end) = crate::simpleboot::mbi_region().ok_or(BootError::InvalidMemoryMap)?;
    push_boot_owner(out, &mut count, start, end)?;

    let mut error = None;
    crate::simpleboot::for_each_module_region(|start, end| {
        if error.is_none() {
            error = push_boot_owner(out, &mut count, start, end).err();
        }
    });
    if let Some(error) = error {
        return Err(error);
    }
    crate::simpleboot::for_each_kernel_region(|start, end| {
        if error.is_none() {
            error = push_boot_owner(out, &mut count, start, end).err();
        }
    });
    if let Some(error) = error {
        return Err(error);
    }
    visit_live_page_tables(|start, end| push_boot_owner(out, &mut count, start, end))?;
    Ok(count)
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreflightError {
    Boot(BootError),
    Policy(direct_map_policy::PlanError),
    InvalidAperture,
}

#[cfg(target_arch = "x86_64")]
fn preflight_device_page(paddr: u64) -> Result<direct_map_policy::PhysicalRange, PreflightError> {
    if paddr == 0 || paddr & 4095 != 0 {
        return Err(PreflightError::InvalidAperture);
    }
    let end = paddr
        .checked_add(4096)
        .ok_or(PreflightError::InvalidAperture)?;
    Ok(direct_map_policy::PhysicalRange { start: paddr, end })
}

/// Count a possible RAM-only direct map while the loader identity map is still live.
/// This is a first-install admission check; the current broad map remains unchanged.
#[cfg(target_arch = "x86_64")]
pub(crate) fn preflight_direct_map(
    lapic_paddr: u64,
    ioapic_paddrs: &[u64],
    limit: u64,
    pool: direct_map_policy::TablePool,
) -> Result<direct_map_policy::TableDemand, PreflightError> {
    use direct_map_policy::{FirmwareKind, FirmwareRange, PhysicalRange, TableDemand};

    let mut firmware = [FirmwareRange {
        range: PhysicalRange { start: 0, end: 0 },
        kind: FirmwareKind::Reserved,
    }; MAX_BOOT_MMAP_ENTRIES];
    let firmware_count =
        read_simpleboot_firmware_map(&mut firmware).map_err(PreflightError::Boot)?;
    let mut owners = [PhysicalRange { start: 0, end: 0 }; MAX_RESERVED_REGIONS];
    let owner_count = collect_boot_owner_ranges(&mut owners).map_err(PreflightError::Boot)?;
    let mut reserved_ram = [PhysicalRange { start: 0, end: 0 }; MAX_RESERVED_REGIONS];
    let reserved_count = direct_map_owners::collect_reserved_ram(
        &firmware[..firmware_count],
        &owners[..owner_count],
        &mut reserved_ram,
    )
    .map_err(PreflightError::Policy)?;

    let mut devices =
        [PhysicalRange { start: 0, end: 0 }; 1 + crate::arch::x86_64::ioapic::MAX_IOAPICS];
    if ioapic_paddrs.len() + 1 > devices.len() {
        return Err(PreflightError::InvalidAperture);
    }
    devices[0] = preflight_device_page(lapic_paddr)?;
    for (index, paddr) in ioapic_paddrs.iter().copied().enumerate() {
        let page = preflight_device_page(paddr)?;
        if devices[..index + 1]
            .iter()
            .any(|prior| prior.start == page.start)
        {
            return Err(PreflightError::InvalidAperture);
        }
        devices[index + 1] = page;
    }
    let mut demand = TableDemand {
        pdpt_pages: 0,
        pd_pages: 0,
        pt_pages: 0,
    };
    direct_map_policy::count_direct_map_tables(
        &firmware[..firmware_count],
        &reserved_ram[..reserved_count],
        &devices[..ioapic_paddrs.len() + 1],
        limit,
        pool,
        &mut demand,
    )
    .map_err(PreflightError::Policy)?;
    Ok(demand)
}
