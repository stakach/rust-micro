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

/// Retain exactly the sources whose leaves passed the first-install capacity check.
/// The native builder and `phys_to_lin` consume this plan after publication.
#[cfg(target_arch = "x86_64")]
pub(crate) struct DirectMapPlan {
    firmware: [direct_map_policy::FirmwareRange; MAX_BOOT_MMAP_ENTRIES],
    firmware_count: usize,
    reserved_ram: [direct_map_policy::PhysicalRange; MAX_RESERVED_REGIONS],
    reserved_count: usize,
    devices: [direct_map_policy::PhysicalRange; 1 + crate::arch::x86_64::ioapic::MAX_IOAPICS],
    device_count: usize,
    runs: [direct_map_policy::PhysicalRange; MAX_BOOT_MMAP_ENTRIES + MAX_RESERVED_REGIONS],
    run_count: usize,
    limit: u64,
    checked: bool,
}

#[cfg(target_arch = "x86_64")]
impl DirectMapPlan {
    pub(crate) const fn new() -> Self {
        use direct_map_policy::{FirmwareKind, FirmwareRange, PhysicalRange};
        const EMPTY: PhysicalRange = PhysicalRange { start: 0, end: 0 };
        Self {
            firmware: [FirmwareRange { range: EMPTY, kind: FirmwareKind::Reserved };
                MAX_BOOT_MMAP_ENTRIES],
            firmware_count: 0,
            reserved_ram: [EMPTY; MAX_RESERVED_REGIONS],
            reserved_count: 0,
            devices: [EMPTY; 1 + crate::arch::x86_64::ioapic::MAX_IOAPICS],
            device_count: 0,
            runs: [EMPTY; MAX_BOOT_MMAP_ENTRIES + MAX_RESERVED_REGIONS],
            run_count: 0,
            limit: 0,
            checked: false,
        }
    }

    pub(crate) fn checked(&self) -> bool { self.checked }
    pub(crate) fn firmware(&self) -> &[direct_map_policy::FirmwareRange] {
        &self.firmware[..self.firmware_count]
    }
    pub(crate) fn reserved_ram(&self) -> &[direct_map_policy::PhysicalRange] {
        &self.reserved_ram[..self.reserved_count]
    }
    pub(crate) fn devices(&self) -> &[direct_map_policy::PhysicalRange] {
        &self.devices[..self.device_count]
    }
    pub(crate) fn limit(&self) -> u64 { self.limit }

    pub(crate) fn contains(&self, paddr: u64) -> bool {
        if !self.checked || paddr >= self.limit { return false; }
        let mut low = 0;
        let mut high = self.run_count;
        while low < high {
            let mid = low + (high - low) / 2;
            let run = self.runs[mid];
            if paddr < run.start { high = mid; }
            else if paddr >= run.end { low = mid + 1; }
            else { return true; }
        }
        false
    }
}

/// Validate the whole physical policy and retain the exact sources used by native construction.
#[cfg(target_arch = "x86_64")]
pub(crate) fn preflight_direct_map(
    lapic_paddr: u64,
    ioapic_paddrs: &[u64],
    limit: u64,
    pool: direct_map_policy::TablePool,
    plan: &mut DirectMapPlan,
) -> Result<direct_map_policy::TableDemand, PreflightError> {
    use direct_map_policy::{PhysicalRange, TableDemand};

    plan.checked = false;
    plan.run_count = 0;
    let firmware_count = read_simpleboot_firmware_map(&mut plan.firmware)
        .map_err(PreflightError::Boot)?;
    let mut owners = [PhysicalRange { start: 0, end: 0 }; MAX_RESERVED_REGIONS];
    let owner_count = collect_boot_owner_ranges(&mut owners).map_err(PreflightError::Boot)?;
    let reserved_count = direct_map_owners::collect_reserved_ram(
        &plan.firmware[..firmware_count],
        &owners[..owner_count],
        &mut plan.reserved_ram,
    )
    .map_err(PreflightError::Policy)?;

    if ioapic_paddrs.len() + 1 > plan.devices.len() {
        return Err(PreflightError::InvalidAperture);
    }
    plan.devices[0] = preflight_device_page(lapic_paddr)?;
    for (index, paddr) in ioapic_paddrs.iter().copied().enumerate() {
        let page = preflight_device_page(paddr)?;
        if plan.devices[..index + 1]
            .iter()
            .any(|prior| prior.start == page.start)
        {
            return Err(PreflightError::InvalidAperture);
        }
        plan.devices[index + 1] = page;
    }
    let mut demand = TableDemand {
        pdpt_pages: 0,
        pd_pages: 0,
        pt_pages: 0,
    };
    direct_map_policy::count_direct_map_tables(
        &plan.firmware[..firmware_count],
        &plan.reserved_ram[..reserved_count],
        &plan.devices[..ioapic_paddrs.len() + 1],
        limit,
        pool,
        &mut demand,
    )
    .map_err(PreflightError::Policy)?;
    let mut run_count = 0;
    let runs = &mut plan.runs;
    direct_map_policy::for_each_direct_map_run(
        &plan.firmware[..firmware_count],
        &plan.reserved_ram[..reserved_count],
        &plan.devices[..ioapic_paddrs.len() + 1],
        limit,
        |run| {
            if run_count == runs.len() {
                return Err(direct_map_policy::PlanError::OutputTooSmall);
            }
            runs[run_count] = run;
            run_count += 1;
            Ok(())
        },
    )
    .map_err(PreflightError::Policy)?;
    plan.firmware_count = firmware_count;
    plan.reserved_count = reserved_count;
    plan.device_count = ioapic_paddrs.len() + 1;
    plan.run_count = run_count;
    plan.limit = limit;
    plan.checked = true;
    Ok(demand)
}
