//! MADT-owned IOAPIC topology and redirection-table programming.
//!
//! The ABI addresses a controller by its zero-based MADT order and a pin local to that
//! controller. Boot validates the complete topology and publishes it atomically; IRQ capability
//! issuance never guesses a physical address, aliases a GSI, or assumes a fixed table size.

use core::ptr;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use super::acpi::MadtEntry;
use super::paging::{map_kernel_mmio_page, KERNEL_IOAPIC_VBASE};

const IOAPIC_REGSEL_OFFSET: u64 = 0x00;
const IOAPIC_IOWIN_OFFSET: u64 = 0x10;
const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VERSION: u32 = 0x01;
const IOAPIC_REG_REDTBL_BASE: u32 = 0x10;
const IOAPIC_PAGE_SIZE: u64 = 0x1000;
const MAX_IOAPICS: usize = 16;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IoApicError {
    NoTopology,
    AlreadyInitialized,
    MalformedMadt,
    TooManyControllers,
    InvalidAddress,
    DuplicateControllerId,
    DuplicateAddress,
    DuplicateGsiRange,
    InvalidHardware,
    ControllerOutOfRange,
    PinOutOfRange,
}

#[derive(Copy, Clone)]
struct IoApicController {
    madt_id: u8,
    paddr: u64,
    vaddr: u64,
    gsi_base: u32,
    redirection_entries: u16,
}

const EMPTY_CONTROLLER: IoApicController = IoApicController {
    madt_id: 0,
    paddr: 0,
    vaddr: 0,
    gsi_base: 0,
    redirection_entries: 0,
};

static IOAPIC_COUNT: AtomicUsize = AtomicUsize::new(0);
static DESTINATION_APIC_ID: AtomicU8 = AtomicU8::new(0);
static mut IOAPICS: [IoApicController; MAX_IOAPICS] = [EMPTY_CONTROLLER; MAX_IOAPICS];

struct InterruptState {
    restore_enabled: bool,
}

impl InterruptState {
    unsafe fn disable() -> Self {
        let flags: u64;
        core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(nomem));
        core::arch::asm!("cli", options(nomem, nostack));
        Self {
            restore_enabled: flags & (1 << 9) != 0,
        }
    }
}

impl Drop for InterruptState {
    fn drop(&mut self) {
        if self.restore_enabled {
            unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
        }
    }
}

#[inline]
unsafe fn write_reg(controller: IoApicController, reg: u32, value: u32) {
    ptr::write_volatile((controller.vaddr + IOAPIC_REGSEL_OFFSET) as *mut u32, reg);
    ptr::write_volatile((controller.vaddr + IOAPIC_IOWIN_OFFSET) as *mut u32, value);
}

#[inline]
unsafe fn read_reg(controller: IoApicController, reg: u32) -> u32 {
    ptr::write_volatile((controller.vaddr + IOAPIC_REGSEL_OFFSET) as *mut u32, reg);
    ptr::read_volatile((controller.vaddr + IOAPIC_IOWIN_OFFSET) as *const u32)
}

fn published_controller(ordinal: usize) -> Result<IoApicController, IoApicError> {
    let count = IOAPIC_COUNT.load(Ordering::Acquire);
    if count == 0 {
        return Err(IoApicError::NoTopology);
    }
    if ordinal >= count {
        return Err(IoApicError::ControllerOutOfRange);
    }
    Ok(unsafe { IOAPICS[ordinal] })
}

/// Discover every MADT IOAPIC, map its register page uncached, read its hardware table size, and
/// publish the catalog only after the complete topology validates.
pub unsafe fn initialize(sdt_addr: u64, bsp_apic_id: u32) -> Result<usize, IoApicError> {
    let _interrupt_state = InterruptState::disable();
    if IOAPIC_COUNT.load(Ordering::Acquire) != 0 {
        return Err(IoApicError::AlreadyInitialized);
    }
    if bsp_apic_id > u8::MAX as u32 {
        return Err(IoApicError::InvalidHardware);
    }
    let madt = super::acpi::find_madt(sdt_addr).map_err(|_| IoApicError::MalformedMadt)?;
    let mut staged = [EMPTY_CONTROLLER; MAX_IOAPICS];
    let mut count = 0usize;
    let mut collect_error = None;
    super::acpi::iter_madt_entries(madt, |entry| {
        let MadtEntry::IoApic {
            ioapic_id,
            address,
            gsi_base,
        } = entry
        else {
            return;
        };
        if collect_error.is_some() {
            return;
        }
        if count == MAX_IOAPICS {
            collect_error = Some(IoApicError::TooManyControllers);
            return;
        }
        if ioapic_id > 0xF {
            collect_error = Some(IoApicError::InvalidHardware);
            return;
        }
        if address == 0 || address & 0xFFF != 0 {
            collect_error = Some(IoApicError::InvalidAddress);
            return;
        }
        for existing in &staged[..count] {
            if existing.madt_id == ioapic_id {
                collect_error = Some(IoApicError::DuplicateControllerId);
                return;
            }
            if existing.paddr == address as u64 {
                collect_error = Some(IoApicError::DuplicateAddress);
                return;
            }
            if existing.gsi_base == gsi_base {
                collect_error = Some(IoApicError::DuplicateGsiRange);
                return;
            }
        }
        staged[count] = IoApicController {
            madt_id: ioapic_id,
            paddr: address as u64,
            vaddr: KERNEL_IOAPIC_VBASE + count as u64 * IOAPIC_PAGE_SIZE,
            gsi_base,
            redirection_entries: 0,
        };
        count += 1;
    })
    .map_err(|_| IoApicError::MalformedMadt)?;
    if let Some(error) = collect_error {
        return Err(error);
    }
    if count == 0 {
        return Err(IoApicError::NoTopology);
    }

    for controller in &mut staged[..count] {
        map_kernel_mmio_page(controller.vaddr, controller.paddr);
        let version = read_reg(*controller, IOAPIC_REG_VERSION);
        let entries = ((version >> 16) & 0xFF) + 1;
        let last_selector = IOAPIC_REG_REDTBL_BASE + (entries - 1) * 2 + 1;
        if last_selector > 0xFF {
            return Err(IoApicError::InvalidHardware);
        }
        let hardware_id = ((read_reg(*controller, IOAPIC_REG_ID) >> 24) & 0xF) as u8;
        if hardware_id != controller.madt_id {
            return Err(IoApicError::InvalidHardware);
        }
        controller.redirection_entries = entries as u16;
        for pin in 0..entries {
            let low_selector = IOAPIC_REG_REDTBL_BASE + pin * 2;
            write_reg(*controller, low_selector, 1 << 16);
            write_reg(*controller, low_selector + 1, 0);
        }
    }

    for left in 0..count {
        let left_end = staged[left]
            .gsi_base
            .checked_add(staged[left].redirection_entries as u32)
            .ok_or(IoApicError::DuplicateGsiRange)?;
        for right in left + 1..count {
            let right_end = staged[right]
                .gsi_base
                .checked_add(staged[right].redirection_entries as u32)
                .ok_or(IoApicError::DuplicateGsiRange)?;
            if staged[left].gsi_base < right_end && staged[right].gsi_base < left_end {
                return Err(IoApicError::DuplicateGsiRange);
            }
        }
    }

    for (ordinal, controller) in staged[..count].iter().copied().enumerate() {
        IOAPICS[ordinal] = controller;
    }
    DESTINATION_APIC_ID.store(bsp_apic_id as u8, Ordering::Relaxed);
    IOAPIC_COUNT.store(count, Ordering::Release);
    Ok(count)
}

pub fn controller_count() -> usize {
    IOAPIC_COUNT.load(Ordering::Acquire)
}

pub fn validate_route(ordinal: usize, pin: u32) -> Result<(), IoApicError> {
    let controller = published_controller(ordinal)?;
    if pin >= controller.redirection_entries as u32 {
        return Err(IoApicError::PinOutOfRange);
    }
    Ok(())
}

pub unsafe fn set_route_mask(ordinal: usize, pin: u32, masked: bool) -> Result<(), IoApicError> {
    validate_route(ordinal, pin)?;
    let controller = published_controller(ordinal)?;
    let lo_reg = IOAPIC_REG_REDTBL_BASE + pin * 2;
    let low = read_reg(controller, lo_reg);
    let next = if masked {
        low | (1 << 16)
    } else {
        low & !(1 << 16)
    };
    if next != low {
        write_reg(controller, lo_reg, next);
    }
    Ok(())
}

/// Program one controller-local redirection entry. The route is installed masked; binding the
/// issued handler to a notification is the commit point that unmasks it.
pub unsafe fn program_redirection(
    ordinal: usize,
    pin: u32,
    vector: u32,
    level: u32,
    polarity: u32,
    masked: bool,
) -> Result<(), IoApicError> {
    validate_route(ordinal, pin)?;
    let controller = published_controller(ordinal)?;
    let lo_reg = IOAPIC_REG_REDTBL_BASE + pin * 2;
    let previous_low = read_reg(controller, lo_reg);
    write_reg(controller, lo_reg, previous_low | (1 << 16));
    let destination = DESTINATION_APIC_ID.load(Ordering::Relaxed) as u32;
    write_reg(controller, lo_reg + 1, destination << 24);
    let polarity_bit = if polarity != 0 { 1 << 13 } else { 0 };
    let trigger_bit = if level != 0 { 1 << 15 } else { 0 };
    let mask_bit = if masked { 1 << 16 } else { 0 };
    let low = (vector & 0xFF) | polarity_bit | trigger_bit | mask_bit;
    write_reg(controller, lo_reg, low);
    Ok(())
}
