//! Phase 42 — IOAPIC redirection-table driver.
//!
//! When sel4test calls `seL4_X86_IRQControl_GetIOAPIC` to claim an
//! interrupt, the kernel must:
//!   1. Issue an `IrqHandler` cap (handled in `decode_irq_control`).
//!   2. Program the IOAPIC redirection-table entry at the requested
//!      pin to deliver the requested vector to the BSP, with the
//!      caller-specified level/polarity, and unmask it.
//!
//! Without (2) the timer driver in sel4test wires up its handler
//! and waits for the timer interrupt forever — the IOAPIC pin
//! stays masked, no IRQ ever fires, `init_timer` times out.
//!
//! This module owns the MMIO programming. The IOAPIC paddr is
//! discovered at boot via MADT (`acpi::iter_madt_entries`) and
//! cached in `IOAPIC_PADDR`; reads/writes go through the kernel-
//! half linear map (`phys_to_lin`) so user vspaces with PML4[0]
//! stripped can still drive the chip from a syscall handler.

use core::ptr;

use super::paging::phys_to_lin;

const IOAPIC_REGSEL_OFFSET: u64 = 0x00;
const IOAPIC_IOWIN_OFFSET: u64 = 0x10;

const IOAPIC_REG_REDTBL_BASE: u32 = 0x10;

#[no_mangle]
pub static mut IOAPIC_PADDR: u64 = 0;

/// Default fallback if MADT enumeration hasn't run / didn't find one.
/// Standard PC platforms place the first IOAPIC at this paddr.
const IOAPIC_DEFAULT_PADDR: u64 = 0xFEC00000;

/// Cache the IOAPIC paddr from MADT. Idempotent; safe to call from
/// boot or from the first invocation that needs it.
pub unsafe fn ensure_ioapic_paddr_discovered(madt_addr: u64) {
    if IOAPIC_PADDR != 0 {
        return;
    }
    if let Ok(madt) = super::acpi::find_madt(madt_addr) {
        super::acpi::iter_madt_entries(madt, |e| {
            if let super::acpi::MadtEntry::IoApic { address, .. } = e {
                if IOAPIC_PADDR == 0 {
                    IOAPIC_PADDR = address as u64;
                }
            }
        });
    }
    if IOAPIC_PADDR == 0 {
        IOAPIC_PADDR = IOAPIC_DEFAULT_PADDR;
    }
}

unsafe fn ioapic_base() -> u64 {
    if IOAPIC_PADDR == 0 {
        IOAPIC_PADDR = IOAPIC_DEFAULT_PADDR;
    }
    phys_to_lin(IOAPIC_PADDR)
}

unsafe fn write_reg(reg: u32, value: u32) {
    let base = ioapic_base();
    ptr::write_volatile((base + IOAPIC_REGSEL_OFFSET) as *mut u32, reg);
    ptr::write_volatile((base + IOAPIC_IOWIN_OFFSET) as *mut u32, value);
}

/// Program the IOAPIC redirection-table entry for `pin` to deliver
/// `vector` to the BSP (physical destination = APIC ID 0). Level/
/// polarity follow the seL4 ABI convention: `level=1` means
/// level-triggered, `polarity=1` means active-low.
///
/// Each redirection entry is 64 bits at register indices
/// `0x10 + 2*pin` (low) and `0x10 + 2*pin + 1` (high). Writes
/// the high half first (so the masked low half doesn't accidentally
/// fire with a stale destination), then the low half last so the
/// unmasked result becomes live atomically.
pub unsafe fn program_redirection(pin: u32, vector: u32, level: u32, polarity: u32) {
    let lo_reg = IOAPIC_REG_REDTBL_BASE + pin * 2;
    let hi_reg = lo_reg + 1;

    // High 32 bits: destination APIC ID in bits 56..63 — for our
    // current single-CPU-target wiring just deliver to the BSP.
    let high: u32 = 0;
    write_reg(hi_reg, high);

    // Low 32 bits:
    //   bits 0..7   = interrupt vector
    //   bits 8..10  = delivery mode (0 = Fixed)
    //   bit 11      = destination mode (0 = Physical)
    //   bit 13      = polarity (0 = active high, 1 = active low)
    //   bit 15      = trigger (0 = edge, 1 = level)
    //   bit 16      = mask (0 = unmasked) — write LAST so the
    //                 redirection goes live with vector + dest set.
    let polarity_bit = if polarity != 0 { 1 << 13 } else { 0 };
    let trigger_bit = if level != 0 { 1 << 15 } else { 0 };
    let low: u32 = (vector & 0xFF) | polarity_bit | trigger_bit;
    write_reg(lo_reg, low);
}
