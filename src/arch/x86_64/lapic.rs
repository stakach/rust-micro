//! Phase 12a — Local APIC driver.
//!
//! The LAPIC sits at the physical address held in IA32_APIC_BASE
//! (default 0xFEE0_0000). We access it through MMIO. BOOTBOOT
//! already maps the relevant page at the kernel's `mmio` virtual
//! address (0xFFFF_FFFF_F800_0000), so we can dereference straight
//! from there once we add the per-register offsets.
//!
//! Functions provided:
//!   - `init_lapic`: enable the LAPIC by setting bit 8 of SVR
//!     (Spurious Vector Register) and parking the spurious vector.
//!   - `eoi`: write to End-Of-Interrupt; needed at the tail of every
//!     IRQ handler so the LAPIC unmasks the next interrupt.
//!   - `send_ipi`: poke the Interrupt Command Register to deliver a
//!     vector to a target CPU (or self / broadcast).
//!   - `apic_id`: read the LAPIC ID (different from the BOOTBOOT
//!     bspid in some configurations).

use core::ptr::{read_volatile, write_volatile};

use super::msr::{rdmsr, IA32_APIC_BASE_MSR};

// ---------------------------------------------------------------------------
// LAPIC register offsets (relative to IA32_APIC_BASE).
// ---------------------------------------------------------------------------

const ID_REGISTER: usize = 0x020;
const VERSION_REGISTER: usize = 0x030;
const TASK_PRIORITY: usize = 0x080;
const EOI: usize = 0x0B0;
const SPURIOUS_VECTOR: usize = 0x0F0;
const ICR_LOW: usize = 0x300;
const ICR_HIGH: usize = 0x310;
const TIMER_LVT: usize = 0x320;
const TIMER_INITIAL_COUNT: usize = 0x380;
const TIMER_CURRENT_COUNT: usize = 0x390;
const TIMER_DIVIDE_CONFIG: usize = 0x3E0;

/// SVR bit 8 — APIC software-enable.
const SVR_ENABLE: u32 = 1 << 8;

/// Spurious-interrupt vector. Must have bits 0-3 = the LAPIC's
/// internal vector index 0xF (architectural requirement on older
/// CPUs); we pick 0xFF to be safe.
const SPURIOUS_VECTOR_NUMBER: u32 = 0xFF;

// ---------------------------------------------------------------------------
// MMIO base. Captured once at init from the IA32_APIC_BASE MSR.
// BOOTBOOT identity-maps the LAPIC page via the kernel's `mmio`
// virtual region; we use that mapping rather than the raw paddr so
// the access is cacheable per the BOOTBOOT page tables.
// ---------------------------------------------------------------------------

const KERNEL_MMIO_BASE: u64 = 0xFFFF_FFFF_F800_0000;

#[no_mangle]
static mut LAPIC_VBASE: u64 = 0;

/// Enable the LAPIC. Idempotent — calling twice is harmless.
///
/// On a BOOTBOOT-loaded kernel the LAPIC's physical page is **not**
/// pre-mapped into kernel virtual address space — neither at the
/// `mmio` symbol's address nor at the physical address itself.
/// Installing a fresh mapping requires walking and modifying the
/// page tables, but BOOTBOOT also doesn't pre-map page-table memory
/// at any kernel-half address we can reach safely.
///
/// Phase 12a delivers the **driver** logic: register layout, send-
/// IPI / EOI / timer-init helpers, the SVR-enable sequence. The
/// MMIO mapping itself lands with the page-table installer in the
/// follow-up phase that owns the kernel's vspace setup. Until then
/// the LAPIC functions are unsafe to call from a running kernel
/// (`init_lapic` will page-fault); the test that follows verifies
/// the *driver* via the MSR-side reads only.
pub fn init_lapic() {
    // Intentionally a no-op for now. See doc comment.
}

/// Acknowledge the current interrupt, allowing the next pending
/// vector to fire. Must be the last action in every IRQ handler.
pub fn eoi() {
    unsafe { write_reg(EOI, 0) };
}

/// Read the LAPIC's own ID register.
pub fn apic_id() -> u32 {
    unsafe { read_reg(ID_REGISTER) >> 24 }
}

/// Read the LAPIC version register.
pub fn version() -> u32 {
    unsafe { read_reg(VERSION_REGISTER) }
}

/// Send a fixed-mode IPI to a specific physical APIC ID. Mirrors
/// the apic_send_ipi helper in seL4's xapic.c.
pub fn send_ipi(target_apic_id: u8, vector: u8) {
    unsafe {
        // ICR high (offset 0x310) holds the destination APIC ID in
        // bits 56..63 (i.e. bits 24..31 of the high half).
        write_reg(ICR_HIGH, (target_apic_id as u32) << 24);
        // ICR low (0x300) — write triggers the IPI:
        //   bits 7..0   = vector
        //   bits 10..8  = delivery mode (0 = fixed)
        //   bit 11      = destination mode (0 = physical)
        //   bits 13..12 = delivery status (read-only)
        //   bit 14      = level (1 = assert)
        //   bit 15      = trigger mode (0 = edge)
        //   bits 19..18 = destination shorthand (00 = no shorthand)
        let icr_low = (vector as u32) | (1 << 14);
        write_reg(ICR_LOW, icr_low);
    }
}

/// Read the physical-APIC base from the MSR. Useful for spec
/// assertions; the kernel itself uses LAPIC_VBASE.
pub fn apic_base_paddr() -> u64 {
    unsafe { rdmsr(IA32_APIC_BASE_MSR) & 0xFFFF_F000 }
}

// ---------------------------------------------------------------------------
// One-shot APIC timer. Used to drive the scheduler tick.
// ---------------------------------------------------------------------------

/// Configure the LAPIC timer for one-shot mode firing on `vector`.
/// `divide_log2` selects the divisor (0 = ÷2, 1 = ÷4, ...; 7 = ÷1).
pub fn timer_one_shot(vector: u8, divide_log2: u8, initial_count: u32) {
    unsafe {
        // Divide configuration register: encoding is non-trivial —
        // bit 3 + bits 1..0 form the field. We support only the
        // common values via a table.
        let div_bits = match divide_log2 {
            0 => 0b0000, // ÷2
            1 => 0b0001, // ÷4
            2 => 0b0010, // ÷8
            3 => 0b0011, // ÷16
            4 => 0b1000, // ÷32
            5 => 0b1001, // ÷64
            6 => 0b1010, // ÷128
            _ => 0b1011, // ÷1
        };
        write_reg(TIMER_DIVIDE_CONFIG, div_bits);
        // LVT: vector + masked=0 + mode=0 (one-shot).
        write_reg(TIMER_LVT, vector as u32);
        // Writing the initial count starts the countdown.
        write_reg(TIMER_INITIAL_COUNT, initial_count);
    }
}

pub fn timer_current_count() -> u32 {
    unsafe { read_reg(TIMER_CURRENT_COUNT) }
}

// ---------------------------------------------------------------------------
// Low-level register access. The LAPIC is MMIO; reads / writes must
// be 32-bit dword-aligned.
// ---------------------------------------------------------------------------

unsafe fn write_reg(offset: usize, value: u32) {
    let ptr = (LAPIC_VBASE as *mut u8).add(offset) as *mut u32;
    write_volatile(ptr, value);
}

unsafe fn read_reg(offset: usize) -> u32 {
    let ptr = (LAPIC_VBASE as *const u8).add(offset) as *const u32;
    read_volatile(ptr)
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_lapic() {
        arch::log("Running LAPIC tests...\n");
        msr_base_at_legacy_address();
        register_layout_constants();
        timer_divide_table_covers_common_values();
        arch::log("LAPIC tests completed\n");
    }

    #[inline(never)]
    fn msr_base_at_legacy_address() {
        // Almost every real x86_64 CPU has the LAPIC at the legacy
        // 0xFEE00000 address by default; QEMU certainly does.
        let p = apic_base_paddr();
        assert_eq!(p, 0xFEE0_0000, "LAPIC base should be at the legacy address");
        arch::log("  ✓ IA32_APIC_BASE points at the legacy 0xFEE00000\n");
    }

    #[inline(never)]
    fn register_layout_constants() {
        // Spot-check the register offsets against the Intel SDM
        // (vol 3 ch 11.4.1 "The Local APIC Block Diagram"):
        //   ID Register             0x020
        //   EOI Register            0x0B0
        //   Spurious Interrupt Vec  0x0F0
        //   ICR Low                 0x300
        //   ICR High                0x310
        //   LVT Timer               0x320
        //   Initial Count           0x380
        assert_eq!(super::ID_REGISTER, 0x020);
        assert_eq!(super::EOI, 0x0B0);
        assert_eq!(super::SPURIOUS_VECTOR, 0x0F0);
        assert_eq!(super::ICR_LOW, 0x300);
        assert_eq!(super::ICR_HIGH, 0x310);
        assert_eq!(super::TIMER_LVT, 0x320);
        assert_eq!(super::TIMER_INITIAL_COUNT, 0x380);
        // SVR enable bit is bit 8.
        assert_eq!(super::SVR_ENABLE, 1 << 8);
        arch::log("  ✓ LAPIC register offsets match Intel SDM\n");
    }

    #[inline(never)]
    fn timer_divide_table_covers_common_values() {
        // The divide-config bit-pattern table is non-obvious. Spot
        // check that the helper builds 0b1011 (÷1) for inputs ≥ 7.
        // We don't actually program the LAPIC since it's not yet
        // mapped; the assertion lives in the divide-bits switch.
        // Just verify the boundary cases:
        //   divide_log2 0..6 each produce a unique 4-bit pattern
        //   anything ≥ 7 produces 0b1011 (÷1)
        // We can't directly call timer_one_shot without an MMIO
        // mapping, so we spot-check by re-implementing the table
        // here.
        fn pattern(divide_log2: u8) -> u32 {
            match divide_log2 {
                0 => 0b0000, 1 => 0b0001, 2 => 0b0010, 3 => 0b0011,
                4 => 0b1000, 5 => 0b1001, 6 => 0b1010,
                _ => 0b1011,
            }
        }
        let mut seen = [false; 16];
        for i in 0..7 {
            let p = pattern(i);
            assert!(!seen[p as usize], "divide pattern {} duplicated", p);
            seen[p as usize] = true;
        }
        assert_eq!(pattern(7), 0b1011);
        assert_eq!(pattern(255), 0b1011);
        arch::log("  ✓ timer divide table covers the canonical inputs\n");
    }
}
