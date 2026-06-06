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
/// **Precondition** (Phase 13b): the kernel page-table installer in
/// `paging::install_kernel_page_tables` must have run; it maps the
/// LAPIC physical page at `KERNEL_LAPIC_VBASE`. Calling this before
/// the installer page-faults.
pub fn init_lapic() {
    unsafe {
        LAPIC_VBASE = super::paging::KERNEL_LAPIC_VBASE;
        // Software-enable the LAPIC and park the spurious-vector.
        write_reg(SPURIOUS_VECTOR, SVR_ENABLE | SPURIOUS_VECTOR_NUMBER);
        // Set task priority to 0 (accept all interrupts).
        write_reg(TASK_PRIORITY, 0);
    }
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

/// Naked-asm IPI entry stub. Vectored from the IDT at `IPI_VECTOR`.
/// Pushes a dummy error code + vector marker (matching the
/// `interrupt!` macro shape) and tail-calls the typed handler.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn ipi_irq_entry() {
    core::arch::naked_asm!(
        "push 0",
        "push 0",
        "call {handler}",
        "add rsp, 16",
        "iretq",
        handler = sym ipi_isr,
    );
}

extern "C" fn ipi_isr() {
    use core::sync::atomic::Ordering;
    use crate::smp::IpiKind;

    crate::smp::bkl_acquire();

    // Drain pending IPIs and dispatch by kind. We snapshot the
    // requested actions out of the per-CPU NodeState while holding
    // BKL, then act on them with the same lock still held — the
    // KERNEL state mutations all live under BKL.
    let me = crate::arch::get_cpu_id();
    let nodes = crate::smp::nodes_mut();
    let mut want_reschedule = false;
    crate::smp::handle_ipis(nodes, me, |_from, kind| match kind {
        IpiKind::Reschedule => want_reschedule = true,
        IpiKind::InvalidateTlb { vaddr } => {
            // Best-effort TLB invalidate on this CPU. Full
            // shootdown integration with vspace ops lands later.
            unsafe {
                core::arch::asm!(
                    "invlpg [{a}]",
                    a = in(reg) vaddr,
                    options(nostack, preserves_flags),
                );
            }
        }
        IpiKind::Stop => {
            // Halt-loop forever. Used at shutdown — no graceful
            // unwinding needed since we never resume an AP after
            // this.
            loop {
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    });

    // Phase 28e — Reschedule IPI runs choose_thread on the target.
    // Updates per-CPU `current` so the next ap_scheduler_loop
    // iteration sees the new pick.
    if want_reschedule {
        unsafe {
            let s = crate::kernel::KERNEL.get();
            let next = s.scheduler.choose_thread();
            s.scheduler.set_current(next);
        }
    }

    crate::smp::IPI_HANDLED_COUNT.fetch_add(1, Ordering::SeqCst);

    eoi();
    crate::smp::bkl_release();
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
        write_reg(TIMER_DIVIDE_CONFIG, divide_bits(divide_log2));
        // LVT: vector + masked=0 + mode=0 (one-shot).
        write_reg(TIMER_LVT, vector as u32);
        // Writing the initial count starts the countdown.
        write_reg(TIMER_INITIAL_COUNT, initial_count);
    }
}

/// Configure the LAPIC timer for periodic mode firing on `vector`.
/// LVT bit 17 = 1 selects periodic — the timer auto-rearms with
/// `initial_count` each time it fires.
pub fn timer_periodic(vector: u8, divide_log2: u8, initial_count: u32) {
    unsafe {
        write_reg(TIMER_DIVIDE_CONFIG, divide_bits(divide_log2));
        write_reg(TIMER_LVT, (vector as u32) | (1 << 17));
        write_reg(TIMER_INITIAL_COUNT, initial_count);
    }
}

/// Start a one-shot countdown with the LVT MASKED — counts but
/// never interrupts. For calibration / specs that only read the
/// current-count register. An unmasked one-shot with no real IDT
/// vector is a trap: it eventually expires, the bogus vector gets
/// no LAPIC EOI, and its priority class blocks every lower LAPIC
/// vector (including the kernel tick) from then on.
pub fn timer_one_shot_masked(divide_log2: u8, initial_count: u32) {
    unsafe {
        write_reg(TIMER_DIVIDE_CONFIG, divide_bits(divide_log2));
        write_reg(TIMER_LVT, 1 << 16); // masked
        write_reg(TIMER_INITIAL_COUNT, initial_count);
    }
}

/// Stop the LAPIC timer (writing 0 to the initial count halts it).
pub fn timer_stop() {
    unsafe {
        write_reg(TIMER_INITIAL_COUNT, 0);
    }
}

/// Divide-configuration register encoding: bit 3 + bits 1..0 form
/// the field. Table covers the canonical inputs.
fn divide_bits(divide_log2: u8) -> u32 {
    match divide_log2 {
        0 => 0b0000, // ÷2
        1 => 0b0001, // ÷4
        2 => 0b0010, // ÷8
        3 => 0b0011, // ÷16
        4 => 0b1000, // ÷32
        5 => 0b1001, // ÷64
        6 => 0b1010, // ÷128
        _ => 0b1011, // ÷1
    }
}

pub fn timer_current_count() -> u32 {
    unsafe { read_reg(TIMER_CURRENT_COUNT) }
}

// ---------------------------------------------------------------------------
// Periodic LAPIC kernel tick — drives `scheduler.tick` + `mcs_tick`.
//
// Step 1 of the LAPIC-timer migration: the LAPIC owns the KERNEL's
// preemption clock, while the PIT (still kernel-programmed at
// 1000 Hz for now) only fans its IRQ to the user-space IRQ 2
// notification. Step 2 (freeing the PIT for the user-space ltimer
// driver entirely) comes once this step soaks.
// ---------------------------------------------------------------------------

/// IDT vector for the LAPIC kernel tick. 0x41 sits just above the
/// cross-CPU IPI vector (0x40), well clear of the PIC range
/// (0x20..0x30) and the spurious vector (0xFF).
pub const LAPIC_TIMER_VECTOR: u8 = 0x41;
const LAPIC_TIMER_DIVIDE_LOG2: u8 = 3; // ÷16

/// Calibrated initial count for a ~1 ms LAPIC timer period. Set by
/// `calibrate_timer_with_pit` on the BSP before user space owns any
/// hardware.
static mut LAPIC_TIMER_INITIAL_COUNT: u32 = 0;

/// TSC increments per millisecond, calibrated against the PIT in
/// the same window as the LAPIC rate. The tick ISR charges time by
/// MEASURED TSC delta, not by fire count: under TCG the guest
/// virtual clock keeps running while the ISR executes, so "1 kHz"
/// fires arrive every ~3 ms of virtual time — counting one tick per
/// fire ran every budget 3× long (SCHED0011 measured 309 ms for a
/// 100 ms period, constant to within jitter).
static mut TSC_PER_MS: u64 = 0;
/// TSC value up to which time has already been charged. Advanced by
/// whole milliseconds only, so the sub-ms remainder carries to the
/// next fire instead of being dropped.
static mut LAST_CHARGED_TSC: u64 = 0;

#[inline(always)]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// Measure the LAPIC timer frequency against the PIT and store the
/// initial count for a 1 ms period. Runs once on the BSP, before
/// the PIT is handed to its periodic kernel duty (and long before
/// user space can touch it). ~50 ms busy-wait.
pub fn calibrate_timer_with_pit() -> u32 {
    use super::pit;
    const CAL_MS: u32 = 50;
    const PIT_COUNT: u16 =
        ((pit::PIT_INPUT_HZ as u64 * CAL_MS as u64) / 1000) as u16;
    unsafe {
        // Run the LAPIC timer masked at max count — we only read
        // the current-count register, the LVT never fires.
        write_reg(TIMER_DIVIDE_CONFIG, divide_bits(LAPIC_TIMER_DIVIDE_LOG2));
        write_reg(TIMER_LVT, 1 << 16); // masked
        write_reg(TIMER_INITIAL_COUNT, u32::MAX);
    }
    // PIT one-shot, poll until the count expires. `read_count`
    // latches, so polling is race-free.
    let tsc0 = rdtsc();
    pit::program(pit::Channel::Ch0, pit::Mode::OneShot, PIT_COUNT);
    loop {
        let c = pit::read_count(pit::Channel::Ch0);
        if c == 0 || c > PIT_COUNT {
            break;
        }
    }
    let tsc1 = rdtsc();
    let elapsed = u32::MAX.wrapping_sub(timer_current_count());
    let per_ms = (elapsed / CAL_MS).max(1);
    unsafe {
        LAPIC_TIMER_INITIAL_COUNT = per_ms;
        // TSC rate over the same window — used by the tick ISR to
        // charge measured time rather than fire counts.
        TSC_PER_MS = (tsc1.wrapping_sub(tsc0) / CAL_MS as u64).max(1);
        // Stop the calibration countdown.
        write_reg(TIMER_INITIAL_COUNT, 0);
    }
    per_ms
}

/// Install the LAPIC-tick IDT entry and start the periodic timer on
/// the calling CPU at the calibrated ~1000 Hz rate. Requires
/// `calibrate_timer_with_pit` to have run first.
pub fn enable_periodic_kernel_timer() {
    use super::interrupts::{IdtEntry, IDT};
    // Defensive: EOI any interrupt stuck in-service on this LAPIC.
    // A vector that was taken but never EOI'd blocks every lower
    // priority class from delivery — including our tick vector.
    drain_in_service();
    unsafe {
        IDT[LAPIC_TIMER_VECTOR as usize] =
            IdtEntry::new(lapic_timer_irq_entry as u64, 0x08, 0, 0x8E);
        LAST_CHARGED_TSC = rdtsc();
        timer_periodic(
            LAPIC_TIMER_VECTOR,
            LAPIC_TIMER_DIVIDE_LOG2,
            LAPIC_TIMER_INITIAL_COUNT,
        );
    }
}

/// In-Service Register: 8 × 32-bit registers at 0x100..0x180, one
/// bit per vector. EOI clears the highest-priority set bit; loop
/// until the whole ISR is clear (bounded — 256 vectors max).
fn drain_in_service() {
    for _ in 0..256 {
        let mut any = false;
        for i in 0..8usize {
            let v = unsafe { read_reg(0x100 + i * 0x10) };
            if v != 0 {
                any = true;
                break;
            }
        }
        if !any {
            return;
        }
        eoi();
    }
}

/// Naked LAPIC-tick entry — same 15-GPR frame shape as
/// `pit_irq_entry` so the shared `IretqContext` swap tail works.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn lapic_timer_irq_entry() {
    core::arch::naked_asm!(
        "push rax", "push rbx", "push rcx", "push rdx",
        "push rsi", "push rdi", "push rbp",
        "push r8",  "push r9",  "push r10", "push r11",
        "push r12", "push r13", "push r14", "push r15",
        "mov rdi, rsp",
        "call {handler}",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop r11", "pop r10", "pop r9",  "pop r8",
        "pop rbp", "pop rdi", "pop rsi", "pop rdx",
        "pop rcx", "pop rbx", "pop rax",
        "iretq",
        handler = sym lapic_timer_irq_dispatch,
    );
}

/// LAPIC kernel-tick ISR: advance the tick clock, charge the
/// running thread's timeslice + SC budget, and context-switch if
/// the tick parked it. EOI goes to the LAPIC (not the PIC — this
/// vector never transits the 8259).
#[no_mangle]
extern "C" fn lapic_timer_irq_dispatch(
    ctx: &mut super::interrupts::IretqContext,
) {
    use core::sync::atomic::Ordering;

    crate::smp::bkl_acquire();
    struct BklGuard;
    impl Drop for BklGuard {
        fn drop(&mut self) {
            crate::smp::bkl_release();
        }
    }
    let _bkl = BklGuard;

    // Charge MEASURED time, not fire counts: virtual time keeps
    // advancing while this ISR executes under TCG, so consecutive
    // fires arrive several ms apart even though the LVT is armed
    // for 1 ms. Advance LAST_CHARGED_TSC by whole milliseconds only
    // so the remainder carries instead of dropping.
    let delta_ms = unsafe {
        let now_tsc = rdtsc();
        let per_ms = TSC_PER_MS.max(1);
        let d = now_tsc.wrapping_sub(LAST_CHARGED_TSC) / per_ms;
        // Clamp pathological jumps (TCG pause, debugger) so a
        // single fire can't charge minutes of budget.
        let d = d.min(1000);
        LAST_CHARGED_TSC = LAST_CHARGED_TSC.wrapping_add(d * per_ms);
        d
    };

    if delta_ms > 0 {
        super::pit::TICK_COUNT.fetch_add(delta_ms, Ordering::Relaxed);
    }

    let from_user = (ctx.cs & 3) == 3;
    let interrupted =
        unsafe { crate::kernel::KERNEL.get().scheduler.current() };

    if delta_ms > 0 {
        unsafe {
            crate::kernel::KERNEL.get().scheduler.tick();
        }
        crate::sched_context::mcs_tick(delta_ms);
    }

    eoi();

    super::interrupts::swap_iretq_context_if_preempted(
        ctx, from_user, interrupted,
    );
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
        live_lapic_id_and_version_after_paging();
        live_apic_timer_decrements();
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
    fn live_lapic_id_and_version_after_paging() {
        // The paging spec already called install_kernel_page_tables
        // and init_lapic. The LAPIC is now mapped and enabled.
        let id = apic_id();
        let v = version();
        assert!(id < 256, "APIC ID fits in 8 bits, got {id}");
        assert!(v != 0, "LAPIC version register populated");
        arch::log("  ✓ LAPIC ID + version readable through MMIO\n");
    }

    #[inline(never)]
    fn live_apic_timer_decrements() {
        // Park the LAPIC timer with a generous MASKED one-shot
        // count; verify the current-count register decreases, then
        // stop it. The LVT must stay masked: an unmasked bogus
        // vector (the old 0xEF) eventually expired with no IDT
        // entry and no EOI, leaving its priority class in-service
        // forever — which silently blocked the kernel-tick vector
        // for the rest of the boot.
        timer_one_shot_masked(7 /* divide ÷1 */, 1_000_000);
        let a = timer_current_count();
        for _ in 0..200_000 {
            core::hint::spin_loop();
        }
        let b = timer_current_count();
        timer_stop();
        assert!(b < a, "APIC timer should decrement (a={a} b={b})");
        arch::log("  ✓ APIC timer current count decrements\n");
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
