//! ARM architected virtual timer used by a non-hypervisor seL4 kernel.

use core::sync::atomic::{AtomicU64, Ordering};

pub const TIMER_IRQ: u32 = 27;
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_ACCOUNTED_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn frequency_hz() -> u32 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {value}, cntfrq_el0", value = out(reg) value, options(nomem, nostack));
    }
    value as u32
}

pub fn counter() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {value}, cntvct_el0", value = out(reg) value, options(nomem, nostack));
    }
    value
}

pub fn program_ticks(ticks: u32) {
    unsafe {
        core::arch::asm!(
            "msr cntv_tval_el0, {ticks}",
            "msr cntv_ctl_el0, {enable}",
            "isb",
            ticks = in(reg) u64::from(ticks),
            enable = in(reg) 1_u64,
            options(nostack),
        );
    }
}

pub fn disable() {
    unsafe {
        core::arch::asm!(
            "msr cntv_ctl_el0, {masked}",
            "isb",
            masked = in(reg) 2_u64,
            options(nomem, nostack),
        );
    }
}

/// Export the architected physical counter and physical timer to EL0.
///
/// seL4 enables CNTKCTL_EL1.EL0PCTEN and EL0PTEN when
/// CONFIG_EXPORT_PCNT_USER/CONFIG_EXPORT_PTMR_USER are selected.  The kernel
/// continues to use the virtual timer (IRQ 27), leaving the physical timer
/// (IRQ 30) available to a userspace timer driver.
pub fn enable_el0_physical_timer() {
    const EL0PCTEN: u64 = 1 << 0;
    const EL0PTEN: u64 = 1 << 9;
    unsafe {
        core::arch::asm!(
            "mrs {control}, cntkctl_el1",
            "orr {control}, {control}, {access}",
            "msr cntkctl_el1, {control}",
            "isb",
            control = out(reg) _,
            access = in(reg) EL0PCTEN | EL0PTEN,
            options(nostack),
        );
    }
}

pub fn enable_periodic_kernel_timer() {
    LAST_ACCOUNTED_COUNTER.store(counter(), Ordering::Relaxed);
    super::gic::unmask(TIMER_IRQ);
    program_ticks((frequency_hz() / 1_000).max(1));
}

fn elapsed_whole_ticks(now: u64, last: u64, per_tick: u64) -> (u64, u64) {
    let elapsed = (now.wrapping_sub(last) / per_tick.max(1)).min(1_000);
    (elapsed, last.wrapping_add(elapsed * per_tick.max(1)))
}

/// Return elapsed whole milliseconds since the last kernel-timer charge.
///
/// QEMU may deliver a nominal 1 ms timer late while translating code. Keep
/// the fractional counter remainder so repeated late interrupts charge wall
/// time instead of fire count, as seL4's MCS timestamp accounting does.
pub fn elapsed_kernel_ticks() -> u64 {
    let now = counter();
    let per_ms = u64::from((frequency_hz() / 1_000).max(1));
    let last = LAST_ACCOUNTED_COUNTER.load(Ordering::Relaxed);
    if last == 0 {
        LAST_ACCOUNTED_COUNTER.store(now, Ordering::Relaxed);
        return 1;
    }
    let (elapsed, next) = elapsed_whole_ticks(now, last, per_ms);
    if elapsed != 0 {
        LAST_ACCOUNTED_COUNTER.store(next, Ordering::Relaxed);
    }
    elapsed
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_timer() {
        arch::log("  aarch64 generic timer...");
        assert_eq!(frequency_hz(), 62_500_000);
        let before = counter();
        while counter() == before {
            core::hint::spin_loop();
        }
        assert!(counter() > before);
        assert_eq!(TIMER_IRQ, 16 + 11);
        assert_eq!(elapsed_whole_ticks(2_600, 1_000, 1_000), (1, 2_000));
        assert_eq!(elapsed_whole_ticks(3_100, 2_000, 1_000), (1, 3_000));
        assert_eq!(elapsed_whole_ticks(5_000, 5_000, 1_000), (0, 5_000));
        let access: u64;
        unsafe {
            core::arch::asm!("mrs {access}, cntkctl_el1", access = out(reg) access, options(nomem, nostack));
        }
        assert_eq!(access & ((1 << 0) | (1 << 9)), (1 << 0) | (1 << 9));
        arch::log(" ok\n");
    }
}
