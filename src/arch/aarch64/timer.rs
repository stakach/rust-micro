//! ARM architected virtual timer used by a non-hypervisor seL4 kernel.

use core::sync::atomic::AtomicU64;

pub const TIMER_IRQ: u32 = 27;
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

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

pub fn enable_periodic_kernel_timer() {
    super::gic::unmask(TIMER_IRQ);
    program_ticks((frequency_hz() / 1_000).max(1));
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
        arch::log(" ok\n");
    }
}
