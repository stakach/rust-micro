//! AArch64 interrupt-controller initialization and dispatch.

use core::sync::atomic::{AtomicU32, Ordering};

static TIMER_INTERRUPTS: AtomicU32 = AtomicU32::new(0);
static UNEXPECTED_INTERRUPTS: AtomicU32 = AtomicU32::new(0);

pub fn init_interrupts() {
    // Keep PSTATE.I set here. `init_exceptions` installs VBAR_EL1 later,
    // and individual interrupt sources are unmasked by their owners.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
    }
    super::gic::init();
}

#[no_mangle]
extern "C" fn aarch64_irq_dispatch() {
    let acknowledge = super::gic::acknowledge();
    let irq = acknowledge & 0x3ff;

    if irq == super::gic::SPURIOUS_IRQ {
        return;
    }

    if irq == super::timer::TIMER_IRQ {
        // The architected timer is level-sensitive. Move its compare value
        // before EOI, matching seL4's resetTimer()/isb()/ackInterrupt order.
        super::timer::disable();
        TIMER_INTERRUPTS.fetch_add(1, Ordering::SeqCst);
    } else {
        super::gic::mask(irq);
        UNEXPECTED_INTERRUPTS.fetch_add(1, Ordering::SeqCst);
    }

    super::gic::end_interrupt(acknowledge);
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_interrupts() {
        arch::log("  aarch64 GICv2/timer IRQ...");

        let before = TIMER_INTERRUPTS.load(Ordering::SeqCst);
        let unexpected = UNEXPECTED_INTERRUPTS.load(Ordering::SeqCst);
        super::super::gic::unmask(super::super::timer::TIMER_IRQ);
        super::super::timer::program_ticks((super::super::timer::frequency_hz() / 1_000).max(1));

        unsafe {
            core::arch::asm!("msr daifclr, #2", "isb", options(nomem, nostack));
        }

        let deadline = super::super::timer::counter()
            .wrapping_add((super::super::timer::frequency_hz() / 10).max(1) as u64);
        while TIMER_INTERRUPTS.load(Ordering::SeqCst) == before
            && super::super::timer::counter().wrapping_sub(deadline) >= (1_u64 << 63)
        {
            core::hint::spin_loop();
        }

        unsafe {
            core::arch::asm!("msr daifset, #2", "isb", options(nomem, nostack));
        }
        super::super::timer::disable();
        super::super::gic::mask(super::super::timer::TIMER_IRQ);

        assert_eq!(TIMER_INTERRUPTS.load(Ordering::SeqCst), before + 1);
        assert_eq!(UNEXPECTED_INTERRUPTS.load(Ordering::SeqCst), unexpected);
        arch::log(" ok\n");
    }
}
