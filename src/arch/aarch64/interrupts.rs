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
extern "C" fn aarch64_irq_dispatch(context: *mut crate::arch::UserContext) {
    let acknowledge = super::gic::acknowledge();
    let irq = acknowledge & 0x3ff;

    if irq == super::gic::SPURIOUS_IRQ {
        return;
    }

    if irq == super::timer::TIMER_IRQ {
        // The architected timer is level-sensitive. Move its compare value
        // before EOI, matching seL4's resetTimer()/isb()/ackInterrupt order.
        let from_user = unsafe { (*context).spsr_el1 & 0xf == 0 };
        super::timer::program_ticks((super::timer::frequency_hz() / 1_000).max(1));
        TIMER_INTERRUPTS.fetch_add(1, Ordering::SeqCst);
        if from_user {
            handle_kernel_tick(context);
        } else {
            handle_idle_tick();
        }
    } else {
        super::gic::mask(irq);
        UNEXPECTED_INTERRUPTS.fetch_add(1, Ordering::SeqCst);
    }

    super::gic::end_interrupt(acknowledge);
}

fn handle_idle_tick() {
    // `wait_for_runnable` executes WFI at EL1 after releasing the BKL. A
    // sporadic SC may be the only thing capable of becoming runnable, so an
    // idle timer IRQ must still advance time and process the release queue.
    crate::smp::bkl_acquire();
    unsafe {
        crate::kernel::KERNEL.get().scheduler.tick();
    }
    super::timer::TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::sched_context::mcs_tick(1);
    crate::smp::bkl_release();
}

fn handle_kernel_tick(context: *mut crate::arch::UserContext) {
    crate::smp::bkl_acquire();
    let interrupted = unsafe {
        crate::kernel::KERNEL
            .get()
            .scheduler
            .active_user()
            .or_else(|| crate::kernel::KERNEL.get().scheduler.current())
    };
    if let Some(thread) = interrupted {
        unsafe {
            let tcb = crate::kernel::KERNEL.get().scheduler.slab.get_mut(thread);
            tcb.user_context = *context;
            crate::arch::aarch64::context::save_exception_fpu(context, &mut tcb.aarch64_fpu_state);
            crate::kernel::KERNEL.get().scheduler.tick();
        }
        super::timer::TICK_COUNT.fetch_add(1, Ordering::Relaxed);
        crate::sched_context::mcs_tick(1);
        crate::arch::aarch64::syscall_entry::dispatch_selected(
            unsafe { &mut *context },
            Some(thread),
            crate::syscalls::Syscall::SysYield,
            false,
            false,
        );
    }
    crate::smp::bkl_release();
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
