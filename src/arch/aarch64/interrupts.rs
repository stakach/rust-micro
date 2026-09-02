//! AArch64 interrupt-controller initialization and dispatch.

use core::sync::atomic::{AtomicU32, Ordering};

static TIMER_INTERRUPTS: AtomicU32 = AtomicU32::new(0);
static UNEXPECTED_INTERRUPTS: AtomicU32 = AtomicU32::new(0);
pub const IPI_IRQ: u32 = 1;

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

    if irq == IPI_IRQ {
        handle_ipi(context, acknowledge);
    } else if irq == super::timer::TIMER_IRQ {
        // The architected timer is level-sensitive. Move its compare value
        // before EOI, matching seL4's resetTimer()/isb()/ackInterrupt order.
        // A domain switch can then wait for another timer interrupt, so the
        // GIC active state must be dropped before entering the scheduler.
        let from_user = unsafe { (*context).spsr_el1 & 0xf == 0 };
        let elapsed = super::timer::elapsed_kernel_ticks();
        super::timer::program_ticks((super::timer::frequency_hz() / 1_000).max(1));
        TIMER_INTERRUPTS.fetch_add(1, Ordering::SeqCst);
        super::gic::end_interrupt(acknowledge);
        if from_user {
            handle_kernel_tick(context, elapsed);
        } else {
            handle_idle_tick(elapsed);
        }
    } else {
        handle_userspace_irq(context, irq, acknowledge);
        return;
    }
}

fn invalidate_local_tlb() {
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            options(nostack),
        );
    }
}

fn handle_ipi(context: *mut crate::arch::UserContext, acknowledge: u32) {
    use crate::smp::IpiKind;

    crate::smp::bkl_acquire();
    let context = unsafe { &mut *context };
    let from_user = context.spsr_el1 & 0xf == 0;
    let me = crate::arch::get_cpu_id();
    let interrupted = unsafe {
        let scheduler = &crate::kernel::KERNEL.get().scheduler;
        if from_user {
            scheduler
                .active_user_for_cpu(me)
                .or_else(|| scheduler.current_for_cpu(me))
        } else {
            scheduler.current_for_cpu(me)
        }
    };

    let mut want_reschedule = false;
    crate::smp::handle_ipis(crate::smp::nodes_mut(), me, |_from, kind| match kind {
        IpiKind::Reschedule => want_reschedule = true,
        IpiKind::InvalidateTlb { .. } | IpiKind::InvalidateVspace { .. } => invalidate_local_tlb(),
        IpiKind::Stop => loop {
            unsafe { core::arch::asm!("wfi", options(nostack, nomem)) };
        },
    });
    crate::smp::IPI_HANDLED_COUNT.fetch_add(1, Ordering::SeqCst);

    if from_user {
        if let Some(thread) = interrupted {
            unsafe {
                let tcb = crate::kernel::KERNEL.get().scheduler.slab.get_mut(thread);
                tcb.user_context = *context;
                crate::arch::aarch64::context::save_exception_fpu(
                    context,
                    &mut tcb.aarch64_fpu_state,
                );
            }
        }
    }

    if crate::smp::STALL_REQUESTED[me as usize].load(Ordering::Acquire) {
        unsafe {
            let scheduler = &mut crate::kernel::KERNEL.get().scheduler;
            scheduler.set_current(None);
            scheduler.set_active_user(None);
        }
        crate::arch::aarch64::vspace::park_on_kernel_root();
        super::gic::end_interrupt(acknowledge);
        crate::smp::STALL_ACK[me as usize].store(true, Ordering::Release);
        crate::smp::bkl_release();
        while crate::smp::STALL_REQUESTED[me as usize].load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        crate::smp::bkl_acquire();
        crate::arch::aarch64::syscall_entry::dispatch_selected(
            context,
            interrupted,
            crate::syscalls::Syscall::SysYield,
            false,
            false,
        );
        crate::smp::bkl_release();
        return;
    }

    super::gic::end_interrupt(acknowledge);
    if want_reschedule {
        if from_user {
            crate::arch::aarch64::syscall_entry::dispatch_selected(
                context,
                interrupted,
                crate::syscalls::Syscall::SysYield,
                false,
                false,
            );
        } else {
            unsafe {
                let scheduler = &mut crate::kernel::KERNEL.get().scheduler;
                let next = scheduler.choose_thread();
                scheduler.set_current(next);
            }
        }
    }
    crate::smp::bkl_release();
}

fn handle_userspace_irq(context: *mut crate::arch::UserContext, irq: u32, acknowledge: u32) {
    crate::smp::bkl_acquire();
    let context = unsafe { &mut *context };
    let from_user = context.spsr_el1 & 0xf == 0;
    let interrupted = unsafe {
        let state = crate::kernel::KERNEL.get();
        if from_user {
            state
                .scheduler
                .active_user()
                .or_else(|| state.scheduler.current())
        } else {
            state.scheduler.current()
        }
    };

    super::gic::mask(irq);
    let handled = unsafe {
        let state = crate::kernel::KERNEL.get();
        let state_ptr: *mut crate::kernel::KernelState = state;
        let handled = matches!(
            (*state_ptr).irqs.get(irq as u16).map(|entry| entry.state),
            Some(crate::interrupt::IrqState::Signal)
        );
        let _ = crate::interrupt::handle_interrupt(
            &mut (*state_ptr).irqs,
            &mut (*state_ptr).notifications,
            &mut (*state_ptr).scheduler,
            irq as u16,
        );
        handled
    };
    if !handled {
        UNEXPECTED_INTERRUPTS.fetch_add(1, Ordering::SeqCst);
    }

    // A level-triggered userspace source stays masked until IRQHandler_Ack.
    // Drop the GIC active state before a possible scheduler wait.
    super::gic::end_interrupt(acknowledge);

    if from_user {
        if let Some(thread) = interrupted {
            unsafe {
                let tcb = crate::kernel::KERNEL.get().scheduler.slab.get_mut(thread);
                tcb.user_context = *context;
                crate::arch::aarch64::context::save_exception_fpu(
                    context,
                    &mut tcb.aarch64_fpu_state,
                );
            }
        }
        crate::arch::aarch64::syscall_entry::dispatch_selected(
            context,
            interrupted,
            crate::syscalls::Syscall::SysYield,
            false,
            false,
        );
    }
    crate::smp::bkl_release();
}

fn handle_idle_tick(elapsed: u64) {
    // `wait_for_runnable` executes WFI at EL1 after releasing the BKL. A
    // sporadic SC may be the only thing capable of becoming runnable, so an
    // idle timer IRQ must still advance time and process the release queue.
    crate::smp::bkl_acquire();
    unsafe {
        crate::kernel::KERNEL.get().scheduler.tick();
    }
    super::timer::TICK_COUNT.fetch_add(elapsed, Ordering::Relaxed);
    crate::sched_context::mcs_tick(elapsed);
    crate::smp::bkl_release();
}

fn handle_kernel_tick(context: *mut crate::arch::UserContext, elapsed: u64) {
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
        super::timer::TICK_COUNT.fetch_add(elapsed, Ordering::Relaxed);
        crate::sched_context::mcs_tick(elapsed);
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
