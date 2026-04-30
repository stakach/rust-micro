//! Phase 14a — static kernel state singleton.
//!
//! Up to here the spec runner has been building `Scheduler` values
//! on the stack per test. To run actual threads we need persistent
//! per-CPU state: the current TCB pointer, the ready queues, and
//! (eventually) the IRQ table + endpoint pool.
//!
//! Concurrency model: uniprocessor, no in-kernel preemption point.
//! Once a CPU enters the kernel via SYSCALL or an exception, it
//! runs to completion (or an explicit yield) before the next entry.
//! That makes a plain `UnsafeCell` behind a `Sync` newtype the
//! correct primitive — no mutexes, no atomics, no allocator. SMP
//! later replaces this with `[KernelState; NUM_CPUS]` keyed by
//! GS_BASE.

use core::cell::UnsafeCell;

use crate::scheduler::Scheduler;
use crate::tcb::{Tcb, TcbId, ThreadStateType};

pub struct KernelState {
    pub scheduler: Scheduler,
}

impl KernelState {
    pub const fn new() -> Self {
        Self { scheduler: Scheduler::new() }
    }
}

/// `Sync` newtype around an `UnsafeCell<KernelState>` so it can be
/// `static`. The contract: only the kernel itself (not user mode,
/// not interrupt context) holds a reference, and the kernel never
/// recurses into itself, so there is exactly one `&mut` in flight
/// at any time.
pub struct KernelStateCell(UnsafeCell<KernelState>);

unsafe impl Sync for KernelStateCell {}

impl KernelStateCell {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(KernelState::new()))
    }

    /// SAFETY: caller is the kernel running in CPL=0 with
    /// interrupts already disabled (or, in UP, simply at any point
    /// where no other kernel-entry context is live). Each call must
    /// drop its `&mut` before another kernel entry runs.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get(&self) -> &mut KernelState {
        &mut *self.0.get()
    }
}

#[no_mangle]
pub static KERNEL: KernelStateCell = KernelStateCell::new();

// ---------------------------------------------------------------------------
// Bootstrap: register the running kernel context as TCB 0.
// ---------------------------------------------------------------------------

/// The bootstrap thread — the one running the boot path. It's
/// already in `Running` state by virtue of being the CPU's current
/// context; we just need to install a TCB representing it so the
/// scheduler has somewhere to save its register state when we
/// context-switch out for the first time.
pub fn bootstrap_boot_thread() -> TcbId {
    unsafe {
        let s = KERNEL.get();
        let mut t = Tcb::default();
        t.priority = 254; // top priority — kernel boot
        t.state = ThreadStateType::Running;
        let id = s.scheduler.admit(t);
        s.scheduler.current = Some(id);
        id
    }
}

/// Get the currently-running thread, or `None` if the bootstrap
/// hasn't run yet. Useful for syscall handlers that need to know
/// *which* TCB to consult for the CSpace lookup.
pub fn current_thread() -> Option<TcbId> {
    unsafe { KERNEL.get().scheduler.current }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_kernel_state() {
        arch::log("Running KernelState tests...\n");
        bootstrap_registers_boot_thread();
        scheduler_state_persists_across_calls();
        arch::log("KernelState tests completed\n");
    }

    #[inline(never)]
    fn bootstrap_registers_boot_thread() {
        let id = bootstrap_boot_thread();
        assert_eq!(current_thread(), Some(id));
        // The boot thread sits at the top of priority space.
        unsafe {
            let s = KERNEL.get();
            let tcb = s.scheduler.slab.get(id);
            assert_eq!(tcb.priority, 254);
            assert_eq!(tcb.state, ThreadStateType::Running);
        }
        arch::log("  ✓ boot thread admitted as the current TCB\n");
    }

    #[inline(never)]
    fn scheduler_state_persists_across_calls() {
        // bootstrap_boot_thread already ran above. Add a second TCB
        // and confirm we see both.
        let mut t = Tcb::default();
        t.priority = 50;
        t.state = ThreadStateType::Running;
        unsafe {
            let s = KERNEL.get();
            let id2 = s.scheduler.admit(t);
            assert!(id2 != current_thread().unwrap(),
                "second TCB should have a different id");
            // Both threads at different priorities — choose_thread
            // picks the higher one (boot thread).
            let chosen = s.scheduler.choose_thread();
            assert_eq!(chosen, current_thread());
            // Free the temp.
            s.scheduler.slab.free(id2);
        }
        arch::log("  ✓ KernelState singleton persists across calls\n");
    }
}
