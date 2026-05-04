//! Phase 10d — lazy FPU state switch.
//!
//! Mirrors seL4/src/machine/fpu.c at the algorithm level. The FPU
//! is large (512 bytes for legacy fxsave, more with XSAVE) so seL4
//! avoids saving/restoring it on every thread switch. Instead it
//! tracks which thread currently "owns" the FPU register file and
//! sets the CR0.TS bit when a different thread runs. The next time
//! anyone touches the FPU, the CPU raises #NM and the kernel:
//!
//!   1. Saves the previous owner's state into its TCB's fpu_state.
//!   2. Restores the new thread's saved state into the FPU.
//!   3. Updates the owner to the new thread, clears CR0.TS.
//!
//! This module owns the bookkeeping side; the actual fxsave/fxrstor
//! and CR0 manipulation is the arch driver's job. Behind the `fpu`
//! feature.

#![cfg(feature = "fpu")]

use crate::tcb::TcbId;

/// Placeholder for an FPU register file. Real fxsave region is 512
/// bytes aligned to 16; XSAVE goes up to 4 KiB depending on
/// supported extensions. We keep the storage on the TCB conceptually
/// — represented here by a TcbId as the "where to save" reference.
/// Specs don't exercise the actual save bytes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FpuState {
    /// Bumped every save/restore so specs can verify the right
    /// number of context switches happened.
    pub generation: u32,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct FpuOwner {
    /// Thread whose state is currently loaded into the hardware FPU
    /// (or `None` if nobody has used the FPU since boot).
    pub current: Option<TcbId>,
    /// Total #NM faults handled — useful telemetry & spec hook.
    pub trap_count: u32,
    /// Total context switches that needed an actual FPU save.
    pub save_count: u32,
}

/// Hooks the arch layer should call. The state-machine functions
/// take an `&mut [FpuState; N]` keyed by `TcbId` so we don't need a
/// separate map; production stores fpu_state inline on the Tcb.
pub trait FpuStorage {
    fn state(&mut self, tcb: TcbId) -> &mut FpuState;
}

/// Called by the trap handler when a thread tries to use the FPU
/// while CR0.TS is set. Saves the previous owner (if any) and
/// switches ownership to `current`. Returns `(saved_from,
/// restored_to)` so the arch driver knows whose register file to
/// emit fxsave / fxrstor against.
pub fn on_fpu_trap<S: FpuStorage>(
    owner: &mut FpuOwner,
    storage: &mut S,
    current: TcbId,
) -> FpuSwitch {
    owner.trap_count += 1;
    let prev = owner.current;
    if let Some(p) = prev {
        if p == current {
            // Nothing to do — CR0.TS was set spuriously, just clear it.
            return FpuSwitch::NoOp;
        }
        // Save previous owner's state.
        storage.state(p).generation = storage.state(p).generation.wrapping_add(1);
        owner.save_count += 1;
    }
    // Restore current's state.
    storage.state(current).generation = storage.state(current).generation.wrapping_add(1);
    owner.current = Some(current);
    FpuSwitch::Switched { prev, restored: current }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FpuSwitch {
    /// CR0.TS was set but `current` already owned the FPU; just
    /// clear TS and resume.
    NoOp,
    /// Saved `prev` (if Some) and loaded `restored`.
    Switched { prev: Option<TcbId>, restored: TcbId },
}

/// Forcibly release the FPU on thread teardown. Mirrors seL4's
/// `fpuRelease`. If the freed thread held the FPU, its state is
/// dropped (it won't run again so no save needed).
pub fn release(owner: &mut FpuOwner, tcb: TcbId) {
    if owner.current == Some(tcb) {
        owner.current = None;
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    struct Storage([FpuState; 4]);
    impl FpuStorage for Storage {
        fn state(&mut self, t: TcbId) -> &mut FpuState {
            &mut self.0[t.0 as usize]
        }
    }

    pub fn test_fpu() {
        arch::log("Running FPU lazy-switch tests...\n");
        first_use_loads_state();
        same_owner_is_noop();
        switch_to_other_saves_and_restores();
        release_clears_owner();
        arch::log("FPU lazy-switch tests completed\n");
    }

    #[inline(never)]
    fn first_use_loads_state() {
        let mut owner = FpuOwner::default();
        let mut store = Storage([FpuState::default(); 4]);
        let r = on_fpu_trap(&mut owner, &mut store, TcbId(1));
        assert_eq!(r, FpuSwitch::Switched { prev: None, restored: TcbId(1) });
        assert_eq!(owner.current, Some(TcbId(1)));
        assert_eq!(owner.trap_count, 1);
        assert_eq!(owner.save_count, 0); // nothing to save first time
        assert_eq!(store.0[1].generation, 1);
        arch::log("  ✓ first FPU use loads state, no save needed\n");
    }

    #[inline(never)]
    fn same_owner_is_noop() {
        let mut owner = FpuOwner::default();
        let mut store = Storage([FpuState::default(); 4]);
        on_fpu_trap(&mut owner, &mut store, TcbId(1));
        let r = on_fpu_trap(&mut owner, &mut store, TcbId(1));
        // Spurious TS — just clear it.
        assert_eq!(r, FpuSwitch::NoOp);
        assert_eq!(owner.save_count, 0);
        arch::log("  ✓ trap from same owner is a no-op\n");
    }

    #[inline(never)]
    fn switch_to_other_saves_and_restores() {
        let mut owner = FpuOwner::default();
        let mut store = Storage([FpuState::default(); 4]);
        on_fpu_trap(&mut owner, &mut store, TcbId(1));
        let r = on_fpu_trap(&mut owner, &mut store, TcbId(2));
        assert_eq!(r, FpuSwitch::Switched { prev: Some(TcbId(1)), restored: TcbId(2) });
        assert_eq!(owner.save_count, 1);
        // Both saved-state generations bumped: TcbId(1) once, TcbId(2) twice.
        assert_eq!(store.0[1].generation, 2);
        assert_eq!(store.0[2].generation, 1);
        arch::log("  ✓ switch saves prev owner, restores new\n");
    }

    #[inline(never)]
    fn release_clears_owner() {
        let mut owner = FpuOwner::default();
        let mut store = Storage([FpuState::default(); 4]);
        on_fpu_trap(&mut owner, &mut store, TcbId(2));
        release(&mut owner, TcbId(2));
        assert_eq!(owner.current, None);
        // Releasing a thread that doesn't own the FPU is a no-op.
        release(&mut owner, TcbId(3));
        assert_eq!(owner.current, None);
        arch::log("  ✓ release clears owner only when freed thread held it\n");
    }
}
