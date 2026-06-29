//! Eager per-CPU FPU (x87/SSE) context save/restore for SMP.
//!
//! The default single-node kernel passes every FPU test without any
//! save/restore: with effectively one FPU user live at a time, a
//! thread's x87/SSE state simply stays resident in the hardware until
//! it next runs. That breaks the moment a thread MIGRATES between
//! cores (sel4test FPU0002): a worker resumes on a new core whose FPU
//! registers hold some *other* thread's state, reads garbage, and
//! corrupts (the observed failure is a #GP from a RIP that is actually
//! an FPU `double`).
//!
//! Because the kernel itself is built `-sse,-sse2,+soft-float`, kernel
//! code never touches user xmm/x87 registers. A user thread's FPU
//! state therefore stays live in the hardware across kernel execution
//! until something explicitly `fxrstor`s a *different* thread. That
//! makes an EAGER per-CPU-owner model both correct and simple:
//!
//!   * Each core tracks which TCB's state is currently resident in its
//!     FPU register file (`FPU_OWNER[core]`).
//!   * On every user-entry dispatch we `fpu_switch_to(next)`: if the
//!     resident owner is already `next` we do nothing; otherwise we
//!     `fxsave64` the outgoing owner into its TCB and `fxrstor64` the
//!     incoming thread's saved state.
//!   * When a running thread is migrated off a core (the remote-stall
//!     park point), the core flushes its resident FPU state back to the
//!     migrating thread's TCB so the destination core restores fresh
//!     state — `flush_local_fpu`.
//!   * On thread teardown we drop any core's ownership of the freed
//!     TCB — `fpu_release` (mirrors seL4's `fpuRelease`).
//!
//! This whole module is gated behind the `smp` cargo feature; the
//! default build compiles it away entirely and is byte-for-byte
//! unchanged.

#![cfg(feature = "smp")]

use core::sync::atomic::{AtomicU32, Ordering};

use crate::smp::MAX_CPUS;
use crate::tcb::{FxArea, TcbId, TcbSlab};

const _: () = assert!(
    MAX_CPUS == 4,
    "FPU_OWNER is hand-listed for MAX_CPUS=4; bump it if you raise the cap",
);

/// Which TCB's FPU state is live in each core's register file.
/// 0 = none (template / nothing meaningful loaded); otherwise the
/// owning `TcbId.0 + 1`. `AtomicU32` so a teardown on one core can
/// clear a sibling core's ownership without a lock — every other
/// access happens under the BKL.
pub static FPU_OWNER: [AtomicU32; MAX_CPUS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

// ---------------------------------------------------------------------------
// Boot template — a valid FINIT FXSAVE image copied into every new TCB.
//
// `fxrstor` of zeroed memory can #GP (reserved MXCSR bits), so a fresh
// TCB must start from a *valid* state, not zeros. We capture one at
// boot (`fninit; fxsave64`) and stamp it into each TCB at allocation.
// The static is pre-seeded with `FxArea::FINIT` so it is valid even
// before `init_fpu_template` runs.
// ---------------------------------------------------------------------------

#[repr(C, align(16))]
struct Template([u8; 512]);

static mut FX_TEMPLATE: Template = Template(FxArea::FINIT.0);

/// Capture the canonical FINIT FPU state into `FX_TEMPLATE`. Also
/// ensures CR4.OSFXSR (+OSXMMEXCPT) so `fxsave`/`fxrstor` and user SSE
/// are valid. Call once on the BSP at boot.
pub fn init_fpu_template() {
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4,
            options(nomem, nostack, preserves_flags));
        // OSFXSR (bit 9) enables fxsave/fxrstor + SSE; OSXMMEXCPT
        // (bit 10) routes SIMD FP exceptions to #XF.
        cr4 |= (1 << 9) | (1 << 10);
        core::arch::asm!("mov cr4, {}", in(reg) cr4,
            options(nomem, nostack, preserves_flags));
        let p = core::ptr::addr_of_mut!(FX_TEMPLATE.0) as *mut u8;
        core::arch::asm!("fninit", options(nostack, preserves_flags));
        fxsave64(p);
    }
}

/// Copy the boot FPU template into a freshly-allocated TCB's save area.
pub fn stamp_template(area: &mut FxArea) {
    unsafe {
        let src = core::ptr::addr_of!(FX_TEMPLATE.0) as *const u8;
        core::ptr::copy_nonoverlapping(src, area.0.as_mut_ptr(), 512);
    }
}

// ---------------------------------------------------------------------------
// Raw fxsave/fxrstor. Valid even in a soft-float kernel — they move the
// whole 512-byte legacy area, they're not SSE arithmetic. `ptr` must be
// 16-byte aligned (FxArea / Template are `align(16)`).
// ---------------------------------------------------------------------------

#[inline]
unsafe fn fxsave64(ptr: *mut u8) {
    core::arch::asm!("fxsave64 [{}]", in(reg) ptr,
        options(nostack, preserves_flags));
}

#[inline]
unsafe fn fxrstor64(ptr: *const u8) {
    core::arch::asm!("fxrstor64 [{}]", in(reg) ptr,
        options(nostack, preserves_flags));
}

// ---------------------------------------------------------------------------
// Switch / flush / release.
// ---------------------------------------------------------------------------

/// Make `next`'s saved FPU state resident in the calling core's FPU
/// registers, saving the outgoing owner first. Caller holds the BKL.
/// Call at every user-entry dispatch site (next to `apply_fpu_gate_for`).
pub unsafe fn fpu_switch_to(slab: &mut TcbSlab, next: TcbId) {
    let me = crate::arch::get_cpu_id() as usize;
    if me >= MAX_CPUS {
        return;
    }
    let next_enc = next.0 as u32 + 1;
    let cur = FPU_OWNER[me].load(Ordering::Relaxed);
    if cur == next_enc {
        // Already resident — nothing to do.
        return;
    }
    // `fxsave`/`fxrstor` themselves raise #NM when CR0.TS=1, and the
    // outgoing thread may have left TS set (an `fpuDisabled` thread runs
    // with TS=1). Clear it before touching the FPU; the caller's
    // `apply_fpu_gate_for`, which runs AFTER us, restores the correct TS
    // for the incoming thread.
    core::arch::asm!("clts", options(nomem, nostack, preserves_flags));
    if cur != 0 {
        let prev = TcbId((cur - 1) as u16);
        if let Some(t) = slab.try_get(prev) {
            fxsave64(t.fpu_state.0.as_ptr() as *mut u8);
        }
    }
    if let Some(t) = slab.try_get(next) {
        fxrstor64(t.fpu_state.0.as_ptr());
        FPU_OWNER[me].store(next_enc, Ordering::Relaxed);
    }
}

/// Flush the calling core's resident FPU state back to its owner TCB
/// and mark the core as owning nobody. Used at the remote-stall park
/// point: a thread migrated off this core has its live FPU state here,
/// not in its TCB, so it must be written back before it runs elsewhere.
/// Caller holds the BKL.
pub unsafe fn flush_local_fpu(slab: &mut TcbSlab) {
    let me = crate::arch::get_cpu_id() as usize;
    if me >= MAX_CPUS {
        return;
    }
    let cur = FPU_OWNER[me].load(Ordering::Relaxed);
    if cur != 0 {
        // `fxsave` #NMs if TS=1 (the migrating thread may be fpuDisabled).
        core::arch::asm!("clts", options(nomem, nostack, preserves_flags));
        let prev = TcbId((cur - 1) as u16);
        if let Some(t) = slab.try_get(prev) {
            fxsave64(t.fpu_state.0.as_ptr() as *mut u8);
        }
        FPU_OWNER[me].store(0, Ordering::Relaxed);
    }
}

/// True if `id`'s FPU state is currently resident in `cpu`'s registers
/// (i.e. live there but not yet flushed to its TCB). Used by the migrate
/// path to decide whether the source core must be stalled to flush the
/// FPU even when the thread is no longer the source core's *current*
/// thread — the core may have gone idle after it ran, leaving its FPU
/// image stranded in registers (the FPU0002 double-ownership window).
pub fn owner_is(cpu: usize, id: TcbId) -> bool {
    cpu < MAX_CPUS && FPU_OWNER[cpu].load(Ordering::Relaxed) == id.0 as u32 + 1
}

/// Drop any core's ownership of `id` (mirrors seL4 `fpuRelease`). Call
/// on thread teardown: the TCB's save area is about to vanish, so a
/// later `fpu_switch_to` must not try to `fxsave` into it.
pub fn fpu_release(id: TcbId) {
    let enc = id.0 as u32 + 1;
    for o in FPU_OWNER.iter() {
        let _ = o.compare_exchange(enc, 0, Ordering::Relaxed, Ordering::Relaxed);
    }
}
