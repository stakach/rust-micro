//! Which user address spaces each CPU may still cache translations for.
//!
//! The kernel runs with CR4.PCIDE clear and never maps user pages global, so a CR3 write
//! discards every non-global TLB and paging-structure-cache entry. A CPU can therefore cache
//! user translations only for the root it most recently loaded. A CPU parked on the kernel
//! root (idle, halted, or quiesced) holds none and needs no retirement IPI.
//!
//! Every CR3 write goes through [`load_root`]. It publishes `ANY` before the write and the
//! exact result after it, so the record is never narrower than the TLB contents. Retirement
//! clears the PTE, issues a full fence, and then samples the record: either it observes the
//! CPU's publication, or that CPU's page walks begin after the fence and see the cleared entry.
use core::sync::atomic::{fence, AtomicU64, Ordering};

use super::MAX_CPUS;

const ROOT_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// No user translations: the last CR3 write loaded the kernel root.
pub(super) const NO_USER_ROOT: u64 = 0;
/// A CR3 transition is in flight; translations for any root may be cached.
pub(super) const ANY_USER_ROOT: u64 = u64::MAX;

/// Boot CPUs start on the kernel root and have never loaded a user root.
static RESIDENT_USER_ROOT: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(NO_USER_ROOT) }; MAX_CPUS];

/// What a retirement must flush.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum RetirementScope {
    /// Translations derived from this user root only.
    Root(u64),
    /// Translations from any user root (a detached table may be reachable from several).
    AnyUserRoot,
    /// Translations through the kernel root, which every online CPU may have loaded.
    KernelRoot,
}

impl RetirementScope {
    /// Classify a root named by a capability. Spec fixtures can map user pages into the
    /// kernel root; those are not covered by any CPU's residency record.
    pub(super) fn for_root(root: u64, kernel_root: u64) -> Self {
        if kernel_root != 0 && root & ROOT_MASK == kernel_root & ROOT_MASK {
            Self::KernelRoot
        } else {
            Self::Root(root & ROOT_MASK)
        }
    }
}

/// Record value for a CPU whose CR3 now holds `cr3`.
fn resident_after(cr3: u64, kernel_root: u64) -> u64 {
    let root = cr3 & ROOT_MASK;
    if kernel_root != 0 && root == kernel_root & ROOT_MASK {
        NO_USER_ROOT
    } else {
        root
    }
}

/// Whether a CPU with `resident` may cache a translation covered by `scope`.
fn may_hold(resident: u64, scope: RetirementScope) -> bool {
    match (resident, scope) {
        (_, RetirementScope::KernelRoot) => true,
        (NO_USER_ROOT, _) => false,
        (ANY_USER_ROOT, _) | (_, RetirementScope::AnyUserRoot) => true,
        (resident, RetirementScope::Root(root)) => resident == root & ROOT_MASK,
    }
}

/// CPUs other than `me` in `online` that must acknowledge a flush before retirement completes.
pub(super) fn retirement_targets(
    online: u32,
    me: u32,
    resident: &[u64; MAX_CPUS],
    scope: RetirementScope,
) -> u32 {
    (0..MAX_CPUS as u32)
        .filter(|cpu| online & (1 << cpu) != 0 && *cpu != me)
        .filter(|cpu| may_hold(resident[*cpu as usize], scope))
        .fold(0, |mask, cpu| mask | (1 << cpu))
}

/// Sample every CPU's record after the caller's page-table stores.
pub(super) fn snapshot_after_unmap() -> [u64; MAX_CPUS] {
    fence(Ordering::SeqCst);
    core::array::from_fn(|cpu| RESIDENT_USER_ROOT[cpu].load(Ordering::SeqCst))
}

/// Load `cr3` on the calling CPU and keep its residency record conservative.
///
/// # Safety
/// `cr3` must name a root whose kernel half matches the kernel root. The caller runs in
/// kernel mode with IF clear.
pub unsafe fn load_root(cr3: u64) {
    let cpu = crate::arch::get_cpu_id() as usize;
    let record = &RESIDENT_USER_ROOT[cpu];
    record.store(ANY_USER_ROOT, Ordering::SeqCst);
    fence(Ordering::SeqCst);
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
    let kernel_root = crate::arch::x86_64::paging::kernel_root_cr3();
    record.store(resident_after(cr3, kernel_root), Ordering::Release);
}

#[cfg(feature = "spec")]
pub(super) fn resident(cpu: usize) -> u64 {
    RESIDENT_USER_ROOT[cpu].load(Ordering::Acquire)
}

/// Stand in for a CPU that loaded `root` without moving its CR3. Spec only.
#[cfg(feature = "spec")]
pub(super) fn set_resident_for_spec(cpu: usize, root: u64) {
    RESIDENT_USER_ROOT[cpu].store(root, Ordering::SeqCst);
}

/// Spec fixtures build VSpaces no CPU has loaded. While this guard lives, every other online
/// CPU is treated as possibly caching any user root, so each retirement still exercises real
/// remote flushes and ACKs. Records changed by an actual CR3 load are left as published.
#[cfg(feature = "spec")]
pub struct AssumeRemoteUserTranslations {
    changed: u32,
}

#[cfg(feature = "spec")]
impl AssumeRemoteUserTranslations {
    pub fn new() -> Self {
        let me = crate::arch::get_cpu_id();
        let online = super::ONLINE_CPUS.load(Ordering::Acquire);
        let mut changed = 0;
        for cpu in 0..MAX_CPUS as u32 {
            if cpu != me && online & (1 << cpu) != 0
                && RESIDENT_USER_ROOT[cpu as usize]
                    .compare_exchange(NO_USER_ROOT, ANY_USER_ROOT, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                changed |= 1 << cpu;
            }
        }
        Self { changed }
    }
}

#[cfg(feature = "spec")]
impl Drop for AssumeRemoteUserTranslations {
    fn drop(&mut self) {
        for cpu in 0..MAX_CPUS {
            if self.changed & (1 << cpu) != 0 {
                let _ = RESIDENT_USER_ROOT[cpu].compare_exchange(
                    ANY_USER_ROOT, NO_USER_ROOT, Ordering::SeqCst, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(feature = "spec")]
pub(super) mod spec {
    use super::*;

    const KERNEL: u64 = 0x10_0000;
    const A: u64 = 0x20_0000;
    const B: u64 = 0x30_0000;

    pub(in crate::smp) fn run() {
        record_tracks_last_loaded_root();
        targets_only_cpus_that_may_hold_the_root();
        crate::arch::log("  retirement targets only CPUs that may cache the user root\n");
    }

    fn record_tracks_last_loaded_root() {
        assert_eq!(resident_after(KERNEL, KERNEL), NO_USER_ROOT);
        assert_eq!(resident_after(KERNEL | 0x18, KERNEL), NO_USER_ROOT, "CR3 flag bits are ignored");
        assert_eq!(resident_after(A | 0x8, KERNEL), A);
        assert_eq!(resident_after(A, 0), A, "uncaptured kernel root never hides a user root");
        assert_eq!(RetirementScope::for_root(A | 0x18, KERNEL), RetirementScope::Root(A));
        assert_eq!(RetirementScope::for_root(KERNEL, KERNEL), RetirementScope::KernelRoot);
        assert_eq!(RetirementScope::for_root(KERNEL, 0), RetirementScope::Root(KERNEL));
    }

    fn targets_only_cpus_that_may_hold_the_root() {
        let all = 0b1111;
        // CPU0 retires; CPU1 ran A; CPU2 is halted on the kernel root; CPU3 is mid-transition.
        let resident = [A, A, NO_USER_ROOT, ANY_USER_ROOT];
        assert_eq!(retirement_targets(all, 0, &resident, RetirementScope::Root(A)), 0b1010);
        assert_eq!(retirement_targets(all, 0, &resident, RetirementScope::Root(A | 0x18)), 0b1010);
        assert_eq!(retirement_targets(all, 0, &resident, RetirementScope::Root(B)), 0b1000);
        assert_eq!(retirement_targets(all, 0, &resident, RetirementScope::AnyUserRoot), 0b1010);
        let resident = [NO_USER_ROOT, B, A, NO_USER_ROOT];
        assert_eq!(retirement_targets(all, 0, &resident, RetirementScope::AnyUserRoot), 0b0110);
        assert_eq!(retirement_targets(all, 2, &resident, RetirementScope::Root(A)), 0, "the caller flushes locally");
        assert_eq!(retirement_targets(0b0011, 0, &resident, RetirementScope::Root(A)), 0, "offline CPUs never ran user code");
        assert_eq!(
            retirement_targets(all, 0, &[NO_USER_ROOT; MAX_CPUS], RetirementScope::AnyUserRoot),
            0,
            "CPUs parked on the kernel root need no IPI",
        );
        assert_eq!(
            retirement_targets(all, 0, &[NO_USER_ROOT; MAX_CPUS], RetirementScope::KernelRoot),
            0b1110,
            "kernel-root translations may be cached by every online CPU",
        );
    }
}
