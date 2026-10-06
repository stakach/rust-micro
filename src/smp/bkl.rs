//! Atomic CPU ownership for the big kernel lock; waiting and quiescence live in the caller.
use core::sync::atomic::{AtomicU32, Ordering};

/// One trusted physical-CPU sample for a non-migrating kernel acquisition.
/// The caller supplies the hardware reader, never user TLS or thread affinity.
/// Discard this value before returning or dispatching to user mode.
#[derive(Copy, Clone)]
pub(super) struct AcquisitionCpu(u32);

impl AcquisitionCpu {
    pub(super) fn sample(read_hardware: impl FnOnce() -> u32, cpu_limit: usize) -> Self {
        let cpu = read_hardware();
        assert!(
            (cpu as usize) < cpu_limit,
            "physical CPU outside mailbox range"
        );
        assert!(cpu < u32::MAX, "physical CPU cannot encode BKL owner");
        Self(cpu)
    }

    pub(super) fn id(self) -> u32 {
        self.0
    }

    pub(super) fn index(self) -> usize {
        self.0 as usize
    }

    pub(super) fn owner(self) -> u32 {
        self.0 + 1
    }
}

pub struct BigKernelLock {
    owner: AtomicU32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseError {
    NotOwner,
}

impl BigKernelLock {
    pub const fn new() -> Self {
        Self {
            owner: AtomicU32::new(0),
        }
    }

    pub fn holder(&self) -> u32 {
        self.owner.load(Ordering::Relaxed)
    }

    pub fn try_acquire(&self, owner: u32) -> bool {
        assert_ne!(owner, 0, "zero does not identify a CPU owner");
        self.owner
            .compare_exchange_weak(0, owner, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Publish protected writes only when the exact nonzero owner releases.
    /// Refusing an unowned release never changes the current holder.
    pub fn release(&self, owner: u32) -> Result<(), ReleaseError> {
        if owner == 0 {
            return Err(ReleaseError::NotOwner);
        }
        self.owner
            .compare_exchange(owner, 0, Ordering::Release, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| ReleaseError::NotOwner)
    }
}

#[cfg(test)]
#[path = "bkl_cpu_tests.rs"]
mod cpu_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn acquire(lock: &BigKernelLock, owner: u32) {
        while !lock.try_acquire(owner) {
            core::hint::spin_loop();
        }
    }

    #[test]
    fn spurious_idle_release_cannot_withdraw_peer_ownership() {
        let lock = BigKernelLock::new();
        acquire(&lock, 1);
        assert_eq!(lock.release(1), Ok(()));
        acquire(&lock, 1);
        // No-thread wake mistakenly releases at the tail, then releases again at the head.
        assert_eq!(lock.release(1), Ok(()));
        acquire(&lock, 2);
        assert_eq!(lock.release(1), Err(ReleaseError::NotOwner));
        assert_eq!(lock.holder(), 2);
        assert_eq!(lock.release(2), Ok(()));
    }

    #[test]
    fn unowned_and_zero_release_are_refused() {
        let lock = BigKernelLock::new();
        assert_eq!(lock.release(1), Err(ReleaseError::NotOwner));
        assert_eq!(lock.release(0), Err(ReleaseError::NotOwner));
        acquire(&lock, 1);
        assert_eq!(lock.release(0), Err(ReleaseError::NotOwner));
        assert_eq!(lock.holder(), 1);
    }

    #[test]
    fn valid_owner_serializes_acquire_and_release() {
        let lock = BigKernelLock::new();
        for _ in 0..128 {
            for owner in 1..=4 {
                acquire(&lock, owner);
                assert_eq!(lock.holder(), owner);
                assert!(!lock.try_acquire(owner));
                assert!(!lock.try_acquire(owner % 4 + 1));
                assert_eq!(lock.release(owner), Ok(()));
                assert_eq!(lock.holder(), 0);
            }
        }
    }

    #[test]
    fn concurrent_owners_publish_protected_writes() {
        use core::sync::atomic::AtomicUsize;
        use std::sync::Arc;

        let shared = Arc::new((BigKernelLock::new(), AtomicUsize::new(0)));
        let mut workers = std::vec::Vec::new();
        for owner in 1..=4 {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                for _ in 0..1024 {
                    acquire(&shared.0, owner);
                    assert_eq!(shared.0.release(owner % 4 + 1), Err(ReleaseError::NotOwner));
                    assert_eq!(shared.0.holder(), owner);
                    let value = shared.1.load(Ordering::Relaxed);
                    shared.1.store(value + 1, Ordering::Relaxed);
                    assert_eq!(shared.0.release(owner), Ok(()));
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        acquire(&shared.0, 5);
        assert_eq!(shared.1.load(Ordering::Relaxed), 4096);
        assert_eq!(shared.0.release(5), Ok(()));
    }

    #[test]
    fn native_syscall_spurious_idle_backedge_retains_ownership() {
        let source = include_str!("../arch/x86_64/syscall_entry.rs");
        let (_, idle) = source.split_once("} else if from_user != 0 {").unwrap();
        let (idle, _) = idle.split_once("// Specs").unwrap();
        let (head, dispatch) = idle.split_once("if let Some(next_id) = next {").unwrap();
        let release = head.find("crate::smp::bkl_release();").unwrap();
        let halt = head
            .find("core::arch::asm!(\"sti\", \"hlt\", \"cli\"")
            .unwrap();
        let acquire = head.find("crate::smp::bkl_acquire();").unwrap();
        assert!(release < halt && halt < acquire);
        assert_eq!(head.matches("crate::smp::bkl_release();").count(), 1);
        let (_, backedge) = dispatch.split_once("// unreachable").unwrap();
        let (backedge, _) = backedge.split_once("// Spurious wake").unwrap();
        assert!(
            !backedge.contains("bkl_release"),
            "a no-thread wake must retain ownership until the next idle-loop head"
        );
        let observation = backedge.split_once("#[cfg(feature = \"spec\")]").unwrap().1;
        let ownership = observation.find("crate::smp::bkl_holder()").unwrap();
        let increment = observation
            .find("SYSCALL_IDLE_BACKEDGES.fetch_add(")
            .unwrap();
        assert!(ownership < increment);
        assert!(observation.contains("crate::arch::get_cpu_id() + 1"));
        assert_eq!(
            source.matches("SYSCALL_IDLE_BACKEDGES.fetch_add(").count(),
            1
        );
    }

    #[test]
    fn native_microtest_completion_reports_live_idle_observation_before_exit() {
        for source in [
            include_str!("../arch/x86_64/syscall_entry.rs"),
            include_str!("../syscall_handler.rs"),
        ] {
            let hook = source
                .split_once("if crate::rootserver::microtest_check_byte(")
                .unwrap()
                .1;
            let report = hook
                .find("crate::smp::print_syscall_idle_backedges();")
                .unwrap();
            let exit = hook.find("crate::arch::qemu_exit(0);").unwrap();
            assert!(report < exit);
            assert!(hook[..report].contains("#[cfg(feature = \"spec\")]"));
        }
        let source = include_str!("../smp.rs");
        let report = source
            .split_once("pub(crate) fn print_syscall_idle_backedges()")
            .unwrap()
            .1;
        let report = report.split_once("static BKL_WAITERS").unwrap().0;
        assert!(report.contains("[spec-bkl] syscall_idle_backedges="));
        assert!(!report.contains("fetch_add"));
    }
}
