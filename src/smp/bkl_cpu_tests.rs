use super::{AcquisitionCpu, BigKernelLock, ReleaseError};
use core::cell::Cell;

#[test]
fn one_physical_sample_survives_failed_admission_and_mailbox_polling() {
    for physical in 0..4 {
        let samples = Cell::new(0);
        let cpu = AcquisitionCpu::sample(
            || {
                samples.set(samples.get() + 1);
                physical
            },
            4,
        );
        let lock = BigKernelLock::new();
        let foreign_owner = (physical + 1) % 4 + 1;
        while !lock.try_acquire(foreign_owner) {}
        let mut pending_retirement = true;
        let mut entry = Some(physical);
        let mut adopted = false;
        let mut flushed = [false; 4];
        let mut acknowledged = [false; 4];
        for _ in 0..16 {
            assert!(!lock.try_acquire(cpu.owner()));
            assert_eq!(lock.release(cpu.owner()), Err(ReleaseError::NotOwner));
            if pending_retirement {
                flushed[cpu.index()] = true;
                assert!(flushed[cpu.index()]);
                acknowledged[cpu.index()] = true;
                pending_retirement = false;
            }
            adopted |= entry.take().is_some();
            assert_eq!(cpu.id(), physical);
        }
        assert!(adopted);
        assert!(entry.is_none());
        assert!(acknowledged[physical as usize]);
        assert_eq!(acknowledged.iter().filter(|ack| **ack).count(), 1);
        assert_eq!(samples.get(), 1);
        assert_eq!(lock.release(foreign_owner), Ok(()));
        while !lock.try_acquire(cpu.owner()) {}
        assert_eq!(lock.holder(), physical + 1);
        assert_eq!(lock.release(cpu.owner()), Ok(()));
    }
}

#[test]
#[should_panic(expected = "physical CPU outside mailbox range")]
fn sampled_physical_identity_must_fit_mailboxes() {
    AcquisitionCpu::sample(|| 4, 4);
}

#[test]
fn native_acquisition_samples_hardware_once_and_threads_identity_through_polls() {
    let source = include_str!("../smp.rs");
    let acquisition = source
        .split_once("pub(crate) fn bkl_acquire_for_user_entry(")
        .unwrap()
        .1;
    let acquisition = acquisition.split_once("/// Release the BKL").unwrap().0;
    assert_eq!(acquisition.matches("crate::arch::get_cpu_id").count(), 1);
    let sample = acquisition
        .find("AcquisitionCpu::sample(crate::arch::get_cpu_id")
        .unwrap();
    let retirement = acquisition
        .find("service_retirement_shootdown_for_cpu(cpu)")
        .unwrap();
    assert!(sample < retirement);
    assert_eq!(
        acquisition
            .matches("service_retirement_shootdown_for_cpu(cpu)")
            .count(),
        2
    );
    assert_eq!(
        acquisition
            .matches("service_quiescence(cpu, &mut entry)")
            .count(),
        2
    );
    assert!(!acquisition.contains("service_retirement_shootdown();"));
    assert!(!acquisition.contains("gs:"));

    let quiescence = include_str!("quiescence.rs");
    let poll = quiescence.split_once("fn service_quiescence(").unwrap().1;
    let poll = poll.split_once("/// Synchronously withdraw").unwrap().0;
    assert!(!poll.contains("get_cpu_id"));
    assert!(poll.contains("service_retirement_shootdown_for_cpu(cpu)"));
    assert!(poll.contains("QUIESCENCE[cpu.index()]"));

    let flush = source
        .split_once("fn flush_retired_translations(")
        .unwrap()
        .1;
    let flush = flush
        .split_once("/// Lock-independent retirement service")
        .unwrap()
        .0;
    assert!(!flush.contains("get_cpu_id"));
    assert!(flush.contains("RETIREMENT_FLUSHES[cpu.index()]"));
    assert_eq!(flush.matches("mov cr4,").count(), 2);

    let service = source
        .split_once("fn service_retirement_shootdown_for_cpu(")
        .unwrap()
        .1;
    let service = service
        .split_once("/// Synchronous translation retirement")
        .unwrap()
        .0;
    assert!(!service.contains("get_cpu_id"));
    assert!(service.contains("RETIREMENT_MAILBOXES[cpu.index()]"));
    assert!(
        service.find("flush_retired_translations(cpu)").unwrap()
            < service.find("mailbox.acknowledge()").unwrap()
    );
    let wrapper = source
        .split_once("pub(crate) fn service_retirement_shootdown()")
        .unwrap()
        .1;
    let wrapper = wrapper
        .split_once("fn service_retirement_shootdown_for_cpu(")
        .unwrap()
        .0;
    assert!(wrapper.contains("AcquisitionCpu::sample(crate::arch::get_cpu_id"));
}
