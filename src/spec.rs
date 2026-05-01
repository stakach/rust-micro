use crate::arch;

mod abi_layout_tests;
mod arch_tests;
mod integration_tests;
mod structures_tests;

pub fn test_main() {
    arch::log("Starting kernel specs...\n");

    arch_tests::test_architecture();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::gdt::spec::test_gdt();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::syscall_entry::spec::test_syscall_msrs();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::paging::spec::test_paging();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::lapic::spec::test_lapic();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::pit::spec::test_pit();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::pic::spec::test_pic();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::acpi::spec::test_acpi();
    structures_tests::test_structures();
    abi_layout_tests::test_abi_layout();
    crate::cap::spec::test_cap_roundtrip();
    crate::cspace::spec::test_cspace_lookup();
    crate::region::spec::test_region();
    crate::object_type::spec::test_object_type();
    crate::untyped::spec::test_untyped();
    crate::tcb::spec::test_tcb();
    crate::scheduler::spec::test_scheduler();
    crate::kernel::spec::test_kernel_state();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::context::spec::test_context_switch();
    crate::syscall_handler::spec::test_syscall_handler();
    crate::invocation::spec::test_invocation();
    crate::fault::spec::test_fault();
    crate::endpoint::spec::test_endpoint();
    crate::notification::spec::test_notification();
    crate::interrupt::spec::test_interrupt();
    crate::vspace::spec::test_vspace();
    crate::boot::spec::test_boot();
    integration_tests::test_integration();

    #[cfg(feature = "mcs")]
    crate::sched_context::spec::test_sched_context();
    #[cfg(feature = "smp")]
    crate::smp::spec::test_smp();
    #[cfg(feature = "fastpath")]
    crate::fastpath::spec::test_fastpath();
    #[cfg(feature = "fpu")]
    crate::fpu::spec::test_fpu();
    #[cfg(feature = "vmx")]
    crate::vcpu::spec::test_vcpu();

    arch::log("All specs passed!\n");
    // Don't `qemu_exit` here — control returns to `main` so the
    // real-hardware boot path (Phase 12d's `boot::kernel_init`)
    // gets exercised before we leave QEMU.
}
