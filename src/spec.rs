use crate::arch;

mod abi_layout_tests;
mod arch_tests;
mod integration_tests;
mod kernel_guard;
mod structures_tests;

pub(crate) use kernel_guard::KernelGuard;

pub fn test_main() {
    arch::log("Starting kernel specs...\n");

    arch_tests::test_architecture();
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::exceptions::spec::test_exceptions();
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::gic::spec::test_gic();
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::timer::spec::test_timer();
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::interrupts::spec::test_interrupts();
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::vspace::spec::test_vspace();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::gdt::spec::test_gdt();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::exceptions::spec::test_exceptions();
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
    KernelGuard::run(crate::cspace::spec::test_cspace_lookup);
    crate::region::spec::test_region();
    crate::object_type::spec::test_object_type();
    crate::untyped::spec::test_untyped();
    crate::tcb::spec::test_tcb();
    KernelGuard::run(crate::scheduler::spec::test_scheduler);
    KernelGuard::run(crate::kernel::spec::test_kernel_state);
    crate::asid::spec::test_asid();
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::context::spec::test_context_switch();
    KernelGuard::run(crate::syscall_handler::spec::test_syscall_handler);
    crate::invocation::spec::test_invocation();
    KernelGuard::run(crate::fault::spec::test_fault);
    KernelGuard::run(crate::endpoint::spec::test_endpoint);
    KernelGuard::run(crate::notification::spec::test_notification);
    KernelGuard::run(crate::interrupt::spec::test_interrupt);
    #[cfg(target_arch = "x86_64")]
    crate::vspace::spec::test_vspace();
    crate::boot::spec::test_boot();
    crate::initrd::spec::test_initrd();
    crate::elf::spec::test_elf();
    crate::rootserver::spec::test_rootserver();
    integration_tests::test_integration();

    KernelGuard::run(crate::sched_context::spec::test_sched_context);
    KernelGuard::run(crate::reply::specs::test_reply_chains);
    crate::smp::spec::test_smp();
    #[cfg(feature = "fastpath")]
    crate::fastpath::spec::test_fastpath();
    #[cfg(feature = "fpu")]
    crate::fpu::spec::test_fpu();
    #[cfg(feature = "vmx")]
    crate::vcpu::spec::test_vcpu();

    arch::log("All specs passed!\n");
    // Return to `main` so the live rootserver boot path is exercised.
}
