use crate::arch;

mod abi_layout_tests;
mod arch_tests;
mod structures_tests;

pub fn test_main() {
    arch::log("Starting kernel specs...\n");

    arch_tests::test_architecture();
    structures_tests::test_structures();
    abi_layout_tests::test_abi_layout();
    crate::cap::spec::test_cap_roundtrip();
    crate::cspace::spec::test_cspace_lookup();
    crate::region::spec::test_region();
    crate::object_type::spec::test_object_type();
    crate::untyped::spec::test_untyped();
    crate::tcb::spec::test_tcb();
    crate::scheduler::spec::test_scheduler();

    arch::log("All specs passed!\n");
    arch::qemu_exit(0);
}
