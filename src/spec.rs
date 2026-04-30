use crate::arch;

mod abi_layout_tests;
mod arch_tests;
mod structures_tests;

pub fn test_main() {
    arch::log("Starting kernel specs...\n");

    arch_tests::test_architecture();
    structures_tests::test_structures();
    abi_layout_tests::test_abi_layout();

    arch::log("All specs passed!\n");
    arch::qemu_exit(0);
}
