use crate::arch;

mod arch_tests;

pub fn test_main() {
    arch::log("Starting kernel specs...\n");
    
    arch_tests::test_architecture();
    
    arch::log("All specs passed!\n");
    arch::qemu_exit(0);
}
