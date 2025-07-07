use crate::arch;

pub fn test_main() {
  arch::log("Specs passed!\n");
  arch::qemu_exit(0);
}
