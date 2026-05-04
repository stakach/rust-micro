pub mod serial;

#[cfg(feature = "spec")]
pub mod qemu;

pub mod cpu;
pub mod interrupts;
pub mod exceptions;

pub use cpu::{get_cpu_id, halt_cpu};
pub use interrupts::init_interrupts;
pub use exceptions::init_exceptions;

/// aarch64 has no GDT — segments aren't a thing. The arch trait
/// keeps the symbol so portable bootstrap code can call
/// `arch::init_gdt()` unconditionally; this is a no-op here.
pub fn init_gdt() {}
