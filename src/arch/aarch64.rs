pub mod serial;

#[cfg(any(feature = "spec", feature = "extern-rootserver"))]
pub mod qemu;

pub mod cpu;
pub mod exceptions;
pub mod interrupts;

pub use cpu::{get_cpu_id, halt_cpu};
pub use exceptions::init_exceptions;
pub use interrupts::init_interrupts;

/// aarch64 has no GDT — segments aren't a thing. The arch trait
/// keeps the symbol so portable bootstrap code can call
/// `arch::init_gdt()` unconditionally; this is a no-op here.
pub fn init_gdt() {}
