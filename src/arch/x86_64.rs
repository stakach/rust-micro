pub mod serial;

#[cfg(feature = "spec")]
pub mod qemu;

pub mod cpu;
pub mod exceptions;
pub mod gdt;
pub mod interrupts;

pub use cpu::{get_cpu_id, halt_cpu};
pub use exceptions::init_exceptions;
pub use gdt::init_gdt;
pub use interrupts::init_interrupts;
