pub mod serial;

#[cfg(feature = "spec")]
pub mod qemu;

pub mod cpu;
pub mod interrupts;
pub mod exceptions;

pub use cpu::{get_cpu_id, halt_cpu};
pub use interrupts::init_interrupts;
pub use exceptions::init_exceptions;
