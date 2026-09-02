pub mod serial;
pub mod syscall_entry;

#[cfg(any(feature = "spec", feature = "extern-rootserver"))]
pub mod qemu;

pub mod context;
pub mod cpu;
pub mod debug;
pub mod exceptions;
pub mod gic;
pub mod interrupts;
pub mod timer;
pub mod vspace;

pub use context::UserContext;
pub use cpu::{get_cpu_id, halt_cpu};
pub use debug::DebugState;
pub use exceptions::init_exceptions;
pub use interrupts::init_interrupts;

/// aarch64 has no GDT — segments aren't a thing. The arch trait
/// keeps the symbol so portable bootstrap code can call
/// `arch::init_gdt()` unconditionally; this is a no-op here.
pub fn init_gdt() {}
