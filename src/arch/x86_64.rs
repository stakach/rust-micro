pub mod serial;

#[cfg(feature = "spec")]
pub mod qemu;

pub mod acpi;
pub mod context;
pub mod cpu;
pub mod exceptions;
pub mod gdt;
pub mod interrupts;
pub mod lapic;
pub mod msr;
pub mod paging;
pub mod pic;
pub mod pit;
pub mod syscall_entry;
pub mod usermode;
pub mod vspace;

pub use cpu::{get_cpu_id, halt_cpu};
pub use exceptions::init_exceptions;
pub use gdt::{init_gdt, init_gdt_for_cpu};
pub use interrupts::{init_interrupts, load_idt};
pub use syscall_entry::init_syscall_msrs;
