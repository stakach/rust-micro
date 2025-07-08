#[cfg(all(target_arch = "x86_64"))]
mod x86_64;
#[cfg(all(target_arch = "aarch64"))]
mod aarch64;

pub type CpuId = u32;

pub trait Architecture {
    fn init_serial();
    fn log(msg: &str);
    fn get_cpu_id() -> CpuId;
    fn halt_cpu();
    fn init_interrupts();
    fn init_exceptions();
    
    #[cfg(feature = "spec")]
    fn qemu_exit(code: u32) -> !;
}

#[cfg(all(target_arch = "x86_64", feature = "spec"))]
pub use x86_64::qemu::qemu_exit;

#[cfg(all(target_arch = "aarch64", feature = "spec"))]
pub use aarch64::qemu::qemu_exit;

#[cfg(all(target_arch = "x86_64"))]
pub use x86_64::{serial::init_serial, serial::log, get_cpu_id, halt_cpu, init_interrupts, init_exceptions};

#[cfg(all(target_arch = "aarch64"))]
pub use aarch64::{serial::init_serial, serial::log, get_cpu_id, halt_cpu, init_interrupts, init_exceptions};
