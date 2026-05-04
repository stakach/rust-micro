#[cfg(all(target_arch = "x86_64"))]
pub mod x86_64;
#[cfg(all(target_arch = "aarch64"))]
pub mod aarch64;

pub type CpuId = u32;

pub trait Architecture {
    fn init_serial();
    fn log(msg: &str);
    fn get_cpu_id() -> CpuId;
    fn halt_cpu();
    fn init_gdt();
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
pub use x86_64::{
    serial::init_serial, serial::log,
    get_cpu_id, halt_cpu, init_gdt, init_interrupts, init_exceptions,
    init_syscall_msrs,
    init_gdt_for_cpu, load_idt,
};

#[cfg(all(target_arch = "aarch64"))]
pub use aarch64::{
    serial::init_serial, serial::log,
    get_cpu_id, halt_cpu, init_interrupts, init_exceptions,
};

/// aarch64 doesn't have IA32 MSRs. Stub so portable bootstrap can
/// call this unconditionally.
#[cfg(all(target_arch = "aarch64"))]
pub fn init_syscall_msrs() {}

/// aarch64 stubs for the SMP per-CPU init shape — APIs are x86_64-shaped
/// today; aarch64 SMP bring-up is a separate phase.
#[cfg(all(target_arch = "aarch64"))]
pub fn init_gdt_for_cpu(_cpu_id: CpuId) {}
#[cfg(all(target_arch = "aarch64"))]
pub fn load_idt() {}
