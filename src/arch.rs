#[cfg(all(target_arch = "aarch64"))]
pub mod aarch64;
#[cfg(all(target_arch = "x86_64"))]
pub mod x86_64;

pub type CpuId = u32;

pub trait Architecture {
    fn init_serial();
    fn log(msg: &str);
    fn get_cpu_id() -> CpuId;
    fn halt_cpu();
    fn init_gdt();
    fn init_interrupts();
    fn init_exceptions();

    #[cfg(any(feature = "spec", feature = "extern-rootserver"))]
    fn qemu_exit(code: u32) -> !;
}

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "spec", feature = "extern-rootserver")
))]
pub use x86_64::qemu::qemu_exit;

#[cfg(all(
    target_arch = "aarch64",
    any(feature = "spec", feature = "extern-rootserver")
))]
pub use aarch64::qemu::qemu_exit;

#[cfg(all(target_arch = "x86_64"))]
pub use x86_64::{
    get_cpu_id, halt_cpu, init_exceptions, init_gdt, init_gdt_for_cpu, init_interrupts,
    init_syscall_msrs, load_idt, serial::init_serial, serial::log,
};

#[cfg(all(target_arch = "aarch64"))]
pub use aarch64::{
    get_cpu_id, halt_cpu, init_exceptions, init_interrupts, serial::init_serial, serial::log,
};

/// Debug helper: log a tag followed by a decimal number + space.
#[allow(dead_code)]
pub fn log_n(tag: &str, n: u32) {
    log(tag);
    let mut b = [0u8; 10];
    let mut i = b.len();
    let mut v = n;
    if v == 0 {
        log("0");
    } else {
        while v > 0 && i > 0 {
            i -= 1;
            b[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        if let Ok(z) = core::str::from_utf8(&b[i..]) {
            log(z);
        }
    }
    log(" ");
}

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
