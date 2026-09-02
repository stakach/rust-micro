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

#[cfg(target_arch = "x86_64")]
pub use x86_64::{debug::DebugState, syscall_entry::UserContext};
#[cfg(all(target_arch = "x86_64"))]
pub use x86_64::{
    get_cpu_id, halt_cpu, init_exceptions, init_gdt, init_gdt_for_cpu, init_interrupts,
    init_syscall_msrs, load_idt, serial::init_serial, serial::log,
};

#[cfg(all(target_arch = "aarch64"))]
pub use aarch64::{
    get_cpu_id, halt_cpu, init_exceptions, init_gdt, init_interrupts, serial::init_serial,
    serial::log, DebugState, UserContext,
};

/// Translate a physical address into the address used by kernel code.
///
/// Both supported boot paths begin with RAM identity-mapped. x86_64 later
/// installs a kernel-half linear map; AArch64 will replace its identity
/// implementation when the EL1 page-table milestone lands.
#[inline(always)]
pub fn phys_to_virt(paddr: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::paging::phys_to_lin(paddr)
    }
    #[cfg(target_arch = "aarch64")]
    {
        paddr
    }
}

/// Read the send destination used by seL4's combined send/receive ABI.
#[inline]
pub fn composite_send_destination(context: &UserContext, wait_variant: bool) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if wait_variant {
            context.r12
        } else {
            context.r13
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // seL4 registerset.h: replyRegister = X6 and
        // nbsendRecvDest = X8.
        context.x[if wait_variant { 6 } else { 8 }]
    }
}

/// Populate the seL4 IPC syscall-return registers.
#[inline]
pub fn set_ipc_return(context: &mut UserContext, badge: u64, info: u64, msg: &[u64]) {
    #[cfg(target_arch = "x86_64")]
    {
        context.rdi = badge;
        context.rsi = info;
        if let Some(value) = msg.first() {
            context.r10 = *value;
        }
        if let Some(value) = msg.get(1) {
            context.r8 = *value;
        }
        if let Some(value) = msg.get(2) {
            context.r9 = *value;
        }
        if let Some(value) = msg.get(3) {
            context.r15 = *value;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // seL4 aarch64 syscalls.h: badge/cap = X0, info = X1,
        // and the four fast message registers = X2..X5.
        context.x[0] = badge;
        context.x[1] = info;
        for (register, value) in context.x[2..6].iter_mut().zip(msg.iter()) {
            *register = *value;
        }
    }
}

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
