//! Saved EL0 register state.

/// Register order matches seL4's `enum _register` in
/// `include/arch/arm/arch/64/mode/machine/registerset.h`: `x0..x30`,
/// `SP_EL0`, `ELR_EL1`, `SPSR_EL1`, `FaultIP`, `TPIDR_EL0`, and
/// `TPIDRRO_EL0`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UserContext {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub fault_ip: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
}

const _: () = assert!(core::mem::size_of::<UserContext>() == 37 * core::mem::size_of::<u64>());

impl UserContext {
    pub const fn new_zero() -> Self {
        Self {
            x: [0; 31],
            sp_el0: 0,
            elr_el1: 0,
            spsr_el1: 0,
            fault_ip: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
        }
    }

    pub const fn for_entry(entry: u64, sp: u64, arg0: u64) -> Self {
        let mut context = Self::new_zero();
        context.x[0] = arg0;
        context.sp_el0 = sp;
        context.elr_el1 = entry;
        // seL4 PSTATE_USER: mask FIQ and return to EL0t.
        context.spsr_el1 = 1 << 6;
        context
    }
}

core::arch::global_asm!(
    r#"
    .section .text.aarch64_enter_user,"ax"
    .global aarch64_enter_user
aarch64_enter_user:
    mov x30, x0
    ldp x9, x10, [x30, #248]
    msr sp_el0, x9
    msr elr_el1, x10
    ldr x9, [x30, #264]
    msr spsr_el1, x9
    ldp x9, x10, [x30, #280]
    msr tpidr_el0, x9
    msr tpidrro_el0, x10
    ldp x0,  x1,  [x30, #0]
    ldp x2,  x3,  [x30, #16]
    ldp x4,  x5,  [x30, #32]
    ldp x6,  x7,  [x30, #48]
    ldp x8,  x9,  [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldp x18, x19, [x30, #144]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]
    ldr x30, [x30, #240]
    eret
"#
);

extern "C" {
    fn aarch64_enter_user(context: *const UserContext) -> !;
}

pub unsafe fn enter_user(context: *const UserContext) -> ! {
    aarch64_enter_user(context)
}

const EXCEPTION_FPU_OFFSET: usize = 304;

pub unsafe fn save_exception_fpu(
    context: *const UserContext,
    destination: &mut crate::tcb::Aarch64FpuState,
) {
    core::ptr::copy_nonoverlapping(
        (context as *const u8).add(EXCEPTION_FPU_OFFSET) as *const crate::tcb::Aarch64FpuState,
        destination,
        1,
    );
}

pub unsafe fn restore_exception_fpu(
    context: *mut UserContext,
    source: &crate::tcb::Aarch64FpuState,
) {
    core::ptr::copy_nonoverlapping(
        source,
        (context as *mut u8).add(EXCEPTION_FPU_OFFSET) as *mut crate::tcb::Aarch64FpuState,
        1,
    );
}

pub fn set_user_fpu_access(disabled: bool) {
    unsafe {
        let mut cpacr: u64;
        core::arch::asm!("mrs {value}, cpacr_el1", value = out(reg) cpacr, options(nomem, nostack));
        cpacr &= !(3 << 20);
        // FPEN=01 traps EL0 while retaining EL1 access; FPEN=11 enables both.
        cpacr |= (if disabled { 1 } else { 3 }) << 20;
        core::arch::asm!("msr cpacr_el1, {value}", value = in(reg) cpacr, options(nomem, nostack));
    }
}
