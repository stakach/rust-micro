//! AArch64 EL1 exception-vector installation.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

static EXPECTED_BRK: AtomicBool = AtomicBool::new(false);
static LAST_ESR: AtomicU64 = AtomicU64::new(0);
static EL0_SPEC_STATE: AtomicU8 = AtomicU8::new(0);

core::arch::global_asm!(
    r#"
    .section .text.aarch64_vectors,"ax"
    .balign 2048
    .global aarch64_vector_table
aarch64_vector_table:
    .balign 128
    b aarch64_sync_entry
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_invalid_entry
    .balign 128
    b aarch64_invalid_entry

    .balign 128
    b aarch64_sync_entry
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_invalid_entry
    .balign 128
    b aarch64_invalid_entry

    .balign 128
    b aarch64_sync_entry
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_invalid_entry
    .balign 128
    b aarch64_invalid_entry

    .balign 128
    b aarch64_sync_entry
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_invalid_entry
    .balign 128
    b aarch64_invalid_entry

    .macro save_aarch64_context
    sub sp, sp, #832
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x0, sp_el0
    mrs x1, elr_el1
    stp x0, x1, [sp, #248]
    mrs x0, spsr_el1
    str x0, [sp, #264]
    str x1, [sp, #272]
    mrs x0, tpidr_el0
    mrs x1, tpidrro_el0
    stp x0, x1, [sp, #280]
    mrs x0, fpcr
    mrs x1, fpsr
    stp x0, x1, [sp, #304]
    stp q0,  q1,  [sp, #320]
    stp q2,  q3,  [sp, #352]
    stp q4,  q5,  [sp, #384]
    stp q6,  q7,  [sp, #416]
    stp q8,  q9,  [sp, #448]
    stp q10, q11, [sp, #480]
    stp q12, q13, [sp, #512]
    stp q14, q15, [sp, #544]
    stp q16, q17, [sp, #576]
    stp q18, q19, [sp, #608]
    stp q20, q21, [sp, #640]
    stp q22, q23, [sp, #672]
    stp q24, q25, [sp, #704]
    stp q26, q27, [sp, #736]
    stp q28, q29, [sp, #768]
    stp q30, q31, [sp, #800]
    .endm

    .macro restore_aarch64_context
    ldp q0,  q1,  [sp, #320]
    ldp q2,  q3,  [sp, #352]
    ldp q4,  q5,  [sp, #384]
    ldp q6,  q7,  [sp, #416]
    ldp q8,  q9,  [sp, #448]
    ldp q10, q11, [sp, #480]
    ldp q12, q13, [sp, #512]
    ldp q14, q15, [sp, #544]
    ldp q16, q17, [sp, #576]
    ldp q18, q19, [sp, #608]
    ldp q20, q21, [sp, #640]
    ldp q22, q23, [sp, #672]
    ldp q24, q25, [sp, #704]
    ldp q26, q27, [sp, #736]
    ldp q28, q29, [sp, #768]
    ldp q30, q31, [sp, #800]
    ldp x0, x1, [sp, #304]
    msr fpcr, x0
    msr fpsr, x1
    ldp x0, x1, [sp, #248]
    msr sp_el0, x0
    msr elr_el1, x1
    ldr x0, [sp, #264]
    msr spsr_el1, x0
    ldp x0, x1, [sp, #280]
    msr tpidr_el0, x0
    msr tpidrro_el0, x1
    ldr x30, [sp, #240]
    ldp x28, x29, [sp, #224]
    ldp x26, x27, [sp, #208]
    ldp x24, x25, [sp, #192]
    ldp x22, x23, [sp, #176]
    ldp x20, x21, [sp, #160]
    ldp x18, x19, [sp, #144]
    ldp x16, x17, [sp, #128]
    ldp x14, x15, [sp, #112]
    ldp x12, x13, [sp, #96]
    ldp x10, x11, [sp, #80]
    ldp x8,  x9,  [sp, #64]
    ldp x6,  x7,  [sp, #48]
    ldp x4,  x5,  [sp, #32]
    ldp x2,  x3,  [sp, #16]
    ldp x0,  x1,  [sp, #0]
    add sp, sp, #832
    .endm

aarch64_sync_entry:
    save_aarch64_context
    mov x0, sp
    bl aarch64_sync_dispatch
    restore_aarch64_context
    eret

aarch64_irq_entry:
    save_aarch64_context
    mov x0, sp
    bl aarch64_irq_dispatch
    restore_aarch64_context
    eret

aarch64_invalid_entry:
    save_aarch64_context
    mov x0, sp
    bl aarch64_invalid_dispatch
1:
    wfi
    b 1b
"#
);

extern "C" {
    static aarch64_vector_table: u8;
}

pub fn init_exceptions() {
    let table = core::ptr::addr_of!(aarch64_vector_table) as u64;
    assert_eq!(table & 0x7ff, 0, "VBAR_EL1 must be 2 KiB aligned");
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {table}",
            "isb",
            table = in(reg) table,
            options(nostack, preserves_flags),
        );
    }
}

#[no_mangle]
extern "C" fn aarch64_sync_dispatch(context: *mut crate::arch::UserContext) {
    let esr: u64;
    unsafe {
        core::arch::asm!("mrs {esr}, esr_el1", esr = out(reg) esr, options(nomem, nostack));
    }
    LAST_ESR.store(esr, Ordering::SeqCst);

    if (esr >> 26) == 0x15 {
        handle_el0_spec_svc(esr, context);
        return;
    }

    // EC=0x3c is BRK from AArch64. Only the architecture spec arms this
    // recovery path; arbitrary kernel synchronous exceptions remain fatal.
    if EXPECTED_BRK.swap(false, Ordering::SeqCst) && (esr >> 26) == 0x3c {
        unsafe { (*context).elr_el1 += 4 };
        return;
    }

    fatal_exception("Unexpected AArch64 synchronous exception\n")
}

fn handle_el0_spec_svc(esr: u64, context: *mut crate::arch::UserContext) {
    let immediate = (esr & 0xffff) as u16;
    let state = EL0_SPEC_STATE.load(Ordering::SeqCst);
    let context = unsafe { &mut *context };
    match (state, immediate) {
        (1, 0) => {
            assert_eq!(context.x[0], b'U' as u64);
            assert_eq!(context.x[7] as i64, -12);
            EL0_SPEC_STATE.store(2, Ordering::SeqCst);
        }
        (2, 1) => {
            assert_eq!(context.x[0], b'Z' as u64);
            extern "C" {
                static aarch64_el0_spec_resume: u8;
            }
            context.elr_el1 = core::ptr::addr_of!(aarch64_el0_spec_resume) as u64;
            context.spsr_el1 = 0x3c5;
            EL0_SPEC_STATE.store(3, Ordering::SeqCst);
        }
        _ => fatal_exception("Unexpected AArch64 EL0 SVC\n"),
    }
}

#[no_mangle]
extern "C" fn aarch64_invalid_dispatch() -> ! {
    fatal_exception("Unexpected AArch64 exception vector\n")
}

fn fatal_exception(message: &str) -> ! {
    crate::arch::log(message);
    #[cfg(any(feature = "spec", feature = "extern-rootserver"))]
    crate::arch::qemu_exit(1);
    #[cfg(not(any(feature = "spec", feature = "extern-rootserver")))]
    loop {
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

#[cfg(feature = "spec")]
pub fn begin_el0_svc_spec() {
    assert_eq!(EL0_SPEC_STATE.swap(1, Ordering::SeqCst), 0);
}

#[cfg(feature = "spec")]
pub fn finish_el0_svc_spec() {
    assert_eq!(EL0_SPEC_STATE.swap(0, Ordering::SeqCst), 3);
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_exceptions() {
        arch::log("  aarch64 exception vectors...");
        let installed: u64;
        unsafe {
            core::arch::asm!("mrs {vbar}, vbar_el1", vbar = out(reg) installed);
        }
        assert_eq!(installed, core::ptr::addr_of!(aarch64_vector_table) as u64);
        assert_eq!(installed & 0x7ff, 0);

        LAST_ESR.store(0, Ordering::SeqCst);
        EXPECTED_BRK.store(true, Ordering::SeqCst);
        unsafe {
            core::arch::asm!("brk #0x534", options(nomem, nostack));
        }
        let esr = LAST_ESR.load(Ordering::SeqCst);
        assert_eq!(esr >> 26, 0x3c);
        assert_eq!(esr & 0xffff, 0x534);
        assert!(!EXPECTED_BRK.load(Ordering::SeqCst));
        arch::log(" ok\n");
    }
}
