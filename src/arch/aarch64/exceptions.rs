//! AArch64 EL1 exception-vector installation.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static EXPECTED_BRK: AtomicBool = AtomicBool::new(false);
static LAST_ESR: AtomicU64 = AtomicU64::new(0);

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
    sub sp, sp, #784
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
    mrs x0, fpcr
    mrs x1, fpsr
    stp x0, x1, [sp, #256]
    stp q0,  q1,  [sp, #272]
    stp q2,  q3,  [sp, #304]
    stp q4,  q5,  [sp, #336]
    stp q6,  q7,  [sp, #368]
    stp q8,  q9,  [sp, #400]
    stp q10, q11, [sp, #432]
    stp q12, q13, [sp, #464]
    stp q14, q15, [sp, #496]
    stp q16, q17, [sp, #528]
    stp q18, q19, [sp, #560]
    stp q20, q21, [sp, #592]
    stp q22, q23, [sp, #624]
    stp q24, q25, [sp, #656]
    stp q26, q27, [sp, #688]
    stp q28, q29, [sp, #720]
    stp q30, q31, [sp, #752]
    .endm

    .macro restore_aarch64_context
    ldp q0,  q1,  [sp, #272]
    ldp q2,  q3,  [sp, #304]
    ldp q4,  q5,  [sp, #336]
    ldp q6,  q7,  [sp, #368]
    ldp q8,  q9,  [sp, #400]
    ldp q10, q11, [sp, #432]
    ldp q12, q13, [sp, #464]
    ldp q14, q15, [sp, #496]
    ldp q16, q17, [sp, #528]
    ldp q18, q19, [sp, #560]
    ldp q20, q21, [sp, #592]
    ldp q22, q23, [sp, #624]
    ldp q24, q25, [sp, #656]
    ldp q26, q27, [sp, #688]
    ldp q28, q29, [sp, #720]
    ldp q30, q31, [sp, #752]
    ldp x0, x1, [sp, #256]
    msr fpcr, x0
    msr fpsr, x1
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
    add sp, sp, #784
    .endm

aarch64_sync_entry:
    save_aarch64_context
    bl aarch64_sync_dispatch
    restore_aarch64_context
    eret

aarch64_irq_entry:
    save_aarch64_context
    bl aarch64_irq_dispatch
    restore_aarch64_context
    eret

aarch64_invalid_entry:
    save_aarch64_context
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
extern "C" fn aarch64_sync_dispatch() {
    let esr: u64;
    unsafe {
        core::arch::asm!("mrs {esr}, esr_el1", esr = out(reg) esr, options(nomem, nostack));
    }
    LAST_ESR.store(esr, Ordering::SeqCst);

    // EC=0x3c is BRK from AArch64. Only the architecture spec arms this
    // recovery path; arbitrary kernel synchronous exceptions remain fatal.
    if EXPECTED_BRK.swap(false, Ordering::SeqCst) && (esr >> 26) == 0x3c {
        unsafe {
            core::arch::asm!(
                "mrs x9, elr_el1",
                "add x9, x9, #4",
                "msr elr_el1, x9",
                out("x9") _,
                options(nomem, nostack),
            );
        }
        return;
    }

    fatal_exception("Unexpected AArch64 synchronous exception\n")
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
