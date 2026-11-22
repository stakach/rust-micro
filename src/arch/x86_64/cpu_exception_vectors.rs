//! x86-64 CPU exception vectors: their names, their hardware frame shape, and which of them a
//! user thread's fault handler receives.
//!
//! A user-mode (CPL3) fault on a delivered vector becomes a `UserException { number: vector,
//! code: error_code }` fault for the thread's fault handler, as upstream seL4
//! `handleUserLevelFault` does; the handler's personality decides what the program sees (NT
//! raises `STATUS_INTEGER_DIVIDE_BY_ZERO` for #DE, for example). The same vectors in kernel
//! mode, and the aborts and interrupt-like vectors in any mode, halt the system.
//!
//! #DB and #BP (debug faults), #NM (the FPU gate), #GP (the DebugService decode) and #PF
//! (VM faults) reach the fault handler through their own entries.

pub const DIVIDE_ERROR: u64 = 0;
pub const DEBUG: u64 = 1;
pub const NMI: u64 = 2;
pub const BREAKPOINT: u64 = 3;
pub const OVERFLOW: u64 = 4;
pub const BOUND_RANGE: u64 = 5;
pub const INVALID_OPCODE: u64 = 6;
pub const DEVICE_NOT_AVAILABLE: u64 = 7;
pub const DOUBLE_FAULT: u64 = 8;
pub const INVALID_TSS: u64 = 10;
pub const SEGMENT_NOT_PRESENT: u64 = 11;
pub const STACK_SEGMENT: u64 = 12;
pub const GENERAL_PROTECTION: u64 = 13;
pub const PAGE_FAULT: u64 = 14;
pub const X87_FLOATING_POINT: u64 = 16;
pub const ALIGNMENT_CHECK: u64 = 17;
pub const MACHINE_CHECK: u64 = 18;
pub const SIMD_FLOATING_POINT: u64 = 19;
pub const VIRTUALIZATION: u64 = 20;
pub const CONTROL_PROTECTION: u64 = 21;

/// Whether a user-mode fault on `vector` is delivered as a `UserException` by the shared CPU
/// exception entry, rather than halting the system.
pub const fn delivers_user_exception(vector: u64) -> bool {
    matches!(
        vector,
        DIVIDE_ERROR
            | OVERFLOW
            | BOUND_RANGE
            | INVALID_OPCODE
            | SEGMENT_NOT_PRESENT
            | STACK_SEGMENT
            | X87_FLOATING_POINT
            | ALIGNMENT_CHECK
            | SIMD_FLOATING_POINT
    )
}

/// Whether the processor pushes an error code below the interrupt frame for `vector`.
pub const fn pushes_error_code(vector: u64) -> bool {
    matches!(
        vector,
        DOUBLE_FAULT
            | INVALID_TSS
            | SEGMENT_NOT_PRESENT
            | STACK_SEGMENT
            | GENERAL_PROTECTION
            | PAGE_FAULT
            | ALIGNMENT_CHECK
            | CONTROL_PROTECTION
    )
}

/// The architectural name of `vector`, for diagnostics.
pub const fn name(vector: u64) -> &'static str {
    match vector {
        DIVIDE_ERROR => "#DE divide error",
        DEBUG => "#DB debug",
        NMI => "NMI",
        BREAKPOINT => "#BP breakpoint",
        OVERFLOW => "#OF overflow",
        BOUND_RANGE => "#BR bound range exceeded",
        INVALID_OPCODE => "#UD invalid opcode",
        DEVICE_NOT_AVAILABLE => "#NM device not available",
        DOUBLE_FAULT => "#DF double fault",
        INVALID_TSS => "#TS invalid TSS",
        SEGMENT_NOT_PRESENT => "#NP segment not present",
        STACK_SEGMENT => "#SS stack segment fault",
        GENERAL_PROTECTION => "#GP general protection",
        PAGE_FAULT => "#PF page fault",
        X87_FLOATING_POINT => "#MF x87 floating point",
        ALIGNMENT_CHECK => "#AC alignment check",
        MACHINE_CHECK => "#MC machine check",
        SIMD_FLOATING_POINT => "#XM SIMD floating point",
        VIRTUALIZATION => "#VE virtualization",
        CONTROL_PROTECTION => "#CP control protection",
        _ => "reserved exception",
    }
}
