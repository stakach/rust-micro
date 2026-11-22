#[path = "../src/arch/x86_64/cpu_exception_vectors.rs"]
mod cpu_exception_vectors;

use cpu_exception_vectors::*;

#[test]
fn user_mode_program_errors_reach_the_fault_handler() {
    // KVM boot 44981790454: a conhost `div` by zero halted the whole system. Every
    // program-detectable fault the shared entry owns is a UserException for the thread.
    for vector in [
        DIVIDE_ERROR,
        OVERFLOW,
        BOUND_RANGE,
        INVALID_OPCODE,
        SEGMENT_NOT_PRESENT,
        STACK_SEGMENT,
        X87_FLOATING_POINT,
        ALIGNMENT_CHECK,
        SIMD_FLOATING_POINT,
    ] {
        assert!(delivers_user_exception(vector), "{}", name(vector));
    }
}

#[test]
fn aborts_and_dedicated_entries_are_not_shared_user_exceptions() {
    // NMI, #DF, #TS, #MC and #VE stay fatal. #DB/#BP (debug faults), #NM (FPU gate),
    // #GP (DebugService decode) and #PF (VM faults) are delivered by their own entries.
    for vector in [
        DEBUG,
        NMI,
        BREAKPOINT,
        DEVICE_NOT_AVAILABLE,
        DOUBLE_FAULT,
        INVALID_TSS,
        GENERAL_PROTECTION,
        PAGE_FAULT,
        MACHINE_CHECK,
        VIRTUALIZATION,
        CONTROL_PROTECTION,
        9,
        15,
        255,
    ] {
        assert!(!delivers_user_exception(vector), "{}", name(vector));
    }
}

#[test]
fn error_code_frames_match_the_architecture() {
    let with_code: Vec<u64> = (0..32).filter(|&vector| pushes_error_code(vector)).collect();
    assert_eq!(with_code, [8, 10, 11, 12, 13, 14, 17, 21]);
}

#[test]
fn diagnostics_name_the_vector() {
    assert_eq!(name(DIVIDE_ERROR), "#DE divide error");
    assert_eq!(name(SIMD_FLOATING_POINT), "#XM SIMD floating point");
    assert_eq!(name(31), "reserved exception");
    let named: Vec<&str> = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21]
        .into_iter()
        .map(name)
        .collect();
    for (index, label) in named.iter().enumerate() {
        assert!(!named[..index].contains(label), "duplicate label {label}");
    }
}
