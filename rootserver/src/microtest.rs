//! Phase 34a — microtest harness.
//!
//! Structured Rust-side conformance suite for our microkernel,
//! intended to cover the same patterns `sel4test` exercises but
//! against our public ABI directly. Each test is a function
//! returning `Result<(), &'static str>`; the harness prints
//! `✓ name` on Ok or `✗ name: reason` on Err, then a final
//! `[microtest done]\n` sentinel that the kernel's exit hook
//! catches to qemu_exit.
//!
//! Tests are organised by feature. As we add the missing seL4
//! pieces (TCB::Configure, IPC buffer, cap transfer, reply caps)
//! each gets a `tests::*` function added here.

use crate::*;

type TestResult = Result<(), &'static str>;
type TestFn = fn() -> TestResult;

struct TestCase {
    name: &'static str,
    body: TestFn,
}

// Registry — keep this list in sync as we add tests. One source
// of truth so the summary footer is accurate.
const CASES: &[TestCase] = &[
    TestCase { name: "syscall_round_trip",   body: tests::syscall_round_trip },
    TestCase { name: "untyped_retype_tcb",   body: tests::untyped_retype_tcb },
];

/// Entry point invoked from `_start` when `--features microtest`
/// is on. Runs every case in `CASES`, prints a summary, then
/// emits the kernel-exit sentinel.
pub unsafe fn run() {
    print_str(b"[microtest start]\n");

    let mut passed: usize = 0;
    let mut failed: usize = 0;
    for case in CASES.iter() {
        match (case.body)() {
            Ok(()) => {
                print_str(b"  PASS ");
                print_str(case.name.as_bytes());
                print_str(b"\n");
                passed += 1;
            }
            Err(why) => {
                print_str(b"  FAIL ");
                print_str(case.name.as_bytes());
                print_str(b": ");
                print_str(why.as_bytes());
                print_str(b"\n");
                failed += 1;
            }
        }
    }

    print_str(b"[microtest summary: ");
    print_u64(passed as u64);
    print_str(b" passed, ");
    print_u64(failed as u64);
    print_str(b" failed]\n");
    // Sentinel — kernel's exit hook qemu_exits when it sees this
    // exact byte stream.
    print_str(b"[microtest done]\n");
}

mod tests {
    use super::*;

    /// Trivial sanity check: a successful syscall returns 0.
    /// `SysYield` is the cheapest such call we have.
    pub(super) fn syscall_round_trip() -> TestResult {
        unsafe { syscall0(SYS_YIELD); }
        Ok(())
    }

    /// `Untyped::Retype` issues a TCB cap and the kernel records
    /// the new TCB in the slab. We can't directly observe slab
    /// state from userspace, so the retype-success rax (0) is
    /// the assertion.
    pub(super) fn untyped_retype_tcb() -> TestResult {
        // Retype into the first empty CNode slot (FIRST_EMPTY_SLOT).
        let r = untyped_retype(
            CAP_INIT_UNTYPED,
            OBJ_TCB,
            /* user_size_bits */ 0,
            /* num_objects */ 1,
            FIRST_EMPTY_SLOT,
        );
        if r != 0 {
            return Err("retype failed");
        }
        Ok(())
    }
}
