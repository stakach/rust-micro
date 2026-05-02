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
    TestCase { name: "tcb_configure",        body: tests::tcb_configure },
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

    /// Phase 34b — `seL4_TCB_Configure` should accept the same
    /// fault_ep / cspace / vspace fields as the per-field
    /// invocations in one shot, plus the priority. The TCB we
    /// retyped in `untyped_retype_tcb` (slot 12) is reused here.
    pub(super) fn tcb_configure() -> TestResult {
        // a2 = fault_ep, a3 = cspace, a4 = vspace, a5 = prio.
        let target = FIRST_EMPTY_SLOT;
        let prio = 50u64;
        let msg_info = LBL_TCB_CONFIGURE << 12;
        let r = unsafe {
            syscall5(
                SYS_SEND, target, msg_info,
                /* fault_ep */ 0,
                /* cspace */ CAP_INIT_THREAD_CNODE,
                /* vspace */ CAP_INIT_THREAD_VSPACE,
            )
        };
        if r != 0 { return Err("Configure(stage 1) failed"); }
        // The Configure ABI also wants `priority` in args.a5,
        // which `syscall5` doesn't expose (only 4 args after the
        // cap). Issue a 6-arg variant via inline asm.
        let r = unsafe { syscall_configure_with_prio(target, msg_info,
            /* fault_ep */ 0,
            CAP_INIT_THREAD_CNODE,
            CAP_INIT_THREAD_VSPACE,
            prio) };
        if r != 0 { return Err("Configure(stage 2) failed"); }
        Ok(())
    }
}

const LBL_TCB_CONFIGURE: u64 = 5;

/// 6-register SYSCALL — like `syscall5` but exposes the sixth arg
/// (r9 / `args.a5`). Used by tests that need to set the priority
/// field of `TCB::Configure`, which lives at a5.
#[inline(always)]
unsafe fn syscall_configure_with_prio(
    target: u64, msg_info: u64,
    fault_ep: u64, cspace: u64, vspace: u64, prio: u64,
) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        in("rax") SYS_SEND as u64,
        in("rdi") target,
        in("rsi") msg_info,
        in("rdx") fault_ep,
        in("r10") cspace,
        in("r8")  vspace,
        in("r9")  prio,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}
