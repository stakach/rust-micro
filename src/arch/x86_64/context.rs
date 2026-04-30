//! Phase 14b — x86_64 context switch.
//!
//! `switch_context(prev, next)` saves the System-V callee-saved
//! registers (rbx/rbp/r12-r15) onto the current kernel stack, parks
//! the resulting rsp into `prev->ksp`, swaps rsp from `next->ksp`,
//! conditionally swaps CR3 if `next->cr3` differs from current,
//! and returns. Because we restore the same callee-saved set the
//! prior `switch_context` saved, the `ret` resumes whatever code
//! was running in the new thread when *it* was last switched out.
//!
//! First-time entry to a thread is handled by `prime_stack` —
//! it lays down a "fake" save frame on the new thread's kernel
//! stack so the first switch_context returns into a Rust trampoline
//! that calls the thread's entry function.

use core::arch::asm;

use crate::tcb::CpuContext;

/// Save callee-saved registers onto the current stack, swap rsp
/// to the next thread's saved kernel stack, restore its callee-
/// saved registers, and return into wherever it last left off.
/// `prev` and `next` are pointers into the respective Tcb's
/// `cpu_context` fields.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn switch_context(prev: *mut CpuContext, next: *const CpuContext) {
    core::arch::naked_asm!(
        // System-V callee-saved set on x86_64: rbx, rbp, r12, r13,
        // r14, r15. Save them onto the current kernel stack.
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Save the current rsp into prev->ksp (offset 0).
        "mov [rdi + 0], rsp",

        // Load the next thread's ksp.
        "mov rsp, [rsi + 0]",

        // Conditionally swap CR3. cr3 = 0 means "keep current".
        "mov rax, [rsi + 8]",
        "test rax, rax",
        "jz 2f",
        "mov rcx, cr3",
        "cmp rax, rcx",
        "je 2f",
        "mov cr3, rax",
        "2:",

        // Restore callee-saved registers from the new thread's stack.
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
    );
}

/// Prime a fresh kernel stack so the first `switch_context` to it
/// returns into `entry(arg)`.
///
/// Layout we lay down (top-of-stack → ↓ growing toward base):
///
///   [stack top]
///   ...
///   <-- rsp will land here after we set ksp
///   r15 placeholder         (popped first)
///   r14
///   r13
///   r12
///   rbp
///   rbx
///   return-address          ← ret pops this; we make it `trampoline`
///
/// The trampoline reads `entry` and `arg` from a fixed offset
/// further down the stack and calls `entry(arg)`. That keeps the
/// switch_context ABI simple (no extra register allowance).
pub unsafe fn prime_stack(
    ctx: &mut CpuContext,
    stack_top: u64,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
) {
    let mut sp = stack_top & !0xFu64; // 16-byte align
    // Push the trampoline arguments first (further from top of stack).
    sp -= 16;
    let args_ptr = sp as *mut u64;
    args_ptr.write(entry as u64);
    args_ptr.add(1).write(arg);

    // Push the return address (= trampoline) and zeroed callee-
    // saved set. We push 6 callees + 1 return address = 7 words.
    sp -= 8 * 7;
    let frame = sp as *mut u64;
    frame.add(0).write(0); // r15
    frame.add(1).write(0); // r14
    frame.add(2).write(0); // r13
    frame.add(3).write(0); // r12
    frame.add(4).write(0); // rbp
    frame.add(5).write(args_ptr as u64); // rbx — reused as args ptr
    frame.add(6).write(thread_trampoline as u64); // return address

    ctx.ksp = sp;
}

/// Trampoline reached on first switch into a primed thread. Reads
/// `entry` and `arg` from rbx (which prime_stack stashed there)
/// and calls them. The entry function is `extern "C" fn(u64) -> !`,
/// so it never returns.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn thread_trampoline() {
    core::arch::naked_asm!(
        // rbx contains the args pointer set up by prime_stack.
        "mov rdi, [rbx + 8]",     // arg
        "mov rax, [rbx]",         // entry function
        "jmp rax",
    );
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use core::sync::atomic::{AtomicU64, Ordering};

    pub fn test_context_switch() {
        arch::log("Running context-switch tests...\n");
        switch_to_primed_thread_runs_entry();
        switch_back_resumes_caller();
        arch::log("Context-switch tests completed\n");
    }

    /// Counter the secondary thread bumps so the primary spec can
    /// verify it ran.
    static SECONDARY_RAN: AtomicU64 = AtomicU64::new(0);

    /// Per-secondary-thread context + 16 KiB kernel stack.
    #[repr(C, align(16))]
    struct StackPage([u8; 16384]);
    static mut SECONDARY_STACK: StackPage = StackPage([0; 16384]);
    static mut SECONDARY_CTX: CpuContext = CpuContext { ksp: 0, cr3: 0 };
    static mut PRIMARY_CTX: CpuContext = CpuContext { ksp: 0, cr3: 0 };

    extern "C" fn secondary_entry(arg: u64) -> ! {
        SECONDARY_RAN.fetch_add(arg, Ordering::Relaxed);
        // Yield back to the primary.
        unsafe {
            switch_context(
                &raw mut SECONDARY_CTX,
                &raw const PRIMARY_CTX,
            );
        }
        // Should never resume.
        panic!("secondary thread resumed after switch_context back");
    }

    #[inline(never)]
    fn switch_to_primed_thread_runs_entry() {
        unsafe {
            let stack_top = (&raw const SECONDARY_STACK) as u64
                + core::mem::size_of::<StackPage>() as u64;
            prime_stack(&mut SECONDARY_CTX, stack_top, secondary_entry, 7);

            // First switch — primary saves its state into PRIMARY_CTX,
            // then jumps into the secondary's primed stack and runs
            // secondary_entry(7).
            switch_context(
                &raw mut PRIMARY_CTX,
                &raw const SECONDARY_CTX,
            );
        }
        // After the secondary yields back, control returns here.
        let n = SECONDARY_RAN.load(Ordering::Relaxed);
        assert_eq!(n, 7, "secondary should have bumped the counter by 7");
        arch::log("  ✓ switch_context dispatches into a primed thread\n");
    }

    #[inline(never)]
    fn switch_back_resumes_caller() {
        // The previous test already exercised both directions; the
        // counter check confirmed the secondary's bump *and* its
        // return into the primary spec frame. This second test just
        // re-uses the same context — re-prime the secondary stack
        // and verify the round-trip again with a different arg.
        unsafe {
            let stack_top = (&raw const SECONDARY_STACK) as u64
                + core::mem::size_of::<StackPage>() as u64;
            prime_stack(&mut SECONDARY_CTX, stack_top, secondary_entry, 100);
            switch_context(
                &raw mut PRIMARY_CTX,
                &raw const SECONDARY_CTX,
            );
        }
        let n = SECONDARY_RAN.load(Ordering::Relaxed);
        assert_eq!(n, 107, "second round-trip should accumulate (+100)");
        arch::log("  ✓ switch_context round-trips a second time\n");
    }
}
