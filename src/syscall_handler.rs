//! Syscall dispatch. This is the kernel's `handleSyscall` from
//! seL4/src/api/syscall.c, distilled down to the parts we can run
//! without an actual user thread on the CPU.
//!
//! In a fully-wired kernel, `handle_syscall` is called from the
//! arch-specific SYSCALL trap entry stub. The stub saves the user
//! register state into the current TCB's `tcbContext`, then invokes
//! us with the syscall number from `%rax` and the user args from
//! `%rdi..%r9`. Phase 5 implements only the dispatcher and one
//! representative syscall (`SysDebugPutChar`); the actual
//! SYSCALL/SYSRET wiring lands with usermode in a later phase.
//!
//! Why surface a `DebugSink` trait rather than calling `arch::log`
//! directly? It lets specs (which run before any usermode exists)
//! capture the byte stream into a buffer for assertion. The
//! production path simply implements the trait around the existing
//! serial driver.

use crate::error::{FaultKind, KException, KResult, SyscallError};
use crate::syscalls::Syscall;
use crate::types::{seL4_Error, seL4_Word as Word};

/// The six register-passed arguments userspace can supply on
/// SYSCALL entry. Mirrors the x86_64 calling convention in seL4's
/// `c_traps.c` (`%rdi..%r9`).
#[derive(Copy, Clone, Debug, Default)]
pub struct SyscallArgs {
    pub a0: Word,
    pub a1: Word,
    pub a2: Word,
    pub a3: Word,
    pub a4: Word,
    pub a5: Word,
}

impl SyscallArgs {
    pub const fn new(a0: Word) -> Self {
        Self { a0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }
    }
}

/// Sink for kernel debug bytes. The kernel implements this around
/// `arch::log`; specs implement it around an in-memory buffer so they
/// can assert the exact byte sequence emitted by `SysDebugPutChar`.
pub trait DebugSink {
    fn put_byte(&mut self, byte: u8);
}

/// Dispatcher. Mirrors `handleSyscall` in seL4 (non-MCS variant):
/// IPC syscalls route through the relevant invocation path; the
/// debug syscalls land in `handle_unknown_syscall`. Anything we
/// don't yet support returns `seL4_IllegalOperation` rather than
/// panicking.
pub fn handle_syscall(
    syscall: Syscall,
    args: &SyscallArgs,
    sink: &mut dyn DebugSink,
) -> KResult<()> {
    match syscall {
        Syscall::SysCall
        | Syscall::SysReplyRecv
        | Syscall::SysSend
        | Syscall::SysNBSend
        | Syscall::SysRecv
        | Syscall::SysReply
        | Syscall::SysNBRecv => {
            // These all need a current thread, an IPC buffer, and a
            // CSpace lookup against the thread's CTable cap — none of
            // which are wired up yet. Return InvalidCapability so a
            // caller in this phase knows the path is recognised but
            // not yet operational.
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )))
        }
        Syscall::SysYield => {
            // No-op without a real scheduler tick; the production
            // version reschedules and rests. We surface success
            // because there's nothing to fail on.
            Ok(())
        }
        Syscall::SysDebugPutChar | Syscall::SysDebugDumpScheduler => {
            // Debug syscalls reach userspace via the fault path
            // (handleUnknownSyscall) in seL4. Forward to the same
            // helper here so the dispatch tree mirrors C.
            let n = syscall as i32 as i64;
            handle_unknown_syscall(n, args, sink)
        }
    }
}

/// Mirrors `handleUnknownSyscall(word_t w)` in seL4. The "unknown"
/// path covers the debug syscalls and any out-of-range number.
pub fn handle_unknown_syscall(
    number: i64,
    args: &SyscallArgs,
    sink: &mut dyn DebugSink,
) -> KResult<()> {
    // Match the syscall number first so the sink receives bytes only
    // for syscalls that should produce output.
    let s = match Syscall::from_i32(number as i32) {
        Some(s) => s,
        None => {
            // Anything outside the known range becomes a
            // `seL4_Fault_UnknownSyscall` — userspace's fault handler
            // gets to decide what to do.
            return Err(KException::Fault(FaultKind::UnknownSyscall { number }));
        }
    };
    match s {
        Syscall::SysDebugPutChar => {
            sink.put_byte(args.a0 as u8);
            Ok(())
        }
        Syscall::SysDebugDumpScheduler => {
            // Stub for now. The full version walks every TCB and
            // logs scheduler state; we'll wire it once the boot
            // sequence holds a Scheduler in static memory.
            for b in b"<scheduler dump unimplemented>\n" {
                sink.put_byte(*b);
            }
            Ok(())
        }
        // IPC syscalls don't go through this entry point in the C
        // kernel; if we land here with one, treat it as an unknown
        // syscall fault.
        _ => Err(KException::Fault(FaultKind::UnknownSyscall { number })),
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    /// In-memory sink that captures every byte emitted by a syscall
    /// for spec assertion.
    struct BufferSink {
        buf: [u8; 64],
        len: usize,
    }
    impl BufferSink {
        fn new() -> Self { Self { buf: [0; 64], len: 0 } }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<non-utf8>")
        }
    }
    impl DebugSink for BufferSink {
        fn put_byte(&mut self, b: u8) {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }

    pub fn test_syscall_handler() {
        arch::log("Running syscall dispatcher tests...\n");
        debug_putchar_emits_byte();
        unknown_syscall_becomes_fault();
        ipc_syscalls_return_invalid_cap_in_phase5();
        sys_yield_succeeds();
        debug_dump_scheduler_writes_placeholder();
        arch::log("Syscall dispatcher tests completed\n");
    }

    fn debug_putchar_emits_byte() {
        let mut sink = BufferSink::new();
        let args = SyscallArgs::new(b'X' as Word);
        handle_syscall(Syscall::SysDebugPutChar, &args, &mut sink).expect("ok");
        assert_eq!(sink.as_str(), "X");
        arch::log("  ✓ SysDebugPutChar emits the requested byte\n");
    }

    fn unknown_syscall_becomes_fault() {
        let mut sink = BufferSink::new();
        // -42 is well outside the legal Syscall range.
        let res = handle_unknown_syscall(-42, &SyscallArgs::default(), &mut sink);
        match res {
            Err(KException::Fault(FaultKind::UnknownSyscall { number: -42 })) => {}
            other => panic!("expected UnknownSyscall fault, got {:?}", other),
        }
        // No bytes written for an unknown syscall.
        assert_eq!(sink.len, 0);
        arch::log("  ✓ unknown syscall numbers raise an UnknownSyscall fault\n");
    }

    fn ipc_syscalls_return_invalid_cap_in_phase5() {
        let mut sink = BufferSink::new();
        for s in &[
            Syscall::SysCall,
            Syscall::SysSend,
            Syscall::SysNBSend,
            Syscall::SysRecv,
            Syscall::SysReply,
            Syscall::SysReplyRecv,
            Syscall::SysNBRecv,
        ] {
            let res = handle_syscall(*s, &SyscallArgs::default(), &mut sink);
            match res {
                Err(KException::SyscallError(SyscallError {
                    code: seL4_Error::seL4_InvalidCapability,
                })) => {}
                other => panic!("expected InvalidCapability for {:?}, got {:?}", s, other),
            }
        }
        arch::log("  ✓ IPC syscalls report InvalidCapability until wired up\n");
    }

    fn sys_yield_succeeds() {
        let mut sink = BufferSink::new();
        handle_syscall(Syscall::SysYield, &SyscallArgs::default(), &mut sink).unwrap();
        assert_eq!(sink.len, 0);
        arch::log("  ✓ SysYield is a successful no-op\n");
    }

    fn debug_dump_scheduler_writes_placeholder() {
        let mut sink = BufferSink::new();
        handle_syscall(
            Syscall::SysDebugDumpScheduler,
            &SyscallArgs::default(),
            &mut sink,
        )
        .unwrap();
        assert!(sink.as_str().contains("scheduler dump"));
        arch::log("  ✓ SysDebugDumpScheduler stubs out a placeholder line\n");
    }
}
