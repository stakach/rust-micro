//! Phase 11b — SYSCALL/SYSRET trap path.
//!
//! Sets up the four MSRs the SYSCALL instruction consults, plus a
//! `naked_asm` entry stub that saves the user register state, calls
//! the Rust dispatcher, and SYSRETs back. Triggering a SYSCALL from
//! kernel mode would force a ring-0 → ring-0 reload that doesn't
//! match the SYSRET semantics; real exercise of this path lands in
//! Phase 11c when we have a ring-3 thread to run.
//!
//! ABI for the stub (matches the x86_64 user-mode SYSCALL convention
//! that seL4 itself uses):
//!   rax = syscall number
//!   rdi..r9 = up to six args
//!   rcx (clobbered by SYSCALL) = saved user RIP
//!   r11 (clobbered by SYSCALL) = saved user RFLAGS

use crate::arch::x86_64::gdt::{KERNEL_CS, USER32_CS};
use crate::arch::x86_64::msr::*;

/// RAII guard that releases the BKL when dropped. Keeps every
/// kernel-entry function tidy: `let _bkl = BklGuard;` after the
/// `bkl_acquire()` call and the lock comes back automatically on
/// any return path (including panics that we'd want to abort
/// anyway).
struct BklGuard;

impl Drop for BklGuard {
    fn drop(&mut self) {
        crate::smp::bkl_release();
    }
}

/// Bits to clear in RFLAGS on SYSCALL entry. The kernel always
/// wants IF=0 (interrupts off), DF=0 (string-op direction), and
/// the trap/AC flags zero. We OR all of them into one mask:
///   IF=bit 9, DF=bit 10, TF=bit 8, AC=bit 18.
const FMASK_VALUE: u64 = (1 << 9) | (1 << 10) | (1 << 8) | (1 << 18);

/// Initialise the MSRs. Must run after the GDT is loaded (so the
/// CS / SS selectors in IA32_STAR refer to a real GDT entry).
pub fn init_syscall_msrs() {
    unsafe {
        // Enable SYSCALL/SYSRET via IA32_EFER.SCE, and No-eXecute
        // page-table support via EFER.NXE so PTEs with bit 63 set
        // don't trip a reserved-bit fault on this CPU. BOOTBOOT
        // sets these on the BSP but not on APs; per-CPU setup
        // makes APs match.
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | EFER_SCE | crate::arch::x86_64::msr::EFER_NXE);

        // IA32_STAR layout:
        //   bits 31..0  = legacy SYSCALL target EIP (32-bit; unused
        //                 in long mode)
        //   bits 47..32 = CS selector for SYSCALL: kernel CS at
        //                 entry; SS = entry+8.
        //   bits 63..48 = base for SYSRET: SS = base+8, CS = base+16.
        let kernel_cs = KERNEL_CS as u64;
        let user_base = USER32_CS as u64; // 0x18 → SS=0x20+3, CS=0x28+3
        let star = (kernel_cs << 32) | (user_base << 48);
        wrmsr(IA32_STAR, star);

        // SYSCALL entry RIP.
        wrmsr(IA32_LSTAR, syscall_entry as u64);

        // RFLAGS mask.
        wrmsr(IA32_FMASK, FMASK_VALUE);
    }
}

/// Read-back accessors used by the spec.
pub fn lstar() -> u64 { unsafe { rdmsr(IA32_LSTAR) } }
pub fn star() -> u64 { unsafe { rdmsr(IA32_STAR) } }
pub fn fmask() -> u64 { unsafe { rdmsr(IA32_FMASK) } }
pub fn efer() -> u64 { unsafe { rdmsr(IA32_EFER) } }

// ---------------------------------------------------------------------------
// Naked SYSCALL entry stub.
//
// On entry from user mode:
//   * CS  = kernel CS (CPU set it from STAR[47:32])
//   * SS  = kernel SS
//   * RSP = the value the user had — we still need to switch to the
//           kernel stack ourselves
//   * RCX = saved user RIP
//   * R11 = saved user RFLAGS
//
// We save the full register snapshot into a per-thread context
// region that scheduler.rs hands us via GS_BASE (set up by the
// per-CPU bootstrap). For Phase 11b that region is a single static
// `SyscallSaveArea` since we don't yet have a current-thread
// pointer. Phase 11c+ swap this for the TCB's tcbContext.
// ---------------------------------------------------------------------------

/// Snapshot of user-mode general-purpose registers a SYSCALL
/// captured. Memory layout matches the order the entry stub writes,
/// so a debugger that reads this struct sees registers in the order
/// they appear in the manual (rax first because it's the syscall
/// number).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UserContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,  // user RIP
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64, // user RFLAGS
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rsp: u64, // user RSP
}

impl UserContext {
    pub const fn new_zero() -> Self {
        Self {
            rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            rsp: 0,
        }
    }

    /// Build a fresh user context that, when entered, will start
    /// executing at `entry` with `rsp` and arg-0 = `arg0`.
    pub const fn for_entry(entry: u64, rsp: u64, arg0: u64) -> Self {
        let mut c = Self::new_zero();
        c.rcx = entry;        // sysretq reloads RIP from rcx
        c.r11 = 0x202;        // RFLAGS: bit 1 reserved=1, IF=1
        c.rsp = rsp;
        c.rdi = arg0;
        c
    }
}

/// Single save area for the current syscall in flight. Phase 11c
/// replaces this with a per-TCB context once threads exist.
#[no_mangle]
pub static mut SYSCALL_SAVE: UserContext = UserContext {
    rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0,
    r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
    rsp: 0,
};

/// Kernel-stack pointer the entry stub loads on SYSCALL. The Phase
/// 11a TSS holds the same value for IRQ entries; this static is the
/// SYSCALL-specific rsp because SYSCALL does not consult the TSS.
#[no_mangle]
pub static mut SYSCALL_KERNEL_RSP: u64 = 0;

/// Set the kernel rsp the SYSCALL entry will switch to.
pub fn set_syscall_kernel_rsp(rsp: u64) {
    unsafe {
        SYSCALL_KERNEL_RSP = rsp;
    }
}

/// First-launch a user thread. Loads `ctx`'s GPRs and uses sysretq
/// to enter user mode. Mirrors what the SYSCALL entry stub's tail
/// does after dispatcher returns. Use this to enter a thread that
/// has never run before — its `user_context.rcx` holds the entry
/// RIP, `r11` the initial RFLAGS, `rsp` the user stack top.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn enter_user_via_sysret(ctx: *const UserContext) -> ! {
    core::arch::naked_asm!(
        // rdi = ctx pointer. Restore GPRs in roughly the same order
        // as the SYSCALL entry stub's restore tail.
        "mov rax, [rdi + 0]",
        "mov rbx, [rdi + 8]",
        "mov rcx, [rdi + 16]",   // user RIP — sysretq reads this
        "mov rdx, [rdi + 24]",
        "mov rsi, [rdi + 32]",
        "mov rbp, [rdi + 48]",
        "mov r8,  [rdi + 56]",
        "mov r9,  [rdi + 64]",
        "mov r10, [rdi + 72]",
        "mov r11, [rdi + 80]",   // user RFLAGS — sysretq reads this
        "mov r12, [rdi + 88]",
        "mov r13, [rdi + 96]",
        "mov r14, [rdi + 104]",
        "mov r15, [rdi + 112]",
        "mov rsp, [rdi + 120]",  // user RSP (sysretq doesn't restore)
        // rdi was the ctx pointer we needed; restore its user value
        // last, after we've used it for everything else.
        "mov rdi, [rdi + 40]",
        "sysretq",
    );
}

/// SYSCALL trap entry. Naked so we control every instruction —
/// the compiler can't be allowed to add a prologue that would
/// clobber rcx / r11 before we save them.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // Save the user GPRs into SYSCALL_SAVE. RIP-relative
        // addressing because the kernel image is PIC-shaped.
        "mov [rip + {save} + 0],   rax",
        "mov [rip + {save} + 8],   rbx",
        "mov [rip + {save} + 16],  rcx",
        "mov [rip + {save} + 24],  rdx",
        "mov [rip + {save} + 32],  rsi",
        "mov [rip + {save} + 40],  rdi",
        "mov [rip + {save} + 48],  rbp",
        "mov [rip + {save} + 56],  r8",
        "mov [rip + {save} + 64],  r9",
        "mov [rip + {save} + 72],  r10",
        "mov [rip + {save} + 80],  r11",
        "mov [rip + {save} + 88],  r12",
        "mov [rip + {save} + 96],  r13",
        "mov [rip + {save} + 104], r14",
        "mov [rip + {save} + 112], r15",
        "mov [rip + {save} + 120], rsp",

        // Switch to the kernel stack.
        "mov rsp, [rip + {kstack}]",

        // Call the Rust dispatcher. ABI:
        //   rdi = syscall number (we put rax there)
        //   rsi = pointer to UserContext
        "mov rdi, [rip + {save} + 0]",
        "lea rsi, [rip + {save}]",
        "call {handler}",

        // Restore user GPRs (rcx and r11 carry the SYSRET targets).
        "mov rax, [rip + {save} + 0]",
        "mov rbx, [rip + {save} + 8]",
        "mov rcx, [rip + {save} + 16]",
        "mov rdx, [rip + {save} + 24]",
        "mov rsi, [rip + {save} + 32]",
        "mov rdi, [rip + {save} + 40]",
        "mov rbp, [rip + {save} + 48]",
        "mov r8,  [rip + {save} + 56]",
        "mov r9,  [rip + {save} + 64]",
        "mov r10, [rip + {save} + 72]",
        "mov r11, [rip + {save} + 80]",
        "mov r12, [rip + {save} + 88]",
        "mov r13, [rip + {save} + 96]",
        "mov r14, [rip + {save} + 104]",
        "mov r15, [rip + {save} + 112]",
        "mov rsp, [rip + {save} + 120]",
        "sysretq",
        save = sym SYSCALL_SAVE,
        kstack = sym SYSCALL_KERNEL_RSP,
        handler = sym rust_syscall_dispatch,
    );
}

/// Rust-side dispatcher invoked by the asm stub. Translates the
/// raw syscall number + UserContext into a `Syscall` and delegates
/// to the existing `syscall_handler::handle_syscall`. The serial
/// driver doubles as the DebugSink for now.
///
/// Public so specs (and a future user-mode integration test) can
/// invoke the same path the trap entry calls.
#[no_mangle]
pub extern "C" fn rust_syscall_dispatch(number: u64, ctx: &mut UserContext) {
    use crate::arch;
    use crate::syscall_handler::{handle_syscall, DebugSink, SyscallArgs};
    use crate::syscalls::Syscall;

    // Phase 28b — Big Kernel Lock. Hold across all kernel-state
    // mutations + the next-thread pick. Released after we've
    // committed the next thread's user_context back to the save
    // area; the asm stub's sysretq tail only reads (from
    // SYSCALL_SAVE) after that, and that read is single-CPU since
    // SYSCALL_SAVE is only touched by this CPU's syscall path.
    crate::smp::bkl_acquire();
    let _bkl = BklGuard;

    struct SerialSink;
    impl DebugSink for SerialSink {
        fn put_byte(&mut self, b: u8) {
            // Tiny wrapper: arch::log takes a &str; we route through
            // a 1-byte buffer. Avoids changing the existing log API.
            let buf = [b];
            if let Ok(s) = core::str::from_utf8(&buf) {
                arch::log(s);
            }
        }
    }

    // Phase 14d: parent the in-flight SYSCALL_SAVE into the current
    // TCB, so the per-thread user_context survives schedule()
    // returning a different current thread.
    use crate::kernel::KERNEL;
    use core::sync::atomic::Ordering as AtomOrd;
    unsafe {
        if let Some(prev) = KERNEL.get().scheduler.current() {
            KERNEL.get().scheduler.slab.get_mut(prev).user_context = *ctx;
            IN_FLIGHT_INVOKER.store(prev.0 as u32, AtomOrd::Relaxed);
        } else {
            IN_FLIGHT_INVOKER.store(u32::MAX, AtomOrd::Relaxed);
        }
    }

    let args = SyscallArgs {
        a0: ctx.rdi,
        a1: ctx.rsi,
        a2: ctx.rdx,
        a3: ctx.r10, // x86_64 user ABI puts a3 in r10 for SYSCALL
        a4: ctx.r8,
        a5: ctx.r9,
    };
    let syscall = match Syscall::from_i32(number as i32) {
        Some(s) => s,
        None => {
            arch::log("[unknown syscall]\n");
            ctx.rax = u64::MAX;
            return;
        }
    };
    let mut sink = SerialSink;
    let result = handle_syscall(syscall, &args, &mut sink);

    use core::sync::atomic::Ordering;
    // Phase 13c integration: single-thread launcher signals "test
    // done" on the first SysDebugPutChar.
    if super::usermode::USERMODE_TEST_TRIGGERED.load(Ordering::Relaxed)
        && matches!(syscall, Syscall::SysDebugPutChar)
    {
        arch::log(
            "\n[user-mode round-trip succeeded — exiting QEMU]\n",
        );
        crate::arch::qemu_exit(0);
    }
    // Phase 14d: the two-thread IPC demo expects to see at least
    // two SysDebugPutChar invocations ('P' from the receiver before
    // it Recv's, then a byte after Recv returns).
    if super::usermode::IPC_DEMO_ACTIVE.load(Ordering::Relaxed)
        && matches!(syscall, Syscall::SysDebugPutChar)
    {
        let prev = super::usermode::IPC_PRINTED.fetch_add(1, Ordering::Relaxed);
        if prev + 1 >= 2 {
            arch::log(
                "\n[two-thread IPC succeeded — exiting QEMU]\n",
            );
            crate::arch::qemu_exit(0);
        }
    }

    // If the current thread blocked on a Send/Recv, scheduler.current
    // is None; pick the next runnable. If none is runnable we fall
    // through with the original ctx, which is fine for the tests
    // that don't end up parking the caller.
    unsafe {
        let s = KERNEL.get();
        let next = match s.scheduler.current() {
            Some(t) => Some(t),
            None => s.scheduler.choose_thread(),
        };
        if let Some(next) = next {
            s.scheduler.set_current(Some(next));
            // Phase 24: if next thread runs in a different vspace,
            // swap CR3. Kernel half is identical across user
            // PML4s so the swap is safe — the next instruction
            // (and SYSCALL_SAVE / SYSCALL_KERNEL_RSP, which we
            // touch below via the naked stub's restore tail) all
            // live in the kernel half.
            let next_cr3 = s.scheduler.slab.get(next).cpu_context.cr3;
            if next_cr3 != 0 {
                let cur_cr3: u64;
                core::arch::asm!("mov {}, cr3", out(reg) cur_cr3,
                    options(nomem, nostack, preserves_flags));
                if next_cr3 != cur_cr3 {
                    core::arch::asm!("mov cr3, {}", in(reg) next_cr3,
                        options(nostack, preserves_flags));
                }
            }
            // Phase 15a: fan IPC delivery state from the receiving
            // TCB into its user-visible registers. The receiver
            // reads:
            //   rax = 0                   (success)
            //   rsi = MessageInfo (label + length packed)
            //   rdi = badge of sender's cap
            //   rdx, r10, r8, r9 = msg_regs[0..3]
            // For non-IPC syscalls (or for the sender after its
            // SysSend completes), rax = result and the rest of
            // the user_context is left as the sender stored it.
            let tcb = s.scheduler.slab.get(next);
            let mut new_ctx = tcb.user_context;
            let was_recv_path = matches!(
                syscall,
                Syscall::SysRecv | Syscall::SysNBRecv | Syscall::SysReplyRecv,
            ) && Some(next) == s.scheduler.current();
            // The "matches" above guards against the sender side:
            // when a blocked sender wakes up, we don't want to
            // overwrite its rdi/rdx with the receiver's view.
            // Distinguish by checking whether `next` is the same
            // thread that just issued the syscall.
            let invoker = current_in_flight_invoker();
            if was_recv_path && Some(next) == invoker {
                // Pack MessageInfo back into rsi: bits 0..7 length,
                // top bits label.
                let mi = (tcb.ipc_label << 12) | (tcb.ipc_length as u64 & 0x7F);
                new_ctx.rsi = mi;
                new_ctx.rdi = tcb.ipc_badge;
                new_ctx.rdx = tcb.msg_regs[0];
                new_ctx.r10 = tcb.msg_regs[1];
                new_ctx.r8 = tcb.msg_regs[2];
                new_ctx.r9 = tcb.msg_regs[3];
            }
            new_ctx.rax = match &result {
                Ok(()) => 0,
                Err(_) => u64::MAX,
            };
            // Persist the user-visible regs back into the TCB so
            // the next entry sees them too (idempotent).
            s.scheduler.slab.get_mut(next).user_context = new_ctx;
            *ctx = new_ctx;
        } else {
            ctx.rax = match result {
                Ok(()) => 0,
                Err(_) => u64::MAX,
            };
        }
    }
}

/// Best-effort — return the TCB that issued the in-flight syscall.
/// We track this via a static populated at the top of the
/// dispatcher (before any block() may clear scheduler.current).
fn current_in_flight_invoker() -> Option<crate::tcb::TcbId> {
    use core::sync::atomic::Ordering;
    let raw = IN_FLIGHT_INVOKER.load(Ordering::Relaxed);
    if raw == u32::MAX {
        None
    } else {
        Some(crate::tcb::TcbId(raw as u16))
    }
}

static IN_FLIGHT_INVOKER: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_syscall_msrs() {
        arch::log("Running SYSCALL MSR setup tests...\n");
        efer_sce_set();
        star_kernel_user_pair();
        lstar_points_at_entry();
        fmask_clears_interrupt_flag();
        dispatcher_emits_byte_for_sys_debug_put_char();
        dispatcher_signals_unknown_via_max_rax();
        arch::log("SYSCALL MSR tests completed\n");
    }

    #[inline(never)]
    fn efer_sce_set() {
        let efer = efer();
        assert!(efer & EFER_SCE != 0, "EFER.SCE must be set");
        arch::log("  ✓ EFER.SCE enables SYSCALL\n");
    }

    #[inline(never)]
    fn star_kernel_user_pair() {
        let star = star();
        let kcs = ((star >> 32) & 0xFFFF) as u16;
        let ucb = ((star >> 48) & 0xFFFF) as u16;
        assert_eq!(kcs, KERNEL_CS);
        assert_eq!(ucb, USER32_CS);
        arch::log("  ✓ STAR holds kernel CS + user-base selectors\n");
    }

    #[inline(never)]
    fn lstar_points_at_entry() {
        let lstar = lstar();
        let entry = syscall_entry as u64;
        assert_eq!(lstar, entry, "LSTAR should point at the entry stub");
        arch::log("  ✓ LSTAR points to the SYSCALL entry stub\n");
    }

    #[inline(never)]
    fn fmask_clears_interrupt_flag() {
        let mask = fmask();
        assert!(mask & (1 << 9) != 0, "FMASK must clear IF on entry");
        assert!(mask & (1 << 10) != 0, "FMASK must clear DF on entry");
        arch::log("  ✓ FMASK clears IF and DF on entry\n");
    }

    /// Phase 11d — integration test of the dispatcher. Builds a
    /// UserContext as the trap stub would and calls
    /// rust_syscall_dispatch directly. We can't trigger an actual
    /// SYSCALL from kernel mode and survive the sysretq (it'd land
    /// in ring 3 at a kernel RIP), so we exercise the same code
    /// path one frame higher up. Identical to what the entry stub
    /// does after register save.
    #[inline(never)]
    pub fn dispatcher_emits_byte_for_sys_debug_put_char() {
        // SysDebugPutChar = -9. ABI: rdi = arg0 (the byte).
        let mut ctx = UserContext::default();
        ctx.rdi = b'!' as u64;
        // Pre-flight rax sentinel; the dispatcher writes the
        // syscall result back here.
        ctx.rax = 0xDEAD_BEEF;

        super::rust_syscall_dispatch(-9i64 as u64, &mut ctx);

        // Successful syscall stamps rax = 0.
        assert_eq!(ctx.rax, 0, "dispatcher should set rax=0 on success");
        arch::log("  ✓ rust_syscall_dispatch handles SysDebugPutChar\n");
    }

    #[inline(never)]
    pub fn dispatcher_signals_unknown_via_max_rax() {
        let mut ctx = UserContext::default();
        ctx.rax = 0;
        super::rust_syscall_dispatch(99u64, &mut ctx);
        assert_eq!(ctx.rax, u64::MAX, "unknown syscall returns -1");
        arch::log("  ✓ rust_syscall_dispatch flags unknown syscalls\n");
    }
}
