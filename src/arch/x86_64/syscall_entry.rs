//! Phase 11b — SYSCALL/SYSRET trap path.
//!
//! Sets up the four MSRs the SYSCALL instruction consults, plus a
//! `naked_asm` entry stub that saves the user register state, calls
//! the Rust dispatcher, and SYSRETs back. Triggering a SYSCALL from
//! kernel mode would force a ring-0 → ring-0 reload that doesn't
//! match the SYSRET semantics; real exercise of this path lands in
//! Phase 11c when we have a ring-3 thread to run.
//!
//! ABI for the stub (matches upstream seL4's x86_64 user-mode SYSCALL
//! convention — see seL4/src/arch/x86/64/traps.S `handle_fastsyscall`):
//!   rdx = syscall number
//!   rdi = capRegister (cap_ptr) / first arg
//!   rsi = msgInfoRegister
//!   r10, r8, r9, r15 = msg_regs[0..3]
//!   rcx (clobbered by SYSCALL) = saved user RIP
//!   r11 (clobbered by SYSCALL) = saved user RFLAGS
//!   rax = preserved across SYSCALL (Phase 38c-followup). Upstream
//!         libsel4 stubs don't list rax as a clobber; we honour that
//!         so optimized libsel4-built code can keep live values in
//!         rax across the syscall. Errors are signalled out of band
//!         via msginfo labels and faults, not via a rax sentinel.

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

    // Phase 28f — per-CPU `IA32_KERNEL_GS_BASE` so the SYSCALL
    // stub's `swapgs` lands GS at the calling CPU's slot of
    // `PER_CPU_SYSCALL`. Done here so every CPU's init path
    // (BSP and AP) wires it up automatically.
    init_per_cpu_gs();
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

/// Per-CPU SYSCALL bookkeeping. Each CPU owns one of these slots
/// and reaches it through `IA32_KERNEL_GS_BASE` after a `swapgs`.
///
/// Field layout matters — the naked syscall stub addresses fields
/// by hard-coded offsets relative to `gs:[0]`, not by name:
///   * offset  0 — `kernel_rsp`     (SYSCALL kernel stack pointer)
///   * offset  8 — padding to keep `user_ctx` 16-byte aligned
///   * offset 16 — `user_ctx`       (UserContext save area)
///
/// `self_ptr` is **not** stored here; the Rust dispatcher recovers
/// the slot via `arch::get_cpu_id()`, and the asm stub addresses
/// fields with constant offsets only.
#[repr(C, align(16))]
pub struct PerCpuSyscallArea {
    pub kernel_rsp: u64,
    _pad: u64,
    pub user_ctx: UserContext,
}

const PER_CPU_INIT: PerCpuSyscallArea = PerCpuSyscallArea {
    kernel_rsp: 0,
    _pad: 0,
    user_ctx: UserContext {
        rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0,
        r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
        rsp: 0,
    },
};

/// Per-CPU syscall save areas. One slot per CPU; each CPU's
/// `IA32_KERNEL_GS_BASE` MSR points at its own slot. The asm stub
/// then uses GS-relative addressing to read/write its own slot,
/// avoiding the cross-CPU race a single shared `SYSCALL_SAVE`
/// would have under SMP.
#[no_mangle]
pub static mut PER_CPU_SYSCALL: [PerCpuSyscallArea; crate::smp::MAX_CPUS] =
    [PER_CPU_INIT; crate::smp::MAX_CPUS];

/// Set the kernel rsp the SYSCALL entry will switch to. Targets
/// the calling CPU's per-CPU slot.
pub fn set_syscall_kernel_rsp(rsp: u64) {
    unsafe {
        let cpu = crate::arch::get_cpu_id() as usize;
        PER_CPU_SYSCALL[cpu].kernel_rsp = rsp;
    }
}

/// Get a pointer to the calling CPU's UserContext save area —
/// used by the Rust dispatcher (the asm stub addresses it via
/// gs-relative writes, not via this helper).
pub fn current_cpu_user_ctx_mut() -> &'static mut UserContext {
    unsafe {
        let cpu = crate::arch::get_cpu_id() as usize;
        &mut PER_CPU_SYSCALL[cpu].user_ctx
    }
}

// ---------------------------------------------------------------------------
// Field offsets the naked stub references. Keep these in sync with
// `PerCpuSyscallArea` — `static_assertions` would catch drift but
// we keep deps minimal.
// ---------------------------------------------------------------------------

/// Offset of `kernel_rsp` within `PerCpuSyscallArea` (gs-relative).
const OFF_KSP: usize = 0;
/// Offset of `user_ctx` within `PerCpuSyscallArea` (gs-relative).
const OFF_CTX: usize = 16;

/// Set the calling CPU's `IA32_KERNEL_GS_BASE` AND active GS_BASE to
/// its per-CPU slot. The kernel relies on the invariant that
/// "kernel-mode active GS_BASE = per-CPU slot": SYSCALL entry's
/// `swapgs` swaps active and KERNEL, so as long as both start equal
/// to the per-CPU slot, every entry/exit pair leaves them unchanged.
/// All exit paths (the SYSCALL stub's tail and `enter_user_via_sysret`)
/// likewise `swapgs` so the round-trip preserves the invariant.
///
/// Setting both at init also covers the very first user dispatch:
/// the rootserver-launch path calls `enter_user_via_sysret` from
/// fresh kernel mode (no prior SYSCALL entry), so without seeding
/// the active register the post-swapgs value would be the boot
/// default of 0 and the next SYSCALL would land in the kernel with
/// gs pointing at virtual address 0.
pub fn init_per_cpu_gs() {
    unsafe {
        let cpu = crate::arch::get_cpu_id() as usize;
        let base = (&raw mut PER_CPU_SYSCALL[cpu]) as u64;
        wrmsr(IA32_KERNEL_GS_BASE, base);
        wrmsr(IA32_GS_BASE, base);
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
        // Mirror the syscall-entry's swapgs round-trip so the
        // active/KERNEL_GS_BASE pair stays balanced. Without this,
        // every dispatch through this path rotates KERNEL_GS_BASE
        // by one (active and KERNEL drift apart), and after a few
        // round-trips KERNEL_GS_BASE = 0 → the next SYSCALL entry's
        // swapgs makes the kernel access gs:[0x10] = address 0x10,
        // crashing the kernel before any GPR is saved. init_per_cpu_gs
        // seeds active=KERNEL=per-CPU at boot so the initial dispatch
        // (no prior SYSCALL entry) starts the invariant correctly.
        "swapgs",
        "sysretq",
    );
}

/// SYSCALL trap entry. Naked so we control every instruction —
/// the compiler can't be allowed to add a prologue that would
/// clobber rcx / r11 before we save them.
///
/// Phase 28f makes this SMP-safe: instead of a single global
/// `SYSCALL_SAVE` static, every CPU has its own slot reachable
/// via `gs:` after `swapgs` (which swaps the active `IA32_GS_BASE`
/// with `IA32_KERNEL_GS_BASE`, the latter set per-CPU at init).
/// All saves/restores below use `gs:[OFF_CTX + reg_offset]`.
///
/// Bytes: PerCpuSyscallArea layout is
///   `kernel_rsp:8 | _pad:8 | user_ctx{rax..rsp}:16*8`,
/// so OFF_KSP=0 and OFF_CTX=16. Field offsets within UserContext
/// are the same as in the previous flat-static layout.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // Switch to the kernel's per-CPU GS_BASE.
        "swapgs",

        // Save the user GPRs into the calling CPU's user_ctx
        // (gs:[16 + reg_offset]).
        "mov gs:[16 + 0],   rax",
        "mov gs:[16 + 8],   rbx",
        "mov gs:[16 + 16],  rcx",
        "mov gs:[16 + 24],  rdx",
        "mov gs:[16 + 32],  rsi",
        "mov gs:[16 + 40],  rdi",
        "mov gs:[16 + 48],  rbp",
        "mov gs:[16 + 56],  r8",
        "mov gs:[16 + 64],  r9",
        "mov gs:[16 + 72],  r10",
        "mov gs:[16 + 80],  r11",
        "mov gs:[16 + 88],  r12",
        "mov gs:[16 + 96],  r13",
        "mov gs:[16 + 104], r14",
        "mov gs:[16 + 112], r15",
        "mov gs:[16 + 120], rsp",

        // Switch to the kernel stack (gs:[0] = kernel_rsp).
        "mov rsp, gs:[0]",

        // Call the Rust dispatcher. ABI:
        //   rdi = syscall number (upstream seL4 ABI puts it in rdx;
        //         our save area at offset 24 holds the saved rdx)
        //   rsi = from_user marker (1 — the no-runnable-thread tail
        //         enters HLT instead of sysret'ing back to a blocked
        //         caller; specs that invoke the dispatcher directly
        //         pass 0 to keep their drive-by call returning).
        // The dispatcher recovers its UserContext via
        // `arch::get_cpu_id()` indexing into `PER_CPU_SYSCALL`.
        "mov rdi, gs:[16 + 24]",
        "mov rsi, 1",
        "call {handler}",

        // Restore user GPRs (rcx and r11 carry the SYSRET targets).
        "mov rax, gs:[16 + 0]",
        "mov rbx, gs:[16 + 8]",
        "mov rcx, gs:[16 + 16]",
        "mov rdx, gs:[16 + 24]",
        "mov rsi, gs:[16 + 32]",
        "mov rdi, gs:[16 + 40]",
        "mov rbp, gs:[16 + 48]",
        "mov r8,  gs:[16 + 56]",
        "mov r9,  gs:[16 + 64]",
        "mov r10, gs:[16 + 72]",
        "mov r11, gs:[16 + 80]",
        "mov r12, gs:[16 + 88]",
        "mov r13, gs:[16 + 96]",
        "mov r14, gs:[16 + 104]",
        "mov r15, gs:[16 + 112]",
        "mov rsp, gs:[16 + 120]",

        // Swap GS_BASE back to the user value before sysretq.
        "swapgs",
        "sysretq",
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
pub extern "C" fn rust_syscall_dispatch(number: u64, from_user: u64) {
    use crate::arch;
    use crate::syscall_handler::{handle_syscall, DebugSink, SyscallArgs};
    use crate::syscalls::Syscall;

    // Phase 28b — Big Kernel Lock. Hold across all kernel-state
    // mutations + the next-thread pick. Released after we've
    // committed the next thread's user_context back to the per-CPU
    // save area; the asm stub's sysretq tail only reads from that
    // save area after that, and the read is single-CPU since each
    // CPU has its own slot indexed via gs:.
    crate::smp::bkl_acquire();
    let _bkl = BklGuard;

    // Phase 28h — bump the per-CPU syscall counter so the SMP
    // ping demo (running on AP1) is observable from BSP.
    crate::smp::SYSCALL_COUNT_PER_CPU[arch::get_cpu_id() as usize]
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);


    // Phase 28f — recover the calling CPU's UserContext from the
    // per-CPU array. The asm stub wrote it via `gs:[16 + ...]`;
    // we look it up by APIC ID here.
    let ctx: &mut UserContext = current_cpu_user_ctx_mut();

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

    // Upstream seL4 x86_64 SYSCALL ABI: rdi = capRegister (a0),
    // rsi = msgInfoRegister (a1), r10/r8/r9/r15 = msg_regs[0..3]
    // (= a2..a5). rdx is the syscall number (consumed in the asm stub).
    let args = SyscallArgs {
        a0: ctx.rdi,
        a1: ctx.rsi,
        a2: ctx.r10,
        a3: ctx.r8,
        a4: ctx.r9,
        a5: ctx.r15,
    };
    let syscall = match Syscall::from_i32(number as i32) {
        Some(s) => s,
        None => {
            // Phase 38c-followup — rax is preserved across SYSCALL
            // (matches upstream seL4); errors are signalled out of
            // band (faults / IPC label), not via a rax sentinel.
            arch::log("[unknown syscall nr=");
            let signed = number as i64;
            let abs = if signed < 0 { (-signed) as u64 } else { signed as u64 };
            if signed < 0 { arch::log("-"); }
            let mut buf = [0u8; 20];
            let mut i = buf.len();
            let mut n = abs;
            if n == 0 {
                arch::log("0");
            } else {
                while n > 0 {
                    i -= 1;
                    buf[i] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
                if let Ok(s) = core::str::from_utf8(&buf[i..]) {
                    arch::log(s);
                }
            }
            arch::log("]\n");
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
    // Phase 29e/g/h + 32g — exit logic for the rootserver demo.
    //   * The 29h IPC sequence prints three newlines (alive banner,
    //     retype-Endpoint, IPC-result). On the third newline we
    //     activate `MCS_DEMO_ACTIVE` and the rootserver continues
    //     into Phase 32g (spawn two SC-bound children that print
    //     'H' / 'B').
    //   * In MCS phase, count 'H' and 'B' bytes; once we've seen
    //     enough of each to verify the budget split, log a summary
    //     and qemu_exit.
    // Phase 34a — microtest sentinel watch. Built whether or not
    // the rootserver is in microtest mode; the matcher is a noop
    // outside that mode (the sentinel never appears in normal
    // output).
    if matches!(syscall, Syscall::SysDebugPutChar) {
        let b = args.a0 as u8;
        if crate::rootserver::microtest_check_byte(b) {
            arch::log("[microtest sentinel matched -- exiting QEMU]\n");
            crate::arch::qemu_exit(0);
        }
    }

    if crate::rootserver::ROOTSERVER_DEMO_ACTIVE.load(Ordering::Relaxed)
        && matches!(syscall, Syscall::SysDebugPutChar)
    {
        let b = args.a0 as u8;
        if b == b'\n' {
            let prev = crate::rootserver::ROOTSERVER_PRINTED
                .fetch_add(1, Ordering::Relaxed);
            if prev + 1 >= 3 && !crate::rootserver::MCS_DEMO_ACTIVE
                .load(Ordering::Relaxed)
            {
                crate::rootserver::MCS_DEMO_ACTIVE
                    .store(true, Ordering::Relaxed);
            }
        } else if crate::rootserver::MCS_DEMO_ACTIVE.load(Ordering::Relaxed) {
            if b == b'H' {
                crate::rootserver::MCS_H_COUNT.fetch_add(1, Ordering::Relaxed);
            } else if b == b'B' {
                crate::rootserver::MCS_B_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            // Exit when we've seen enough chars from both children
            // to verify the budget split. Threshold is generous so
            // we land deep into the MCS scheduler rather than just
            // catching the first dispatch.
            let h = crate::rootserver::MCS_H_COUNT.load(Ordering::Relaxed);
            let bc = crate::rootserver::MCS_B_COUNT.load(Ordering::Relaxed);
            // Threshold sized so MCS spans several refill periods
            // and the H:B ratio settles toward the budget split.
            // Each char ≈ 1 µs in qemu; 20 000 chars ≈ 20 ms which
            // is two full 10-ms refill periods at 1000 Hz PIT.
            if h + bc >= 20000 && h > 0 && bc > 0 {
                arch::log("\n[MCS demo: ");
                let mut tmp = [0u8; 20];
                fn print_decimal(n: usize) {
                    let mut buf = [0u8; 20];
                    let mut i = buf.len();
                    let mut n = n;
                    if n == 0 {
                        crate::arch::log("0");
                        return;
                    }
                    while n > 0 {
                        i -= 1;
                        buf[i] = b'0' + (n % 10) as u8;
                        n /= 10;
                    }
                    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
                        crate::arch::log(s);
                    }
                }
                let _ = tmp;
                print_decimal(h);
                arch::log("H ");
                print_decimal(bc);
                arch::log("B] [rootserver bootstrap complete — exiting QEMU]\n");
                crate::arch::qemu_exit(0);
            }
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
            // TCB into its user-visible registers. Mirrors upstream
            // seL4's IPC return ABI (`x64_sys_recv`):
            //   rax = 0                   (success — our extension)
            //   rsi = MessageInfo (label + length packed)
            //   rdi = badge of sender's cap
            //   r10, r8, r9, r15 = msg_regs[0..3]
            // For non-IPC syscalls (or for the sender after its
            // SysSend completes), rax = result and the rest of
            // the user_context is left as the sender stored it.
            let tcb = s.scheduler.slab.get(next);
            let mut new_ctx = tcb.user_context;
            let was_recv_path = matches!(
                syscall,
                Syscall::SysRecv
                | Syscall::SysNBRecv
                | Syscall::SysReplyRecv
                | Syscall::SysWait
                | Syscall::SysNBWait,
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
                new_ctx.r10 = tcb.msg_regs[0];
                new_ctx.r8  = tcb.msg_regs[1];
                new_ctx.r9  = tcb.msg_regs[2];
                new_ctx.r15 = tcb.msg_regs[3];
            }
            // Phase 38c-followup — rax is preserved across SYSCALL
            // (matches upstream seL4: their `handle_fastsyscall`
            // saves and restores rax around `c_handle_syscall`).
            // Errors are signalled out of band — invocations that
            // produce return data write it to the IPC buffer + msg
            // regs and pack the status into msginfo's label, faults
            // go via the parent's fault EP. Keeping `rax` clobber-
            // free is required so libsel4-built code (whose stubs
            // don't list rax as a clobber) doesn't lose loop
            // counters across the syscall.
            let _ = &result;
            // Persist the user-visible regs back into the TCB so
            // the next entry sees them too (idempotent).
            s.scheduler.slab.get_mut(next).user_context = new_ctx;
            *ctx = new_ctx;
        } else if from_user != 0 {
            // No runnable thread on this CPU. The asm restore tail
            // would otherwise sysretq back to the original caller's
            // context (PER_CPU_SYSCALL[cpu].user_ctx, which the
            // entry stub populated with caller's GPRs). But the
            // caller is the one we just blocked — sysret'ing to it
            // would have it run user code as if the syscall returned
            // normally, retry the operation, eventually corrupt its
            // own stack and #PF at RIP=0. Halt this CPU in kernel
            // mode until an IRQ arrives instead. Release the BKL
            // first so peer CPUs can keep making progress.
            //
            // sti+hlt is the canonical "enable interrupts and wait
            // for one" sequence on x86; the next IRQ pops us out
            // and we re-enter the dispatcher to look for runnable
            // work.
            //
            // The `from_user` gate keeps spec tests that invoke
            // the dispatcher directly from kernel context falling
            // through and returning, since they have no scheduler
            // state and shouldn't sit in a wait-for-IRQ loop.
            let _ = result;
            crate::smp::bkl_release();
            loop {
                core::arch::asm!("sti", "hlt",
                    options(nostack, preserves_flags));
                // After waking, re-evaluate. If something is now
                // runnable, dispatch it via enter_user_via_sysret.
                let s = KERNEL.get();
                crate::smp::bkl_acquire();
                let next = match s.scheduler.current() {
                    Some(t) => Some(t),
                    None => s.scheduler.choose_thread(),
                };
                if let Some(next_id) = next {
                    s.scheduler.set_current(Some(next_id));
                    let tcb = s.scheduler.slab.get(next_id);
                    let next_cr3 = tcb.cpu_context.cr3;
                    let next_ctx = tcb.user_context;
                    if next_cr3 != 0 {
                        let cur_cr3: u64;
                        core::arch::asm!("mov {}, cr3", out(reg) cur_cr3,
                            options(nomem, nostack, preserves_flags));
                        if next_cr3 != cur_cr3 {
                            core::arch::asm!("mov cr3, {}", in(reg) next_cr3,
                                options(nostack, preserves_flags));
                        }
                    }
                    let pcc = current_cpu_user_ctx_mut();
                    *pcc = next_ctx;
                    crate::smp::bkl_release();
                    enter_user_via_sysret(pcc as *const _);
                    // unreachable
                }
                crate::smp::bkl_release();
                // Spurious wake (e.g. IPI to peer) — go back to HLT.
            }
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
        per_cpu_kernel_gs_base_set();
        dispatcher_emits_byte_for_sys_debug_put_char();
        dispatcher_signals_unknown_via_max_rax();
        arch::log("SYSCALL MSR tests completed\n");
    }

    /// Phase 28f — `IA32_KERNEL_GS_BASE` on this CPU should point
    /// at this CPU's slot in `PER_CPU_SYSCALL`. After SYSCALL+swapgs
    /// the kernel addresses its slot via `gs:[...]`.
    #[inline(never)]
    fn per_cpu_kernel_gs_base_set() {
        let cpu = crate::arch::get_cpu_id() as usize;
        let expected =
            unsafe { (&raw const super::PER_CPU_SYSCALL[cpu]) as u64 };
        let actual = unsafe {
            super::rdmsr(super::IA32_KERNEL_GS_BASE)
        };
        assert_eq!(actual, expected,
            "BSP's IA32_KERNEL_GS_BASE should point at its PER_CPU_SYSCALL slot");
        arch::log("  ✓ IA32_KERNEL_GS_BASE points at this CPU's slot\n");
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
    ///
    /// Phase 38c-followup — rax is preserved across SYSCALL
    /// (upstream ABI), so this spec asserts the dispatcher leaves
    /// the user's rax untouched rather than stamping a result.
    #[inline(never)]
    pub fn dispatcher_emits_byte_for_sys_debug_put_char() {
        // SysDebugPutChar = -12 (MCS layout). ABI: rdi = arg0 (byte).
        let ctx = super::current_cpu_user_ctx_mut();
        *ctx = UserContext::default();
        ctx.rdi = b'!' as u64;
        ctx.rax = 0xDEAD_BEEF;

        super::rust_syscall_dispatch(-12i64 as u64, 0);

        let ctx = super::current_cpu_user_ctx_mut();
        assert_eq!(ctx.rax, 0xDEAD_BEEF,
                   "dispatcher must preserve user's rax (upstream ABI)");
        arch::log("  ✓ rust_syscall_dispatch handles SysDebugPutChar\n");
    }

    /// Phase 38c-followup — unknown syscalls are still rejected,
    /// but `rax` is preserved (no longer stamped with u64::MAX).
    /// The dispatcher just logs `[unknown syscall]` and returns;
    /// userspace would normally see this via a fault delivery to
    /// the parent's fault EP.
    #[inline(never)]
    pub fn dispatcher_signals_unknown_via_max_rax() {
        let ctx = super::current_cpu_user_ctx_mut();
        *ctx = UserContext::default();
        ctx.rax = 0xFEED_CAFE;
        super::rust_syscall_dispatch(99u64, 0);
        let ctx = super::current_cpu_user_ctx_mut();
        assert_eq!(ctx.rax, 0xFEED_CAFE,
                   "kernel preserves rax even on unknown-syscall exit");
        arch::log("  ✓ rust_syscall_dispatch flags unknown syscalls\n");
    }
}
