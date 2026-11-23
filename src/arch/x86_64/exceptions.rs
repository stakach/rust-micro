use super::interrupts::{IdtEntry, IDT};
use core::sync::atomic::{AtomicU64, Ordering};

static USER_PAGE_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);

fn log_user_page_fault(
    faulter: Option<crate::tcb::TcbId>,
    cr2: u64,
    error_code: u64,
    saved_rip: u64,
) {
    crate::arch::log("[user #PF: tcb=");
    if let Some(id) = faulter {
        let mut v = u64::from(id.0);
        let mut buf = [b'0'; 20];
        let mut i = buf.len();
        if v == 0 {
            crate::arch::log("0");
        }
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        if let Ok(s) = core::str::from_utf8(&buf[i..]) {
            crate::arch::log(s);
        }
    } else {
        crate::arch::log("none");
    }
    crate::arch::log(" cr2=0x");
    log_hex64(cr2);
    crate::arch::log(" err=0x");
    log_hex64(error_code);
    crate::arch::log(" rip=0x");
    log_hex64(saved_rip);
    if let Some(id) = faulter.filter(|_| cr2 == 0x10 && saved_rip == 0x801a_0009) {
        // Preserve the special GS diagnosis when a fault is logged.
        let live_user_gs = unsafe {
            crate::arch::x86_64::msr::rdmsr(crate::arch::x86_64::msr::IA32_KERNEL_GS_BASE)
        };
        let configured_gs = unsafe {
            crate::kernel::KERNEL
                .get()
                .scheduler
                .slab
                .get(id)
                .cpu_context
                .gs_base
        };
        crate::arch::log(" user_gs=0x");
        log_hex64(live_user_gs);
        crate::arch::log(" configured_gs=0x");
        log_hex64(configured_gs);
    }
    crate::arch::log("]\n");
}

const X86_DEBUG_SERVICE_GP_ERROR: u64 = (0x2d << 3) | 2;
const X86_DEBUG_SERVICE_SKIP_BYTES: u64 = 3;

#[inline]
fn is_debug_service_gp(error_code: u64) -> bool {
    error_code == X86_DEBUG_SERVICE_GP_ERROR
}

#[inline]
fn debug_service_resume_ip(ip: u64) -> u64 {
    ip.wrapping_add(X86_DEBUG_SERVICE_SKIP_BYTES)
}

/// RAII guard for the BKL — releases on drop. Same shape as the
/// one in `syscall_entry.rs`; duplicated rather than moved into
/// `smp::` to keep the lock surface area visible at each entry
/// point.
struct BklGuard;
impl Drop for BklGuard {
    fn drop(&mut self) {
        crate::smp::bkl_release();
    }
}

use super::cpu_exception_vectors as vector;

/// Shared entry for the CPU exceptions without a dedicated path. A user-mode fault saves the
/// full fault-time register state (the TRUE rcx/r11 in the GPR slots, the frame's
/// RIP/RFLAGS/RSP in the iretq slots, as the #PF/#GP entries do) and is delivered to the
/// thread's fault handler; anything else halts. Neither path returns.
///
/// Stack on entry, after the optional error code at [rsp+0]:
///   [rsp+F+0]  = saved RIP
///   [rsp+F+8]  = saved CS
///   [rsp+F+16] = saved RFLAGS
///   [rsp+F+24] = saved RSP
///   [rsp+F+32] = saved SS
macro_rules! cpu_exception_entry {
    ($name:ident, $vector:expr) => {
        const _: () = assert!(!vector::pushes_error_code($vector));
        cpu_exception_entry!(@entry $name, $vector, 0, "xor edi, edi");
    };
    ($name:ident, $vector:expr, error_code) => {
        const _: () = assert!(vector::pushes_error_code($vector));
        cpu_exception_entry!(@entry $name, $vector, 8, "mov rdi, [rsp]");
    };
    (@entry $name:ident, $vector:expr, $frame:expr, $load_error:literal) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "test byte ptr [rsp + {cs}], 3",
                "jz 2f",
                // -------- user mode: full save into the per-CPU UserContext --------
                "swapgs",
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
                "mov rax, [rsp + {rip}]",
                "mov gs:[16 + 128], rax",   // user_ctx.rip    = saved RIP
                "mov rax, [rsp + {rflags}]",
                "mov gs:[16 + 136], rax",   // user_ctx.rflags = saved RFLAGS
                "mov rax, [rsp + {rsp}]",
                "mov gs:[16 + 120], rax",   // user_ctx.rsp    = saved RSP
                "2:",
                $load_error,                // error code (0 when the CPU pushes none)
                "mov esi, {vector}",
                "mov rdx, [rsp + {rip}]",
                "mov rcx, [rsp + {cs}]",
                "and rsp, -16",
                "call {handler}",
                "ud2",
                vector = const $vector,
                rip = const $frame,
                cs = const $frame + 8,
                rflags = const $frame + 16,
                rsp = const $frame + 24,
                handler = sym handle_cpu_exception,
            );
        }
    };
}

cpu_exception_entry!(divide_error_entry, vector::DIVIDE_ERROR);
// #DB (1) and INT3 (3) are handled by debug_exception_entry / int3_entry
// (CONFIG_HARDWARE_DEBUG_API), defined below.
cpu_exception_entry!(nmi_entry, vector::NMI);
cpu_exception_entry!(overflow_entry, vector::OVERFLOW);
cpu_exception_entry!(bound_range_entry, vector::BOUND_RANGE);
cpu_exception_entry!(invalid_opcode_entry, vector::INVALID_OPCODE);
cpu_exception_entry!(double_fault_entry, vector::DOUBLE_FAULT, error_code);
cpu_exception_entry!(invalid_tss_entry, vector::INVALID_TSS, error_code);
cpu_exception_entry!(segment_not_present_entry, vector::SEGMENT_NOT_PRESENT, error_code);
cpu_exception_entry!(stack_segment_entry, vector::STACK_SEGMENT, error_code);
// #GP (13) and #PF (14) have dedicated entries below.
cpu_exception_entry!(x87_floating_point_entry, vector::X87_FLOATING_POINT);
cpu_exception_entry!(alignment_check_entry, vector::ALIGNMENT_CHECK, error_code);
cpu_exception_entry!(machine_check_entry, vector::MACHINE_CHECK);
cpu_exception_entry!(simd_floating_point_entry, vector::SIMD_FLOATING_POINT);
cpu_exception_entry!(virtualization_entry, vector::VIRTUALIZATION);

pub fn init_exceptions() {
    unsafe {
        IDT[0] = IdtEntry::new(divide_error_entry as u64, 0x08, 0, 0x8E);
        IDT[1] = IdtEntry::new(debug_exception_entry as u64, 0x08, 0, 0x8E);
        IDT[2] = IdtEntry::new(nmi_entry as u64, 0x08, 0, 0x8E);
        // INT3 (#BP) gate needs DPL=3 so a user-mode `int3` traps here
        // instead of #GP'ing (BREAK_REQUEST_001).
        IDT[3] = IdtEntry::new(int3_entry as u64, 0x08, 0, 0xEE);
        IDT[4] = IdtEntry::new(overflow_entry as u64, 0x08, 0, 0x8E);
        IDT[5] = IdtEntry::new(bound_range_entry as u64, 0x08, 0, 0x8E);
        // PAGEFAULT0005 — #UD from user mode becomes a UserException
        // fault to the thread's fault handler (upstream
        // handleUserLevelFault).
        IDT[6] = IdtEntry::new(invalid_opcode_entry as u64, 0x08, 0, 0x8E);
        // FPU0004 — replace the macro stub with `device_not_available_entry`,
        // which captures saved CS so the handler can distinguish user-mode
        // (CPL=3 → check `tcbFlags & seL4_TCBFlag_fpuDisabled`) from
        // kernel-mode #NM. Same pattern the page-fault handler uses.
        IDT[7] = IdtEntry::new(device_not_available_entry as u64, 0x08, 0, 0x8E);
        IDT[8] = IdtEntry::new(double_fault_entry as u64, 0x08, 0, 0x8E);
        IDT[10] = IdtEntry::new(invalid_tss_entry as u64, 0x08, 0, 0x8E);
        IDT[11] = IdtEntry::new(segment_not_present_entry as u64, 0x08, 0, 0x8E);
        IDT[12] = IdtEntry::new(stack_segment_entry as u64, 0x08, 0, 0x8E);
        IDT[13] = IdtEntry::new(general_protection_fault_handler as u64, 0x08, 0, 0x8E);
        // Phase 25: page_fault_entry passes CR2, the error code and the
        // saved CS/RIP to the typed handler.
        IDT[14] = IdtEntry::new(page_fault_entry as u64, 0x08, 0, 0x8E);
        IDT[16] = IdtEntry::new(x87_floating_point_entry as u64, 0x08, 0, 0x8E);
        IDT[17] = IdtEntry::new(alignment_check_entry as u64, 0x08, 0, 0x8E);
        IDT[18] = IdtEntry::new(machine_check_entry as u64, 0x08, 0, 0x8E);
        IDT[19] = IdtEntry::new(simd_floating_point_entry as u64, 0x08, 0, 0x8E);
        IDT[20] = IdtEntry::new(virtualization_entry as u64, 0x08, 0, 0x8E);
    }
}

/// Typed tail of `cpu_exception_entry!`. A user-mode fault on a delivered vector becomes a
/// `UserException { number: vector, code: error_code }` for the thread's fault handler
/// (upstream handleUserLevelFault), and the CPU moves on to the next runnable thread: returning
/// would re-execute the faulting instruction. Everything else is fatal.
extern "C" fn handle_cpu_exception(error_code: u64, vector: u64, saved_rip: u64, saved_cs: u64) -> ! {
    let from_user = (saved_cs & 3) == 3;
    if !from_user || !vector::delivers_user_exception(vector) {
        crate::arch::log("EXCEPTION: ");
        crate::arch::log(vector::name(vector));
        crate::arch::log(if from_user { " (user mode)\n" } else { " (kernel mode)\n" });
        fatal_exception(vector, error_code, saved_rip);
    }
    acquire_user_fault_entry();
    let Some(faulter) = crate::arch::x86_64::syscall_entry::resolve_live_user_thread() else {
        // Same race as the #PF no-current path: another CPU blocked
        // us mid-flight. Dispatch whatever is runnable.
        unsafe { dispatch_next_or_idle("[user CPU exception: no current, idling CPU]\n") }
    };
    unsafe {
        // Mirror the per-CPU snapshot (full fault-time state) into
        // the faulter and mark iretq resume.
        let snapshot = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
        let s = crate::kernel::KERNEL.get();
        let t = s.scheduler.slab.get_mut(faulter);
        t.user_context = snapshot;
        t.use_iretq_resume = true;
        if crate::fault::deliver_fault(
            faulter,
            crate::fault::FaultMessage::UserException { number: vector as u32, code: error_code as u32 },
        )
        .is_err()
        {
            crate::arch::log("[user ");
            crate::arch::log(vector::name(vector));
            crate::arch::log(": tcb=");
            log_dec_u64(faulter.0 as u64);
            crate::arch::log(" rip=0x");
            log_hex64(saved_rip);
            crate::arch::log(" err=0x");
            log_hex64(error_code);
            crate::arch::log(" — no fault handler, suspending thread]\n");
            s.scheduler
                .block(faulter, crate::tcb::ThreadStateType::Inactive);
        }
        dispatch_next_or_idle("[user CPU exception: no next thread, idling CPU]\n")
    }
}

/// Custom #NM (Device Not Available, vector 7) entry. CPU pushes no
/// error code for this vector. We need both the saved CS / RIP (to
/// decide whether the trap came from user mode, CPL=3) AND the user
/// GPRs (so the faulter can resume cleanly after the fault handler
/// replies — without saving, sysretq would restore stale registers
/// from the last syscall save and the helper page-faults on return).
///
/// Stack on entry (no error code from CPU):
///   [rsp+0]  = saved RIP
///   [rsp+8]  = saved CS
///   [rsp+16] = saved RFLAGS
///   [rsp+24] = saved RSP
///   [rsp+32] = saved SS
///
/// We assume #NM only ever fires from user mode — kernel never sets
/// CR0.TS for itself; the gate is applied just before sysretq for
/// `fpuDisabled` threads. So we always `swapgs`. If a kernel-mode
/// #NM ever fires, the handler logs and clears TS defensively, and
/// the asm tail restores the (mostly-stale) GPRs before iretq.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn device_not_available_entry() {
    core::arch::naked_asm!(
        // Switch to kernel GS_BASE so gs:[16+...] addresses the
        // per-CPU UserContext save slot.
        "swapgs",
        // Save user GPRs into per-CPU user_ctx (same layout the
        // syscall entry uses — see UserContext).
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
        // Stamp the iretq frame's saved RIP / RFLAGS / RSP into the
        // DEDICATED user_ctx slots (iretq-flavor), leaving the TRUE rcx /
        // r11 saved above intact — matching page_fault_entry /
        // invalid_opcode_entry. The handler marks the faulter
        // use_iretq_resume=true, so resume_ip must read user_ctx.rip
        // (not rcx). The old sysret-flavor stamp (rcx=RIP) was masked by
        // the dispatch clearing use_iretq_resume; once that clear was
        // removed it left the #NM context inconsistent (FPU0004).
        "mov rax, [rsp + 0]",
        "mov gs:[16 + 128], rax",   // user_ctx.rip    = saved RIP
        "mov rax, [rsp + 16]",
        "mov gs:[16 + 136], rax",   // user_ctx.rflags = saved RFLAGS
        "mov rax, [rsp + 24]",
        "mov gs:[16 + 120], rax",   // user_ctx.rsp    = saved RSP
        // Call the typed Rust handler with (saved_rip, saved_cs).
        // Stack stays on the IDT-pushed kernel stack (TSS RSP0 for
        // user-mode entry). Plenty of room for one C call.
        "mov rdi, [rsp + 0]",
        "mov rsi, [rsp + 8]",
        // The five-word hardware frame leaves RSP eight bytes short of call alignment.
        "sub rsp, 8",
        "call {handler}",
        "add rsp, 8",
        // Handler returns only on the spurious-TS / kernel-mode
        // path. Restore GPRs from the per-CPU snapshot, swapgs
        // back, and iretq.
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
        "swapgs",
        "iretq",
        handler = sym handle_device_not_available_typed,
    );
}

extern "C" fn handle_device_not_available_typed(saved_rip: u64, saved_cs: u64) {
    // CPL is the low 2 bits of CS. User mode = 3.
    let from_user = (saved_cs & 3) == 3;
    if !from_user {
        // Kernel-mode #NM is unexpected (we only set CR0.TS just
        // before sysretq). Clear and proceed defensively rather
        // than panic.
        unsafe {
            crate::arch::x86_64::syscall_entry::set_cr0_ts(false);
        }
        return;
    }

    // User-mode #NM: retain the exact entry before waiting for BKL.
    acquire_user_fault_entry();
    let _bkl = BklGuard;

    let current = match crate::arch::x86_64::syscall_entry::resolve_live_user_thread() {
        Some(c) => c,
        None => {
            // No current thread — shouldn't happen from user
            // mode but be defensive.
            unsafe {
                crate::arch::x86_64::syscall_entry::set_cr0_ts(false);
            }
            return;
        }
    };
    unsafe {
        let s = crate::kernel::KERNEL.get();
        const FPU_DISABLED: u64 = 0x1;
        let flags = s.scheduler.slab.get(current).flags;
        if (flags & FPU_DISABLED) == 0 {
            // Spurious TS — thread isn't actually disabled, just
            // clear and resume. This shouldn't normally fire (we
            // only set TS for fpuDisabled threads) but tolerate it.
            crate::arch::x86_64::syscall_entry::set_cr0_ts(false);
            return;
        }

        // Real fpuDisabled trap. Mirror the per-CPU UserContext
        // snapshot the asm stub just stamped (saved RIP/RFLAGS/RSP
        // already in there) into the faulter's TCB so the resume
        // path sees the right state — without this, sysretq would
        // restore from whatever was saved on the last syscall and
        // the helper page-faults on return from the fault reply.
        let pcc_snapshot = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
        s.scheduler.slab.get_mut(current).user_context = pcc_snapshot;
        let _ = saved_rip; // already in pcc_snapshot.rcx
        let _ = crate::fault::deliver_fault(
            current,
            crate::fault::FaultMessage::UserException { number: 7, code: 0 },
        );

        // The faulter is now BlockedOnReply (or suspended if no
        // handler). iretq'ing back to it would re-execute the FPU
        // instruction. Context-switch to the next runnable thread
        // by sysretq'ing into it directly — same pattern the page
        // fault handler uses. Drop the BKL just before sysretq.
        let candidate = s.scheduler.choose_thread();
        let next = debug_ready_thread(s, candidate);
        if let Some(next_id) = next {
            s.scheduler.set_current(Some(next_id));
            s.scheduler.set_active_user(Some(next_id));
            let tcb = s.scheduler.slab.get(next_id);
            let next_cr3 = tcb.vm_root_cr3();
            let next_fs_base = tcb.cpu_context.fs_base;
            let next_gs_base = tcb.cpu_context.gs_base;
            let next_ctx = tcb.user_context;
            if next_cr3 != 0 {
                let cur_cr3: u64;
                core::arch::asm!("mov {}, cr3", out(reg) cur_cr3,
                    options(nomem, nostack, preserves_flags));
                if next_cr3 != cur_cr3 {
                    crate::smp::load_root(next_cr3);
                }
            }
            crate::arch::x86_64::msr::wrmsr(crate::arch::x86_64::msr::IA32_FS_BASE, next_fs_base);
            crate::arch::x86_64::msr::wrmsr(
                crate::arch::x86_64::msr::IA32_KERNEL_GS_BASE,
                next_gs_base,
            );
            crate::arch::x86_64::fpu_ctx::fpu_switch_to(&mut s.scheduler.slab, next_id);
            crate::arch::x86_64::syscall_entry::apply_fpu_gate_for(s.scheduler.slab.get(next_id));
            crate::arch::x86_64::syscall_entry::apply_debug_state_for(
                s.scheduler.slab.get(next_id),
            );
            let pcc = crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
            *pcc = next_ctx;
            // Honour use_iretq_resume on this resume path too. Don't clear
            // it — it tracks the save flavor (see swap_iretq_context...).
            if s.scheduler.slab.get(next_id).use_iretq_resume {
                drop(_bkl);
                crate::arch::x86_64::syscall_entry::enter_user_via_iretq(pcc as *const _);
            }
            // Release BKL via Drop on _bkl, then sysret.
            drop(_bkl);
            crate::arch::x86_64::syscall_entry::enter_user_via_sysret(pcc as *const _);
            // unreachable
        }
        // No runnable thread — idle this CPU until an IRQ wakes it.
        crate::arch::log("[#NM: no next thread, idling CPU]\n");
        // SMP: flush live FPU state to its owner TCB before idling so a
        // migration off this idle core restores fresh state.
        crate::arch::x86_64::fpu_ctx::flush_local_fpu(&mut s.scheduler.slab);
        s.scheduler.set_active_user(None);
        drop(_bkl);
        loop {
            core::arch::asm!("sti", "hlt");
        }
    }
}

/// Idle tags are reported on first sighting and every `REPORT_EVERY`th time after.
static IDLE_LOG: crate::idle_log_budget::IdleLogBudget = crate::idle_log_budget::IdleLogBudget::new();

/// Print an admitted idle tag with its running count. Called with the BKL released: a
/// serial line is one VM exit per byte, and no other CPU should wait behind it.
fn log_idle_tag(tag: &str, count: u64) {
    crate::arch::log(tag.strip_suffix('\n').unwrap_or(tag));
    if count > 1 {
        crate::arch::log(" seen=0x");
        crate::invocation::log_hex_u64(count);
    }
    crate::arch::log("\n");
}

/// Dispatch the next runnable thread or idle in HLT. Shared tail
/// for exception handlers that just blocked the current thread
/// (fault delivery): returning via iretq would re-execute the
/// faulting instruction, so we sysret/iretq into the next thread
/// instead. Caller must hold the BKL — released here just before
/// user entry / idle.
pub(crate) unsafe fn dispatch_next_or_idle(idle_tag: &str) -> ! {
    let s = crate::kernel::KERNEL.get();
    // Re-dispatch after every idle wake. Under the domain scheduler
    // the CPU idles whenever the current domain has no runnable
    // thread; the next timer tick advances `ksDomScheduleIdx` and a
    // thread in the new domain becomes eligible, so we must re-run
    // choose_thread rather than hlt forever (which would strand every
    // thread once the schedule rotated away from a non-empty domain).
    let mut logged = false;
    loop {
        let candidate = s.scheduler.choose_thread();
        if let Some(next_id) = debug_ready_thread(s, candidate) {
            s.scheduler.set_current(Some(next_id));
            s.scheduler.set_active_user(Some(next_id));
            crate::sched_context::complete_yield_if_pending(next_id);
            let tcb = s.scheduler.slab.get(next_id);
            let next_cr3 = tcb.vm_root_cr3();
            let next_fs_base = tcb.cpu_context.fs_base;
            let next_gs_base = tcb.cpu_context.gs_base;
            let next_ctx = tcb.user_context;
            if next_cr3 != 0 {
                // SMP: if this core went idle since its last dispatch, reload
                // CR3 unconditionally to flush a possibly-stale TLB. While
                // idle, `shootdown_tlb` skipped this core, so another core
                // may have mutated the shared page tables underneath it
                // (MULTICORE0002 — a migrated thread saw stale code/stack
                // pages and ran wild). When NOT coming from idle, only reload
                // on an actual vspace change — flushing every dispatch makes
                // the yield-stress test crawl (MULTICORE0004).
                let was_idle = crate::smp::take_went_idle();
                let cur_cr3: u64;
                core::arch::asm!("mov {}, cr3", out(reg) cur_cr3,
                options(nomem, nostack, preserves_flags));
                if was_idle || next_cr3 != cur_cr3 {
                    crate::smp::load_root(next_cr3);
                }
            }
            crate::arch::x86_64::msr::wrmsr(crate::arch::x86_64::msr::IA32_FS_BASE, next_fs_base);
            // Restore the per-thread user %gs base into the swapped-out MSR so the resume's tail
            // `swapgs` lands this thread's TEB in %gs (Windows gs:[0x30]) — mirrors the sysret-tail
            // dispatch. Without this, resuming via this path (fault/int-0x2d) drops the TEB gs base.
            crate::arch::x86_64::msr::wrmsr(
                crate::arch::x86_64::msr::IA32_KERNEL_GS_BASE,
                next_gs_base,
            );
            crate::arch::x86_64::fpu_ctx::fpu_switch_to(&mut s.scheduler.slab, next_id);
            crate::arch::x86_64::syscall_entry::apply_fpu_gate_for(s.scheduler.slab.get(next_id));
            crate::arch::x86_64::syscall_entry::apply_debug_state_for(
                s.scheduler.slab.get(next_id),
            );
            let pcc = crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
            *pcc = next_ctx;
            if s.scheduler.slab.get(next_id).use_iretq_resume {
                crate::smp::bkl_release();
                crate::arch::x86_64::syscall_entry::enter_user_via_iretq(pcc as *const _);
            }
            crate::smp::bkl_release();
            crate::arch::x86_64::syscall_entry::enter_user_via_sysret(pcc as *const _);
        }
        let report = if logged { None } else { IDLE_LOG.admit(idle_tag) };
        logged = true;
        // Flush before idle so migration need not wake this CPU to capture
        // its last resident FPU owner's hardware state.
        crate::arch::x86_64::fpu_ctx::flush_local_fpu(&mut s.scheduler.slab);
        s.scheduler.set_active_user(None);
        // Idle: drop the lock so the timer ISR can run, halt until an
        // interrupt, then re-acquire and loop back to choose_thread.
        // Mark went-idle so the next dispatch flushes a possibly-stale TLB.
        // Park on the kernel root page table first — a user vspace left in
        // CR3 here can be freed by another core's teardown, after which our
        // next interrupt would read an unmapped IDT and triple-fault.
        crate::arch::x86_64::paging::park_on_kernel_root();
        crate::smp::mark_went_idle();
        crate::smp::bkl_release();
        if let Some(count) = report {
            log_idle_tag(idle_tag, count);
        }
        // `cli` after `hlt`: restore the kernel's IF=0 invariant before the
        // BKL-held re-acquire + loop-back below, so the timer IRQ can't
        // re-enter bkl_acquire while we hold the lock (the silent DOMAINS
        // hang — see the syscall idle loop in syscall_entry.rs).
        core::arch::asm!("sti", "hlt", "cli");
        crate::smp::bkl_acquire();
    }
}

/// Resume the current user thread directly after an observation-only fault.
///
/// The CPU reached this code through a user exception entry that already saved
/// the full user context and swapped into the kernel GS regime. Unlike a real
/// user fault, DebugService must not become a scheduling boundary: debug output
/// is not IPC and must not strand a loader callout between a diagnostic trap and
/// the instruction that publishes real process state.
unsafe fn resume_current_user_via_iretq(current: crate::tcb::TcbId) -> ! {
    let s = crate::kernel::KERNEL.get();
    s.scheduler.set_current(Some(current));
    s.scheduler.set_active_user(Some(current));
    crate::sched_context::complete_yield_if_pending(current);
    let tcb = s.scheduler.slab.get(current);
    let next_cr3 = tcb.vm_root_cr3();
    let next_fs_base = tcb.cpu_context.fs_base;
    let next_gs_base = tcb.cpu_context.gs_base;
    let next_ctx = tcb.user_context;
    if next_cr3 != 0 {
        let cur_cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cur_cr3,
            options(nomem, nostack, preserves_flags));
        if next_cr3 != cur_cr3 {
            crate::smp::load_root(next_cr3);
        }
    }
    crate::arch::x86_64::msr::wrmsr(crate::arch::x86_64::msr::IA32_FS_BASE, next_fs_base);
    crate::arch::x86_64::msr::wrmsr(crate::arch::x86_64::msr::IA32_KERNEL_GS_BASE, next_gs_base);
    crate::arch::x86_64::syscall_entry::apply_fpu_gate_for(s.scheduler.slab.get(current));
    crate::arch::x86_64::syscall_entry::apply_debug_state_for(s.scheduler.slab.get(current));
    let pcc = crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
    *pcc = next_ctx;
    crate::smp::bkl_release();
    crate::arch::x86_64::syscall_entry::enter_user_via_iretq(pcc as *const _);
}

/// #GP (General Protection, vector 13) entry. The CPU pushes an
/// error code, so the frame is offset by 8 vs the #UD entry:
///   [rsp+0]  = error_code
///   [rsp+8]  = saved RIP
///   [rsp+16] = saved CS
///   [rsp+24] = saved RFLAGS
///   [rsp+32] = saved RSP
///   [rsp+40] = saved SS
///
/// A user-mode #GP (e.g. an unprivileged `in`/`out` without an IO-port
/// cap — IOPORTS1000) is delivered to the thread's fault handler as a
/// UserException, the same way #UD is. Kernel-mode #GP stays fatal.
/// Same full fault-time capture as #UD/#PF (true rcx/r11 in the GPR
/// slots; RIP/RFLAGS/RSP in the iretq slots).
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn general_protection_fault_handler() {
    core::arch::naked_asm!(
        "test byte ptr [rsp + 16], 3",
        "jz 2f",
        // -------- user-mode #GP: full save --------
        "swapgs",
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
        "mov rax, [rsp + 8]",
        "mov gs:[16 + 128], rax",   // user_ctx.rip    = saved RIP
        "mov rax, [rsp + 24]",
        "mov gs:[16 + 136], rax",   // user_ctx.rflags = saved RFLAGS
        "mov rax, [rsp + 32]",
        "mov gs:[16 + 120], rax",   // user_ctx.rsp    = saved RSP
        "mov rdi, [rsp + 0]",       // error_code
        "mov rsi, [rsp + 16]",      // saved CS
        "mov rdx, [rsp + 8]",       // saved RIP
        "mov rcx, [rsp + 32]",      // saved RSP
        "call {handler}",
        // Unreachable for user faults; defensive restore + return.
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
        "swapgs",
        "add rsp, 8",               // pop error code
        "iretq",
        // -------- kernel-mode #GP: fatal --------
        "2:",
        "mov rdi, [rsp + 0]",       // error_code
        "mov rsi, [rsp + 16]",      // saved CS
        "mov rdx, [rsp + 8]",       // saved RIP
        "mov rcx, [rsp + 32]",      // saved RSP
        "call {handler}",
        "add rsp, 8",
        "iretq",
        handler = sym handle_general_protection_fault_typed,
    );
}

extern "C" fn handle_general_protection_fault_typed(
    error_code: u64,
    saved_cs: u64,
    saved_rip: u64,
    saved_rsp: u64,
) {
    let from_user = (saved_cs & 3) == 3;
    if !from_user {
        crate::arch::log("EXCEPTION: kernel general protection fault, err=0x");
        log_hex64(error_code);
        crate::arch::log(" rip=0x");
        log_hex64(saved_rip);
        crate::arch::log(" rsp=0x");
        log_hex64(saved_rsp);
        crate::arch::log(" cpu=0x");
        log_hex64(crate::arch::get_cpu_id() as u64);
        crate::arch::log("\n");
        let current_rsp: u64;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nostack, nomem));
        }
        if error_code == 0x20
            && saved_rip == super::lapic::timer_irq_iretq_site()
            && saved_rsp & 7 == 0
            && saved_rsp >= 0xffff_8000_0000_0000
            && saved_rsp <= u64::MAX - 5 * 8
            && saved_rsp >= current_rsp
            && saved_rsp - current_rsp <= 4096
        {
            let frame = saved_rsp as *const u64;
            crate::arch::log("  attempted iretq rip/cs/rflags/rsp/ss:");
            for index in 0..5 {
                crate::arch::log(" 0x");
                log_hex64(unsafe { core::ptr::read_volatile(frame.add(index)) });
            }
            crate::arch::log("\n  gdtr base=0x");
            let (base, limit, descriptors) = super::gdt::live_user_descriptors();
            log_hex64(base);
            crate::arch::log(" limit=0x");
            log_hex64(limit as u64);
            if let Some((user_ds, user_cs)) = descriptors {
                crate::arch::log(" user_ds=0x");
                log_hex64(user_ds);
                crate::arch::log(" user_cs=0x");
                log_hex64(user_cs);
            }
            crate::arch::log("\n");
        }
        fatal_exception(vector::GENERAL_PROTECTION, error_code, saved_rip);
    }
    acquire_user_fault_entry();
    let current = crate::arch::x86_64::syscall_entry::resolve_live_user_thread();
    let Some(faulter) = current else {
        unsafe { dispatch_next_or_idle("[#GP: no current, idling CPU]\n") }
    };
    // `int 0x2d` — the x86 DebugService interrupt, which the CPU raises as a #GP (no IDT gate)
    // with error code (0x2d << 3) | 2 = 0x16a. The DEBUG-build ntdll uses it for DbgPrint and,
    // in RtlAssert, DbgPrompt ("Break/Ignore/Terminate/Pass?"). We act as the attached kernel
    // debugger: PRINT (EAX=1) forwards the message string (RCX=ptr, RDX=len) to the kernel serial
    // log as `[dbg] ...` — invaluable for bringing up a real ntdll loader, whose DPRINT1s report
    // exactly why process init fails; PROMPT (EAX=2) answers 'Ignore' into the response buffer
    // (RCX). Then skip past `int 0x2d; int3` (3 bytes) and RESUME the thread (no fault delivered).
    // This keeps assertions from spinning forever.
    if is_debug_service_gp(error_code) {
        unsafe {
            let snapshot = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
            let s = crate::kernel::KERNEL.get();
            let t = s.scheduler.slab.get_mut(faulter);
            t.user_context = snapshot;
            let service = t.user_context.rax & 0xFFFF_FFFF;
            if service == 1 {
                let ptr = t.user_context.rcx;
                let len = (t.user_context.rdx as usize).min(240);
                if ptr != 0 {
                    let started = super::debug_output_cost::start();
                    let mut message_bytes = 0usize;
                    crate::arch::log("[dbg] ");
                    for i in 0..len {
                        let c = core::ptr::read_volatile((ptr as *const u8).add(i));
                        if c == 0 {
                            break;
                        }
                        let ch = [if (0x20..0x7f).contains(&c) || c == b'\n' {
                            c
                        } else {
                            b'.'
                        }];
                        if let Ok(sst) = core::str::from_utf8(&ch) {
                            crate::arch::log(sst);
                            message_bytes += 1;
                        }
                    }
                    crate::arch::log("\n");
                    super::debug_output_cost::finish(
                        super::debug_output_cost::Channel::DebugService,
                        started,
                        message_bytes + b"[dbg] \n".len(),
                    );
                }
            }
            if service == 2 {
                // BREAKPOINT_PROMPT (RtlAssert's "Break/Ignore/…?"). The x64 DebugService ABI at
                // int 0x2d is (eax=service, rcx=Prompt.Buffer, edx=Prompt.Length, r8=Response.Buffer,
                // r9=Response.Length) — verified by disassembling ntdll DbgPrompt. Answer 'Ignore'
                // into the RESPONSE buffer (R8, NOT rcx which is the read-only prompt string) so
                // RtlAssert reads it and returns; writing rcx left the response unset and RtlAssert
                // re-prompted forever (a failing assert spun the whole process).
                let buf = t.user_context.r8;
                if buf != 0 {
                    core::ptr::write_volatile(buf as *mut u8, b'I');
                }
                t.user_context.rax = 1; // one char returned
            } else {
                t.user_context.rax = 0;
            }
            t.user_context.rip = debug_service_resume_ip(t.user_context.rip);
            t.use_iretq_resume = true;
            if t.is_runnable() {
                resume_current_user_via_iretq(faulter);
            }
            dispatch_next_or_idle("[int 0x2d: no runnable current, idling CPU]\n")
        }
    }
    unsafe {
        let snapshot = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
        let s = crate::kernel::KERNEL.get();
        let t = s.scheduler.slab.get_mut(faulter);
        t.user_context = snapshot;
        t.use_iretq_resume = true;
        // UserException(number = 13 = #GP vector, code = error_code) —
        // mirrors upstream handleUserLevelFault for a user GP fault.
        // IOPORTS1000's handler only checks the label is UserException,
        // advances RIP past the faulting `in`, and resumes.
        if crate::fault::deliver_fault(
            faulter,
            crate::fault::FaultMessage::UserException {
                number: 13,
                code: error_code as u32,
            },
        )
        .is_err()
        {
            crate::arch::log("[user #GP: tcb=");
            log_dec_u64(faulter.0 as u64);
            crate::arch::log(" err=0x");
            log_hex64(error_code);
            crate::arch::log(" rip=0x");
            log_hex64(snapshot.rip);
            crate::arch::log(" rsp=0x");
            log_hex64(snapshot.rsp);
            crate::arch::log(" rax=0x");
            log_hex64(snapshot.rax);
            crate::arch::log(" rcx=0x");
            log_hex64(snapshot.rcx);
            crate::arch::log(" r11=0x");
            log_hex64(snapshot.r11);
            crate::arch::log("]\n");
            crate::fault::log_fault_handler_state(faulter);
            crate::arch::log("[#GP: no fault handler — suspending thread]\n");
            s.scheduler
                .block(faulter, crate::tcb::ThreadStateType::Inactive);
        }
        dispatch_next_or_idle("[#GP: no next thread, idling CPU]\n")
    }
}

// ---------------------------------------------------------------------------
// Phase 25 — proper page-fault entry that routes user faults
// through deliver_fault.
//
// A focused stub that:
//   1. captures CR2 + error code + saved CS into the right argument
//      registers
//   2. calls the Rust handler
//   3. cleans up and iretq's
// ---------------------------------------------------------------------------

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn page_fault_entry() {
    core::arch::naked_asm!(
        // Stack on entry from a #PF (vector 14):
        //   [rsp+0]  = error_code   (CPU pushed)
        //   [rsp+8]  = saved RIP
        //   [rsp+16] = saved CS
        //   [rsp+24] = saved RFLAGS
        //   [rsp+32] = saved RSP
        //   [rsp+40] = saved SS
        //
        // For USER-mode faults (CPL=3 in saved CS) we capture the
        // complete fault-time register state into the per-CPU
        // UserContext — the PAGEFAULT tests' handler thread does
        // seL4_TCB_ReadRegisters on the fault-blocked thread and
        // expects fault-time rax (BAD_MAGIC check), and the faulter
        // must be resumable at the exact fault point. Unlike the
        // SYSCALL path, rcx/r11 here are REAL user registers (not
        // RIP/RFLAGS stand-ins): the saved RIP/RFLAGS go to the
        // dedicated .rip/.rflags iretq slots and the typed handler
        // marks the faulter `use_iretq_resume`.
        "test byte ptr [rsp + 16], 3",
        "jz 2f",
        // -------- user-mode fault: full save --------
        "swapgs",
        "mov gs:[16 + 0],   rax",
        "mov gs:[16 + 8],   rbx",
        "mov gs:[16 + 16],  rcx",   // TRUE rcx
        "mov gs:[16 + 24],  rdx",
        "mov gs:[16 + 32],  rsi",
        "mov gs:[16 + 40],  rdi",
        "mov gs:[16 + 48],  rbp",
        "mov gs:[16 + 56],  r8",
        "mov gs:[16 + 64],  r9",
        "mov gs:[16 + 72],  r10",
        "mov gs:[16 + 80],  r11",   // TRUE r11
        "mov gs:[16 + 88],  r12",
        "mov gs:[16 + 96],  r13",
        "mov gs:[16 + 104], r14",
        "mov gs:[16 + 112], r15",
        "mov rax, [rsp + 8]",
        "mov gs:[16 + 128], rax",   // user_ctx.rip    = saved RIP
        "mov rax, [rsp + 24]",
        "mov gs:[16 + 136], rax",   // user_ctx.rflags = saved RFLAGS
        "mov rax, [rsp + 32]",
        "mov gs:[16 + 120], rax",   // user_ctx.rsp    = saved RSP
        // System V ABI for the Rust handler:
        //   rdi = CR2, rsi = error code, rdx = saved CS,
        //   rcx = saved RIP (for fault msgs / logging)
        "mov rdi, cr2",
        "mov rsi, [rsp]",
        "mov rdx, [rsp + 16]",
        "mov rcx, [rsp + 8]",
        "call {handler}",
        // The handler never returns for user faults (it sysrets /
        // iretqs into the next thread or idles). Defensive tail:
        // restore the snapshot and iretq back.
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
        "swapgs",
        "add rsp, 8",
        "iretq",
        // -------- kernel-mode fault: fatal path, no gs swap --------
        "2:",
        "mov rdi, cr2",
        "mov rsi, [rsp]",
        "mov rdx, [rsp + 16]",
        "mov rcx, [rsp + 8]",
        "call {handler}",
        "add rsp, 8",
        "iretq",
        handler = sym handle_page_fault_typed,
    );
}

#[no_mangle]
extern "C" fn handle_page_fault_typed(cr2: u64, error_code: u64, saved_cs: u64, saved_rip: u64) {
    // Phase 28b / 42 — BKL across the fault handler. Fault delivery
    // touches the kernel scheduler + fault EP cap chain, all of
    // which are shared kernel state.
    //
    // We DON'T use BklGuard here. The handler has multiple exit
    // paths that don't return through this function (sysret into
    // a freshly-dispatched thread, infinite hlt loop), and the
    // RAII guard's Drop never fires on those — leaving the BKL
    // held forever and deadlocking peer CPUs in `bkl_acquire`.
    // Each early-exit path calls `bkl_release()` explicitly below.
    let user_mode = (saved_cs & 3) == 3;
    if user_mode { acquire_user_fault_entry(); } else { crate::smp::bkl_acquire(); }
    if !user_mode {
        crate::arch::log("KERNEL PAGE FAULT @ rip=0x");
        log_hex64(saved_rip);
        crate::arch::log(", cr2=0x");
        log_hex64(cr2);
        crate::arch::log(", err=0x");
        log_hex64(error_code);
        crate::arch::log("\nfatal — halting\n");
        crate::smp::bkl_release();
        #[cfg(any(feature = "spec", feature = "extern-rootserver"))]
        crate::arch::qemu_exit(255);
        #[cfg(not(any(feature = "spec", feature = "extern-rootserver")))]
        loop {
            unsafe {
                core::arch::asm!("hlt");
            }
        }
    }

    // User-mode page fault — try to deliver to the thread's
    // fault handler. If delivery fails (no handler / bad cap),
    // we kill the thread by parking it Inactive.
    let fault_count = USER_PAGE_FAULT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    #[cfg(not(feature = "trace-user-page-faults"))]
    if fault_count % 4096 == 0 {
        crate::arch::log("[user #PF count: ");
        log_hex64(fault_count);
        crate::arch::log("]\n");
    }
    #[cfg(feature = "trace-user-page-faults")]
    let _ = fault_count;
    let current = crate::arch::x86_64::syscall_entry::resolve_live_user_thread();
    if current.is_none() {
        // We took a user-mode #PF before this CPU had a published user-entry
        // owner. Don't refault forever; dispatch whatever is runnable.
        log_user_page_fault(None, cr2, error_code, saved_rip);
        unsafe { dispatch_next_or_idle("[USER #PF no current, no runnable — idle]\n") }
    }
    let faulter = current.unwrap();
    // The entry stub captured the complete fault-time register
    // state (true rcx/r11; RIP/RFLAGS/RSP in the dedicated iretq
    // slots) into the per-CPU UserContext. Mirror it into the
    // faulter's TCB and flag iretq resume so:
    //   * ReadRegisters returns fault-time registers (the fault
    //     tests assert rax == BAD_MAGIC),
    //   * a later resume (fault reply / WriteRegisters) re-enters
    //     at the exact fault point with all GPRs intact.
    unsafe {
        let snapshot = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
        let t = crate::kernel::KERNEL.get().scheduler.slab.get_mut(faulter);
        t.user_context = snapshot;
        t.use_iretq_resume = true;
    }
    let fault = crate::fault::FaultMessage::VMFault {
        addr: cr2,
        fsr: error_code,
        instruction: (error_code & (1 << 4)) != 0,
    };
    #[cfg(feature = "trace-user-page-faults")]
    log_user_page_fault(Some(faulter), cr2, error_code, saved_rip);
    let suspended = if crate::fault::deliver_fault(faulter, fault).is_err() {
        #[cfg(not(feature = "trace-user-page-faults"))]
        log_user_page_fault(Some(faulter), cr2, error_code, saved_rip);
        crate::arch::log("[no fault handler — suspending thread]\n");
        unsafe {
            crate::kernel::KERNEL
                .get()
                .scheduler
                .block(faulter, crate::tcb::ThreadStateType::Inactive);
        }
        true
    } else {
        // deliver_fault blocks the faulter on the fault EP and may
        // wake the handler. Either way the faulter is no longer
        // current.
        true
    };

    // If we just blocked the faulter, iretq would dump us back
    // into its now-unmapped page and refault forever (and on the
    // refault `current` would be None → the no-current path
    // halts this CPU). Pick the next runnable thread and enter it
    // directly, bypassing iretq.
    if suspended {
        unsafe { dispatch_next_or_idle("[user #PF: no next thread, idling CPU]\n") }
    }
    // (suspended is always true above; this branch is dead but kept
    // for clarity should the deliver_fault path change.)
}

// ---------------------------------------------------------------------------
// Hardware-debug exceptions (CONFIG_HARDWARE_DEBUG_API).
//
// #DB (vector 1) and INT3/#BP (vector 3) push NO error code. Like the
// #PF path we capture the full user register state (a #DB can preempt
// any instruction) into the per-CPU UserContext so the debug-fault
// handler can ReadRegisters and the thread is resumable.
// ---------------------------------------------------------------------------

include!("exceptions/deferred_debug.rs");

macro_rules! debug_entry_asm {
    ($handler:path) => {
        core::arch::naked_asm!(
            // Stack (no error code):
            //   [rsp+0]=RIP [rsp+8]=CS [rsp+16]=RFLAGS [rsp+24]=RSP
            "test byte ptr [rsp + 8], 3",
            "jz 2f",
            "swapgs",
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
            "mov rax, [rsp + 0]",
            "mov gs:[16 + 128], rax",   // rip
            "mov rax, [rsp + 16]",
            "mov gs:[16 + 136], rax",   // rflags
            "mov rax, [rsp + 24]",
            "mov gs:[16 + 120], rax",   // rsp
            "mov rdi, [rsp + 8]",       // saved CS
            "mov rsi, [rsp + 0]",       // saved RIP
            "sub rsp, 8",
            "call {handler}",
            "add rsp, 8",
            // Defensive tail (handler normally dispatches away).
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
            "swapgs",
            "iretq",
            // kernel-mode debug exception: just hand to the typed
            // handler (it clears DR6 and returns) then iretq.
            "2:",
            "mov rdi, [rsp + 8]",
            "mov rsi, [rsp + 0]",
            "sub rsp, 8",
            "call {handler}",
            "add rsp, 8",
            "iretq",
            handler = sym $handler,
        )
    };
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn debug_exception_entry() {
    debug_entry_asm!(handle_debug_typed);
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn int3_entry() {
    debug_entry_asm!(handle_int3_typed);
}

/// Snapshot the captured user context into the faulting thread's TCB so
/// ReadRegisters sees the debug-time state and the thread resumes at the
/// exact point. Mirrors the #PF path.
unsafe fn snapshot_into_tcb(faulter: crate::tcb::TcbId) {
    let snapshot = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
    let t = crate::kernel::KERNEL.get().scheduler.slab.get_mut(faulter);
    t.user_context = snapshot;
    t.use_iretq_resume = true;
}

#[no_mangle]
extern "C" fn handle_debug_typed(saved_cs: u64, saved_rip: u64) {
    use crate::arch::x86_64::debug;
    debug::hardware_changed_live_registers();
    if (saved_cs & 3) != 3 {
        // Kernel-mode #DB — clear status and resume.
        unsafe {
            debug::write_dr6(0xFFFF_0FF0);
        }
        return;
    }
    let status = unsafe { debug::read_dr6() };
    unsafe { debug::write_dr6(0xFFFF_0FF0); }
    let context = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
    assert_eq!(context.rip, saved_rip);
    let kind = crate::smp::UserEntryKind::Debug { status };
    if crate::smp::bkl_acquire_for_user_entry(Some(crate::smp::UserEntrySnapshot { context, kind })) {
        unsafe { dispatch_next_or_idle("[#DB quiesced]\n") }
    }
    let faulter = match crate::arch::x86_64::syscall_entry::resolve_live_user_thread() {
        Some(t) => t,
        None => unsafe { dispatch_next_or_idle("[#DB no current]\n") },
    };
    unsafe {
        snapshot_into_tcb(faulter);
    }
    let s = unsafe { crate::kernel::KERNEL.get() };
    defer_quiesced_debug(s.scheduler.slab.get_mut(faulter), kind);
    deliver_deferred_debug(s, faulter);
    unsafe { dispatch_next_or_idle("[#DB]\n") }
}

#[no_mangle]
extern "C" fn handle_int3_typed(saved_cs: u64, saved_rip: u64) {
    if (saved_cs & 3) != 3 {
        crate::arch::log("KERNEL INT3\n");
        return;
    }
    let context = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
    assert_eq!(context.rip, saved_rip);
    let kind = crate::smp::UserEntryKind::Breakpoint;
    if crate::smp::bkl_acquire_for_user_entry(Some(crate::smp::UserEntrySnapshot { context, kind })) {
        unsafe { dispatch_next_or_idle("[INT3 quiesced]\n") }
    }
    let faulter = match crate::arch::x86_64::syscall_entry::resolve_live_user_thread() {
        Some(t) => t,
        None => unsafe { dispatch_next_or_idle("[INT3 no current]\n") },
    };
    unsafe {
        snapshot_into_tcb(faulter);
    }
    unsafe {
        let s = crate::kernel::KERNEL.get();
        defer_quiesced_debug(s.scheduler.slab.get_mut(faulter), kind);
        deliver_deferred_debug(s, faulter);
        dispatch_next_or_idle("[INT3]\n")
    }
}

fn log_dec_u64(mut v: u64) {
    let mut buf = [b'0'; 20];
    let mut i = buf.len();
    if v == 0 {
        crate::arch::log("0");
        return;
    }
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

fn log_hex64(v: u64) {
    let mut buf = [b'0'; 16];
    for i in 0..16 {
        let nyb = ((v >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nyb < 10 {
            b'0' + nyb
        } else {
            b'a' + (nyb - 10)
        };
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        crate::arch::log(s);
    }
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;

    pub fn test_exceptions() {
        crate::arch::log("Running exception tests...\n");
        debug_service_gp_is_recognized_and_skips_trap_bundle();
        crate::arch::x86_64::debug::spec::run();
        test_deferred_debug();
        crate::arch::log("Exception tests completed\n");
    }

    fn debug_service_gp_is_recognized_and_skips_trap_bundle() {
        assert!(is_debug_service_gp(0x16a));
        assert!(!is_debug_service_gp(0x16b));
        assert_eq!(debug_service_resume_ip(0x1000), 0x1003);
        assert_eq!(debug_service_resume_ip(u64::MAX - 1), 1);
        crate::arch::log("  ✓ int 0x2d DebugService resumes after trap bundle\n");
    }
}

fn fatal_exception(vector: u64, error_code: u64, saved_rip: u64) -> ! {
    crate::arch::log("Vector: ");
    print_hex(vector);
    crate::arch::log("\nError code: ");
    print_hex(error_code);
    crate::arch::log("\nRIP: ");
    print_hex(saved_rip);
    crate::arch::log("\nSystem halted due to unrecoverable error\n");

    #[cfg(any(feature = "spec", feature = "extern-rootserver"))]
    crate::arch::qemu_exit(255);

    #[cfg(not(any(feature = "spec", feature = "extern-rootserver")))]
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

fn print_hex(value: u64) {
    let hex_chars = b"0123456789ABCDEF";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';

    for i in 0..16 {
        let shift = 60 - (i * 4);
        let digit = ((value >> shift) & 0xF) as usize;
        buf[i + 2] = hex_chars[digit];
    }

    if let Ok(s) = core::str::from_utf8(&buf) {
        crate::arch::log(s);
    }
}
