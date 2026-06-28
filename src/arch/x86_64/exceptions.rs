use super::interrupts::{IDT, IdtEntry, interrupt, interrupt_with_error};

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

// Define all exception handlers using macros
interrupt!(divide_error_handler, handle_divide_error);
// #DB (1) and INT3 (3) are handled by debug_exception_entry / int3_entry
// (CONFIG_HARDWARE_DEBUG_API), defined below.
interrupt!(nmi_handler, handle_nmi);
interrupt!(overflow_handler, handle_overflow);
interrupt!(bound_range_handler, handle_bound_range);
interrupt!(invalid_opcode_handler, handle_invalid_opcode);
interrupt!(device_not_available_handler, handle_device_not_available);
interrupt_with_error!(double_fault_handler, handle_double_fault, 8);
interrupt_with_error!(invalid_tss_handler, handle_invalid_tss, 10);
interrupt_with_error!(segment_not_present_handler, handle_segment_not_present, 11);
interrupt_with_error!(stack_segment_fault_handler, handle_stack_segment_fault, 12);
// general_protection_fault_handler defined manually below — we want
// the saved RIP/CS/RSP for diagnostics, which the macro stub doesn't
// pass.
interrupt_with_error!(page_fault_handler, handle_page_fault, 14);
interrupt!(x87_floating_point_handler, handle_x87_floating_point);
interrupt_with_error!(alignment_check_handler, handle_alignment_check, 17);
interrupt!(machine_check_handler, handle_machine_check);
interrupt!(simd_floating_point_handler, handle_simd_floating_point);
interrupt!(virtualization_handler, handle_virtualization);

pub fn init_exceptions() {
    unsafe {
        IDT[0] = IdtEntry::new(divide_error_handler as u64, 0x08, 0, 0x8E);
        IDT[1] = IdtEntry::new(debug_exception_entry as u64, 0x08, 0, 0x8E);
        IDT[2] = IdtEntry::new(nmi_handler as u64, 0x08, 0, 0x8E);
        // INT3 (#BP) gate needs DPL=3 so a user-mode `int3` traps here
        // instead of #GP'ing (BREAK_REQUEST_001).
        IDT[3] = IdtEntry::new(int3_entry as u64, 0x08, 0, 0xEE);
        IDT[4] = IdtEntry::new(overflow_handler as u64, 0x08, 0, 0x8E);
        IDT[5] = IdtEntry::new(bound_range_handler as u64, 0x08, 0, 0x8E);
        // PAGEFAULT0005 — #UD from user mode becomes a UserException
        // fault to the thread's fault handler (upstream
        // handleUserLevelFault). The custom entry captures the full
        // fault-time register state like the #PF / #NM entries.
        IDT[6] = IdtEntry::new(invalid_opcode_entry as u64, 0x08, 0, 0x8E);
        // FPU0004 — replace the macro stub with `device_not_available_entry`,
        // which captures saved CS so the handler can distinguish user-mode
        // (CPL=3 → check `tcbFlags & seL4_TCBFlag_fpuDisabled`) from
        // kernel-mode #NM. Same pattern the page-fault handler uses.
        IDT[7] = IdtEntry::new(device_not_available_entry as u64, 0x08, 0, 0x8E);
        IDT[8] = IdtEntry::new(double_fault_handler as u64, 0x08, 0, 0x8E);
        IDT[10] = IdtEntry::new(invalid_tss_handler as u64, 0x08, 0, 0x8E);
        IDT[11] = IdtEntry::new(segment_not_present_handler as u64, 0x08, 0, 0x8E);
        IDT[12] = IdtEntry::new(stack_segment_fault_handler as u64, 0x08, 0, 0x8E);
        IDT[13] = IdtEntry::new(general_protection_fault_handler as u64, 0x08, 0, 0x8E);
        // Phase 25: replace the broken interrupt_with_error stub
        // (which doesn't pass cr2/error_code/saved CS correctly)
        // with the proper page_fault_entry that sets up System V
        // ABI registers before calling the typed handler.
        IDT[14] = IdtEntry::new(page_fault_entry as u64, 0x08, 0, 0x8E);
        IDT[16] = IdtEntry::new(x87_floating_point_handler as u64, 0x08, 0, 0x8E);
        IDT[17] = IdtEntry::new(alignment_check_handler as u64, 0x08, 0, 0x8E);
        IDT[18] = IdtEntry::new(machine_check_handler as u64, 0x08, 0, 0x8E);
        IDT[19] = IdtEntry::new(simd_floating_point_handler as u64, 0x08, 0, 0x8E);
        IDT[20] = IdtEntry::new(virtualization_handler as u64, 0x08, 0, 0x8E);
    }
}

extern "C" fn handle_divide_error(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Divide by zero error\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_nmi(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Non-maskable interrupt\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_overflow(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Overflow\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_bound_range(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Bound range exceeded\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_invalid_opcode(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Invalid opcode\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_device_not_available(error_code: u64, exception_num: u64) {
    // The plain `interrupt!` stub doesn't pass saved CS or RIP, so
    // route #NM through `device_not_available_entry` instead (see
    // init_exceptions). This wrapper is unreachable in practice but
    // kept so the macro-generated stub compiles.
    crate::arch::log("EXCEPTION: Device not available (legacy stub)\n");
    fatal_exception(exception_num, error_code);
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
        // Stamp the iretq frame's saved RIP / RFLAGS / RSP into
        // user_ctx. sysretq restores RIP from rcx and RFLAGS from
        // r11, so user_ctx.rcx = RIP and user_ctx.r11 = RFLAGS.
        "mov rax, [rsp + 0]",
        "mov gs:[16 + 16],  rax",   // user_ctx.rcx = saved RIP
        "mov rax, [rsp + 16]",
        "mov gs:[16 + 80],  rax",   // user_ctx.r11 = saved RFLAGS
        "mov rax, [rsp + 24]",
        "mov gs:[16 + 120], rax",   // user_ctx.rsp = saved RSP
        // Call the typed Rust handler with (saved_rip, saved_cs).
        // Stack stays on the IDT-pushed kernel stack (TSS RSP0 for
        // user-mode entry). Plenty of room for one C call.
        "mov rdi, [rsp + 0]",
        "mov rsi, [rsp + 8]",
        "call {handler}",
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

    // User-mode #NM: BKL on, look up current thread's flags.
    crate::smp::bkl_acquire();
    let _bkl = BklGuard;

    unsafe {
        let s = crate::kernel::KERNEL.get();
        let current = match s.scheduler.current() {
            Some(c) => c,
            None => {
                // No current thread — shouldn't happen from user
                // mode but be defensive.
                crate::arch::x86_64::syscall_entry::set_cr0_ts(false);
                return;
            }
        };
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
        let pcc_snapshot = *crate::arch::x86_64::syscall_entry
            ::current_cpu_user_ctx_mut();
        s.scheduler.slab.get_mut(current).user_context = pcc_snapshot;
        let _ = saved_rip; // already in pcc_snapshot.rcx
        let _ = crate::fault::deliver_fault(
            current,
            crate::fault::FaultMessage::UserException {
                number: 7,
                code: 0,
            },
        );

        // The faulter is now BlockedOnReply (or suspended if no
        // handler). iretq'ing back to it would re-execute the FPU
        // instruction. Context-switch to the next runnable thread
        // by sysretq'ing into it directly — same pattern the page
        // fault handler uses. Drop the BKL just before sysretq.
        let next = s.scheduler.choose_thread();
        if let Some(next_id) = next {
            s.scheduler.set_current(Some(next_id));
            let tcb = s.scheduler.slab.get(next_id);
            let next_cr3 = tcb.cpu_context.cr3;
            let next_fs_base = tcb.cpu_context.fs_base;
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
            crate::arch::x86_64::msr::wrmsr(
                crate::arch::x86_64::msr::IA32_FS_BASE, next_fs_base);
            crate::arch::x86_64::syscall_entry::apply_fpu_gate_for(
                s.scheduler.slab.get(next_id));
            crate::arch::x86_64::syscall_entry::apply_debug_state_for(
                s.scheduler.slab.get(next_id));
            let pcc = crate::arch::x86_64::syscall_entry
                ::current_cpu_user_ctx_mut();
            *pcc = next_ctx;
            // Honour use_iretq_resume on this resume path too.
            if s.scheduler.slab.get(next_id).use_iretq_resume {
                s.scheduler.slab.get_mut(next_id).use_iretq_resume = false;
                drop(_bkl);
                crate::arch::x86_64::syscall_entry::enter_user_via_iretq(
                    pcc as *const _);
            }
            // Release BKL via Drop on _bkl, then sysret.
            drop(_bkl);
            crate::arch::x86_64::syscall_entry::enter_user_via_sysret(
                pcc as *const _);
            // unreachable
        }
        // No runnable thread — idle this CPU until an IRQ wakes it.
        crate::arch::log("[#NM: no next thread, idling CPU]\n");
        drop(_bkl);
        loop { core::arch::asm!("sti", "hlt"); }
    }
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
    if let Some(next_id) = s.scheduler.choose_thread() {
        s.scheduler.set_current(Some(next_id));
        crate::sched_context::complete_yield_if_pending(next_id);
        let tcb = s.scheduler.slab.get(next_id);
        let next_cr3 = tcb.cpu_context.cr3;
        let next_fs_base = tcb.cpu_context.fs_base;
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
            // The from-idle CR3 reload is only needed under real SMP (a
            // core that idled on a vspace can miss a cross-core
            // shootdown). In the default single-node build it's pure
            // overhead AND perturbs the flaky suspend/resume timing
            // (SCHED0000), so gate it behind `smp`.
            #[cfg(feature = "smp")]
            let was_idle = crate::smp::take_went_idle();
            #[cfg(not(feature = "smp"))]
            let was_idle = false;
            let cur_cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cur_cr3,
                options(nomem, nostack, preserves_flags));
            if was_idle || next_cr3 != cur_cr3 {
                core::arch::asm!("mov cr3, {}", in(reg) next_cr3,
                    options(nostack, preserves_flags));
            }
        }
        crate::arch::x86_64::msr::wrmsr(
            crate::arch::x86_64::msr::IA32_FS_BASE, next_fs_base);
        crate::arch::x86_64::syscall_entry::apply_fpu_gate_for(
            s.scheduler.slab.get(next_id));
        crate::arch::x86_64::syscall_entry::apply_debug_state_for(
            s.scheduler.slab.get(next_id));
        let pcc = crate::arch::x86_64::syscall_entry
            ::current_cpu_user_ctx_mut();
        *pcc = next_ctx;
        if s.scheduler.slab.get(next_id).use_iretq_resume {
            s.scheduler.slab.get_mut(next_id).use_iretq_resume = false;
            crate::smp::bkl_release();
            crate::arch::x86_64::syscall_entry::enter_user_via_iretq(
                pcc as *const _);
        }
        crate::smp::bkl_release();
        crate::arch::x86_64::syscall_entry::enter_user_via_sysret(
            pcc as *const _);
    }
    if !logged { crate::arch::log(idle_tag); logged = true; }
    // Idle: drop the lock so the timer ISR can run, halt until an
    // interrupt, then re-acquire and loop back to choose_thread.
    // Mark went-idle so the next dispatch flushes a possibly-stale TLB.
    // Park on the kernel root page table first — a user vspace left in
    // CR3 here can be freed by another core's teardown, after which our
    // next interrupt would read an unmapped IDT and triple-fault. Only a
    // concern under real SMP; the default single-node build can't have a
    // peer free the vspace under an idling core.
    #[cfg(feature = "smp")]
    crate::arch::x86_64::paging::park_on_kernel_root();
    crate::smp::mark_went_idle();
    crate::smp::bkl_release();
    core::arch::asm!("sti", "hlt");
    crate::smp::bkl_acquire();
    }
}

/// Custom #UD (Invalid Opcode, vector 6) entry. No error code.
/// Same full fault-time capture as the #PF entry: TRUE rcx/r11 in
/// the GPR slots, frame RIP/RFLAGS/RSP in the dedicated iretq
/// slots. PAGEFAULT0005's `ud2` relies on the handler reading the
/// exact fault-time SP (the test points RSP at a magic variable).
///
/// Stack on entry (no error code from CPU):
///   [rsp+0]  = saved RIP
///   [rsp+8]  = saved CS
///   [rsp+16] = saved RFLAGS
///   [rsp+24] = saved RSP
///   [rsp+32] = saved SS
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn invalid_opcode_entry() {
    core::arch::naked_asm!(
        "test byte ptr [rsp + 8], 3",
        "jz 2f",
        // -------- user-mode #UD: full save --------
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
        "mov rax, [rsp + 0]",
        "mov gs:[16 + 128], rax",   // user_ctx.rip    = saved RIP
        "mov rax, [rsp + 16]",
        "mov gs:[16 + 136], rax",   // user_ctx.rflags = saved RFLAGS
        "mov rax, [rsp + 24]",
        "mov gs:[16 + 120], rax",   // user_ctx.rsp    = saved RSP
        "mov rdi, [rsp + 0]",
        "mov rsi, [rsp + 8]",
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
        "iretq",
        // -------- kernel-mode #UD: fatal --------
        "2:",
        "mov rdi, [rsp + 0]",
        "mov rsi, [rsp + 8]",
        "call {handler}",
        "iretq",
        handler = sym handle_invalid_opcode_typed,
    );
}

extern "C" fn handle_invalid_opcode_typed(saved_rip: u64, saved_cs: u64) {
    let from_user = (saved_cs & 3) == 3;
    if !from_user {
        crate::arch::log("FATAL: kernel #UD @ rip=0x");
        log_hex64(saved_rip);
        crate::arch::log("\n");
        fatal_exception(6, 0);
    }
    crate::smp::bkl_acquire();
    let current = crate::kernel::current_thread();
    let Some(faulter) = current else {
        // Same race as the #PF no-current path: another CPU blocked
        // us mid-flight. Dispatch whatever is runnable.
        unsafe { dispatch_next_or_idle("[#UD: no current, idling CPU]\n") }
    };
    unsafe {
        // Mirror the per-CPU snapshot (full fault-time state) into
        // the faulter and mark iretq resume.
        let snapshot = *crate::arch::x86_64::syscall_entry
            ::current_cpu_user_ctx_mut();
        let s = crate::kernel::KERNEL.get();
        let t = s.scheduler.slab.get_mut(faulter);
        t.user_context = snapshot;
        t.use_iretq_resume = true;
        // UserException(number=6 (#UD vector), code=0) — mirrors
        // upstream handleUserLevelFault for int_invalid_op.
        if crate::fault::deliver_fault(
            faulter,
            crate::fault::FaultMessage::UserException { number: 6, code: 0 },
        ).is_err() {
            crate::arch::log("[#UD: no fault handler — suspending thread]\n");
            s.scheduler.block(faulter, crate::tcb::ThreadStateType::Inactive);
        }
        dispatch_next_or_idle("[#UD: no next thread, idling CPU]\n")
    }
}

extern "C" fn handle_double_fault(error_code: u64, exception_num: u64) {
    crate::arch::log("FATAL: Double fault - system is in an unrecoverable state\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_invalid_tss(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Invalid TSS\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_segment_not_present(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Segment not present\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_stack_segment_fault(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Stack segment fault\n");
    fatal_exception(exception_num, error_code);
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
        "call {handler}",
        "add rsp, 8",
        "iretq",
        handler = sym handle_general_protection_fault_typed,
    );
}

extern "C" fn handle_general_protection_fault_typed(
    error_code: u64,
    saved_cs: u64,
) {
    let from_user = (saved_cs & 3) == 3;
    if !from_user {
        crate::arch::log("EXCEPTION: kernel general protection fault, err=0x");
        log_hex64(error_code);
        crate::arch::log("\n");
        fatal_exception(13, error_code);
    }
    crate::smp::bkl_acquire();
    let current = crate::kernel::current_thread();
    let Some(faulter) = current else {
        unsafe { dispatch_next_or_idle("[#GP: no current, idling CPU]\n") }
    };
    unsafe {
        let snapshot = *crate::arch::x86_64::syscall_entry
            ::current_cpu_user_ctx_mut();
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
        ).is_err() {
            crate::arch::log("[#GP: no fault handler — suspending thread]\n");
            s.scheduler.block(faulter, crate::tcb::ThreadStateType::Inactive);
        }
        dispatch_next_or_idle("[#GP: no next thread, idling CPU]\n")
    }
}

extern "C" fn handle_page_fault(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Page fault\n");
    fatal_exception(exception_num, error_code);
}

// ---------------------------------------------------------------------------
// Phase 25 — proper page-fault entry that routes user faults
// through deliver_fault.
//
// The original `interrupt_with_error!` macro pushes a placeholder
// vector then `call`s the Rust handler. The handler is `extern "C"`
// (System V ABI) but the macro doesn't put args in rdi/rsi, so it
// reads garbage. We write a focused stub that:
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
extern "C" fn handle_page_fault_typed(
    cr2: u64,
    error_code: u64,
    saved_cs: u64,
    saved_rip: u64,
) {
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
    crate::smp::bkl_acquire();

    let user_mode = (saved_cs & 3) == 3;
    if !user_mode {
        crate::arch::log("KERNEL PAGE FAULT @ rip=0x");
        log_hex64(saved_rip);
        crate::arch::log(", cr2=0x");
        log_hex64(cr2);
        crate::arch::log(", err=0x");
        log_hex64(error_code);
        crate::arch::log("\nfatal — halting\n");
        crate::smp::bkl_release();
        #[cfg(feature = "spec")]
        crate::arch::qemu_exit(255);
        #[cfg(not(feature = "spec"))]
        loop { unsafe { asm!("hlt"); } }
    }

    // User-mode page fault — try to deliver to the thread's
    // fault handler. If delivery fails (no handler / bad cap),
    // we kill the thread by parking it Inactive.
    let current = crate::kernel::current_thread();
    if current.is_none() {
        // We took a user-mode #PF on a CPU whose `current` is
        // None. Most common cause: another CPU blocked the thread
        // we were running (e.g. as the receiver in a Call) — its
        // `block()` cleared the per-CPU `current` everywhere
        // before we trapped, so by the time we acquired the BKL
        // and looked, the slot was empty. Don't refault forever;
        // dispatch the next runnable thread or idle.
        unsafe {
            dispatch_next_or_idle("[USER #PF no current, no runnable — idle]\n")
        }
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
        let snapshot = *crate::arch::x86_64::syscall_entry
            ::current_cpu_user_ctx_mut();
        let t = crate::kernel::KERNEL.get().scheduler.slab.get_mut(faulter);
        t.user_context = snapshot;
        t.use_iretq_resume = true;
    }
    let _ = saved_rip; // captured in the snapshot's .rip slot
    let fault = crate::fault::FaultMessage::VMFault {
        addr: cr2,
        fsr: error_code,
        instruction: (error_code & (1 << 4)) != 0,
    };
    crate::arch::log("[user #PF: tcb=");
    {
        let mut buf = [b'0'; 6]; let mut v = faulter.0 as u64; let mut i = 6;
        if v == 0 { crate::arch::log("0"); }
        while v > 0 && i > 0 { i -= 1; buf[i] = b'0' + (v % 10) as u8; v /= 10; }
        if let Ok(s) = core::str::from_utf8(&buf[i..]) { crate::arch::log(s); }
    }
    crate::arch::log(" cr2=0x");
    log_hex64(cr2);
    crate::arch::log(" err=0x");
    log_hex64(error_code);
    crate::arch::log(" rip=0x");
    log_hex64(saved_rip);
    crate::arch::log("]\n");
    let suspended = if crate::fault::deliver_fault(faulter, fault).is_err() {
        crate::arch::log("[no fault handler — suspending thread]\n");
        unsafe {
            crate::kernel::KERNEL.get().scheduler.block(
                faulter,
                crate::tcb::ThreadStateType::Inactive,
            );
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
        unsafe {
            dispatch_next_or_idle("[user #PF: no next thread, idling CPU]\n")
        }
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
            "call {handler}",
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
            "call {handler}",
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

/// Deliver a debug fault; suspend the thread if it has no handler.
unsafe fn deliver_debug_fault(faulter: crate::tcb::TcbId, fault: crate::fault::FaultMessage) {
    if crate::fault::deliver_fault(faulter, fault).is_err() {
        crate::arch::log("[debug fault — no handler, suspending]\n");
        crate::kernel::KERNEL.get().scheduler.block(
            faulter, crate::tcb::ThreadStateType::Inactive);
    }
}

#[no_mangle]
extern "C" fn handle_debug_typed(saved_cs: u64, saved_rip: u64) {
    use crate::arch::x86_64::debug;
    crate::smp::bkl_acquire();
    if (saved_cs & 3) != 3 {
        // Kernel-mode #DB — clear status and resume.
        unsafe { debug::write_dr6(0xFFFF_0FF0); }
        crate::smp::bkl_release();
        return;
    }
    let faulter = match crate::kernel::current_thread() {
        Some(t) => t,
        None => unsafe { dispatch_next_or_idle("[#DB no current]\n") },
    };
    unsafe { snapshot_into_tcb(faulter); }
    let dr6 = unsafe { debug::read_dr6() };
    let s = unsafe { crate::kernel::KERNEL.get() };

    // Active hardware breakpoint? (B0..B3 = DR6 bits 0..3)
    let active = (0..4).find(|&b| dr6 & (1 << b) != 0);
    if let Some(bp) = active {
        unsafe { debug::write_dr6(dr6 & !(1u64 << bp)); }
        let (vaddr, reason) = {
            let st = &s.scheduler.slab.get(faulter).debug;
            (st.dr[bp], debug::breakpoint_reason(st, bp))
        };
        unsafe {
            deliver_debug_fault(faulter, crate::fault::FaultMessage::DebugException {
                fault_ip: saved_rip, reason, trigger_addr: vaddr, bp_num: bp as u64,
            });
            dispatch_next_or_idle("[#DB hw bp]\n")
        }
    } else if dr6 & debug::DR6_SINGLE_STEP != 0 {
        unsafe { debug::write_dr6(dr6 & !debug::DR6_SINGLE_STEP); }
        // Set RF so an instruction breakpoint at the resume IP isn't
        // re-raised (auto-cleared by the CPU after one instruction).
        s.scheduler.slab.get_mut(faulter).user_context.rflags |= debug::FLAGS_RF;
        let ready = debug::single_step_counter_ready(
            &mut s.scheduler.slab.get_mut(faulter).debug);
        if ready {
            unsafe {
                deliver_debug_fault(faulter, crate::fault::FaultMessage::DebugException {
                    fault_ip: saved_rip, reason: debug::SEL4_SINGLE_STEP,
                    trigger_addr: 0, bp_num: 0,
                });
                dispatch_next_or_idle("[#DB single-step]\n")
            }
        } else {
            // Counter not yet zero — keep stepping (TF stays set).
            unsafe { dispatch_next_or_idle("[#DB step]\n") }
        }
    } else {
        // Spurious — clear and resume.
        unsafe { debug::write_dr6(0xFFFF_0FF0); }
        unsafe { dispatch_next_or_idle("[#DB spurious]\n") }
    }
}

#[no_mangle]
extern "C" fn handle_int3_typed(saved_cs: u64, saved_rip: u64) {
    use crate::arch::x86_64::debug;
    crate::smp::bkl_acquire();
    if (saved_cs & 3) != 3 {
        crate::arch::log("KERNEL INT3\n");
        crate::smp::bkl_release();
        return;
    }
    let faulter = match crate::kernel::current_thread() {
        Some(t) => t,
        None => unsafe { dispatch_next_or_idle("[INT3 no current]\n") },
    };
    unsafe { snapshot_into_tcb(faulter); }
    unsafe {
        deliver_debug_fault(faulter, crate::fault::FaultMessage::DebugException {
            fault_ip: saved_rip,
            reason: debug::SEL4_SOFTWARE_BREAK_REQUEST,
            trigger_addr: 0, bp_num: 0,
        });
        dispatch_next_or_idle("[INT3]\n")
    }
}

fn log_hex64(v: u64) {
    let mut buf = [b'0'; 16];
    for i in 0..16 {
        let nyb = ((v >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nyb < 10 { b'0' + nyb } else { b'a' + (nyb - 10) };
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        crate::arch::log(s);
    }
}

extern "C" fn handle_x87_floating_point(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: x87 floating point exception\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_alignment_check(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Alignment check\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_machine_check(error_code: u64, exception_num: u64) {
    crate::arch::log("FATAL: Machine check exception - hardware error\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_simd_floating_point(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: SIMD floating point exception\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_virtualization(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Virtualization exception\n");
    fatal_exception(exception_num, error_code);
}

fn fatal_exception(exception_num: u64, error_code: u64) -> ! {
    crate::arch::log("Exception number: ");
    print_hex(exception_num);
    crate::arch::log("\nError code: ");
    print_hex(error_code);
    crate::arch::log("\nSystem halted due to unrecoverable error\n");
    
    #[cfg(feature = "spec")]
    crate::arch::qemu_exit(255);
    
    #[cfg(not(feature = "spec"))]
    loop {
        unsafe {
            asm!("hlt");
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