use core::arch::asm;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

#[repr(C, packed)]
struct IdtDescriptor {
    limit: u16,
    base: u64,
}

pub static mut IDT: [IdtEntry; 256] = [IdtEntry {
    offset_low: 0,
    selector: 0,
    ist: 0,
    type_attr: 0,
    offset_mid: 0,
    offset_high: 0,
    reserved: 0,
}; 256];

impl IdtEntry {
    pub fn new(handler: u64, selector: u16, ist: u8, type_attr: u8) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector,
            ist,
            type_attr,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

pub fn init_interrupts() {
    unsafe {
        for i in 0..256 {
            IDT[i] = IdtEntry::new(
                default_interrupt_handler as u64,
                0x08,
                0,
                0x8E,
            );
        }
        // Phase 28d — install the cross-CPU IPI handler.
        IDT[crate::smp::IPI_VECTOR as usize] = IdtEntry::new(
            super::lapic::ipi_irq_entry as u64,
            0x08,
            0,
            0x8E,
        );
    }
    // Phase 33b — install generic IRQ entries for IRQ 1..15 so
    // hardware vectors funnel through `irq_dispatch` →
    // `interrupt::handle_interrupt` → bound notification.
    install_irq_entries();
    load_idt();
}

/// Per-CPU IDT load. Run on each CPU after the BSP has populated
/// the shared IDT. Loads `IDT` into `IDTR` and unmasks IF via STI.
pub fn load_idt() {
    unsafe {
        let idt_desc = IdtDescriptor {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: core::ptr::addr_of!(IDT) as u64,
        };
        asm!("lidt [{}]", in(reg) &idt_desc);
        asm!("sti");
    }
}

macro_rules! interrupt {
    ($name:ident, $handler:ident) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",            // Push error code (0 for exceptions without it)
                "push 0",            // Dummy IRQ number or vector
                "call {handler}",    // Call actual handler function
                "add rsp, 16",       // Clean up stack
                "iretq",             // Return from interrupt
                handler = sym $handler
            );
        }
    };
}

macro_rules! interrupt_with_error {
    ($name:ident, $handler:ident, $vector:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push {vector}",     // Push vector number  
                "call {handler}",    // Call actual handler function
                "add rsp, 16",       // Clean up stack (error code + vector)
                "iretq",             // Return from interrupt
                vector = const $vector,
                handler = sym $handler
            );
        }
    };
}

pub(crate) use interrupt;
pub(crate) use interrupt_with_error;

#[unsafe(naked)]
unsafe extern "C" fn default_interrupt_handler() {
    core::arch::naked_asm!(
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "call {}",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "iretq",
        sym handle_interrupt
    );
}

extern "C" fn handle_interrupt() {
    crate::arch::log("Received interrupt\n");
}

// ---------------------------------------------------------------------------
// Phase 33b — generic IRQ entry. Vectors PIC1_VECTOR_BASE+1..+15
// (IRQ 1..15) funnel through `irq_dispatch`, which calls
// `interrupt::handle_interrupt` to signal any bound notification,
// EOIs the PIC, and (if a higher-priority thread woke) context-
// switches the iretq frame the same way `pit_irq_dispatch` does.
// IRQ 0 (the PIT) keeps its dedicated entry in `pit.rs` since that
// one also debits MCS budgets.
// ---------------------------------------------------------------------------

/// Snapshot the generic IRQ entry produces on the kernel stack.
/// 15 GPRs in `rax..r15` push order, then the CPU-pushed iretq
/// frame: RIP, CS, RFLAGS, RSP, SS.
#[repr(C)]
pub struct IretqContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Macro: define a naked IRQ entry for a fixed IRQ number. The
/// number is encoded into the stub so `irq_dispatch` knows which
/// PIC line to EOI without a separate table. We generate one stub
/// per supported IRQ at compile time.
macro_rules! irq_entry {
    ($name:ident, $irq:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push rax",
                "push rbx",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push rbp",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "mov rdi, rsp",
                "mov rsi, {irq}",
                "call {handler}",
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop r11",
                "pop r10",
                "pop r9",
                "pop r8",
                "pop rbp",
                "pop rdi",
                "pop rsi",
                "pop rdx",
                "pop rcx",
                "pop rbx",
                "pop rax",
                "iretq",
                irq = const ($irq as u64),
                handler = sym irq_dispatch,
            );
        }
    };
}

irq_entry!(irq1_entry, 1);
irq_entry!(irq2_entry, 2);
irq_entry!(irq3_entry, 3);
irq_entry!(irq4_entry, 4);
irq_entry!(irq5_entry, 5);
irq_entry!(irq6_entry, 6);
irq_entry!(irq7_entry, 7);
irq_entry!(irq8_entry, 8);
irq_entry!(irq9_entry, 9);
irq_entry!(irq10_entry, 10);
irq_entry!(irq11_entry, 11);
irq_entry!(irq12_entry, 12);
irq_entry!(irq13_entry, 13);
irq_entry!(irq14_entry, 14);
irq_entry!(irq15_entry, 15);

struct IrqBklGuard;
impl Drop for IrqBklGuard {
    fn drop(&mut self) {
        crate::smp::bkl_release();
    }
}

#[no_mangle]
extern "C" fn irq_dispatch(ctx: &mut IretqContext, irq: u64) {
    crate::smp::bkl_acquire();
    let _bkl = IrqBklGuard;

    let from_user = (ctx.cs & 3) == 3;
    let interrupted = unsafe { crate::kernel::KERNEL.get().scheduler.current() };

    // Phase 33b — signal any notification bound to this IRQ.
    // `handle_interrupt` returns `Some(tcb)` if a thread woke up;
    // we use it as a hint that the schedule may want to swap.
    unsafe {
        let s = crate::kernel::KERNEL.get();
        let s_ptr: *mut crate::kernel::KernelState = s;
        // Aliasing dance: `handle_interrupt` borrows three sibling
        // fields of `*s` mutably. Splitting via raw pointers keeps
        // the BKL the only enforcer of exclusivity.
        let _ = crate::interrupt::handle_interrupt(
            &mut (*s_ptr).irqs,
            &mut (*s_ptr).notifications,
            &mut (*s_ptr).scheduler,
            irq as u16,
        );
        // Mask a level-triggered IOAPIC line BEFORE the EOI: a still-asserted level
        // source (e.g. PCI INTx, held until the driver clears the device cause) would
        // otherwise re-fire immediately after EOI and storm the CPU. The owning
        // IRQHandler::Ack unmasks it once the driver has serviced the device.
        if let Some(entry) = (*s_ptr).irqs.get(irq as u16) {
            if entry.level_triggered {
                if let Some(pin) = entry.ioapic_pin {
                    super::ioapic::mask_pin(pin as u32);
                }
            }
        }
    }
    super::pic::eoi(irq as u8);
    // In APIC mode EVERY interrupt reaches the CPU via the LAPIC, so it MUST be
    // acknowledged with a LAPIC EOI — not just the (vestigial) 8259 EOI above. Without
    // this the LAPIC's in-service bit for this vector stays set and blocks every later
    // interrupt in the same priority class: the first IOAPIC/MSI device IRQ would
    // deliver, then all subsequent ones (INTx, MSI, other pins) would be silently
    // dropped. (The LAPIC timer tick already EOIs via lapic_timer_irq_dispatch.)
    super::lapic::eoi();

    // Same context-switch tail as `pit_irq_dispatch`. Factored
    // here so PIT and generic IRQs use one path; PIT keeps its own
    // entry only because of the extra `mcs_tick` work it does.
    swap_iretq_context_if_preempted(ctx, from_user, interrupted);
}

/// Common preemption tail used by both the PIT IRQ and the generic
/// IRQ dispatchers. If the running thread changed during the IRQ
/// (block on budget exhaustion, signal-driven wake of a higher-
/// priority thread, etc.), save the interrupted thread's regs into
/// its TCB and rewrite `ctx` from the next current's user_context.
pub(crate) fn swap_iretq_context_if_preempted(
    ctx: &mut IretqContext,
    from_user: bool,
    interrupted: Option<crate::tcb::TcbId>,
) {
    if !from_user {
        return;
    }
    unsafe {
        let s = crate::kernel::KERNEL.get();
        let next = match s.scheduler.current() {
            Some(t) => Some(t),
            None => s.scheduler.choose_thread(),
        };
        let next = match next {
            Some(t) => t,
            None => {
                // No runnable thread in the current domain. We must
                // NOT resume the interrupted user thread: it belongs
                // to a domain that isn't currently scheduled, and
                // resuming it would also leave `current` desynced from
                // the actually-running thread (the next preemption
                // would then load a stale context and fault — the
                // DOMAINS teardown #PF). Save its live registers so it
                // resumes correctly when its domain comes round again,
                // then idle until the next tick advances the schedule.
                if let Some(prev) = interrupted {
                    let prev_tcb = s.scheduler.slab.get_mut(prev);
                    prev_tcb.user_context.rax = ctx.rax;
                    prev_tcb.user_context.rbx = ctx.rbx;
                    prev_tcb.user_context.rcx = ctx.rcx;
                    prev_tcb.user_context.rdx = ctx.rdx;
                    prev_tcb.user_context.rsi = ctx.rsi;
                    prev_tcb.user_context.rdi = ctx.rdi;
                    prev_tcb.user_context.rbp = ctx.rbp;
                    prev_tcb.user_context.r8 = ctx.r8;
                    prev_tcb.user_context.r9 = ctx.r9;
                    prev_tcb.user_context.r10 = ctx.r10;
                    prev_tcb.user_context.r11 = ctx.r11;
                    prev_tcb.user_context.r12 = ctx.r12;
                    prev_tcb.user_context.r13 = ctx.r13;
                    prev_tcb.user_context.r14 = ctx.r14;
                    prev_tcb.user_context.r15 = ctx.r15;
                    prev_tcb.user_context.rsp = ctx.rsp;
                    prev_tcb.user_context.rip = ctx.rip;
                    prev_tcb.user_context.rflags = ctx.rflags;
                    prev_tcb.use_iretq_resume = true;
                }
                s.scheduler.set_current(None);
                // IRQ entry does not swap GS. Normalize to the kernel GS
                // regime expected by dispatch_next_or_idle: active GS is the
                // per-CPU area and KERNEL_GS_BASE is the outgoing user value.
                // Its enter-user tail will install the next value and swap back.
                core::arch::asm!("swapgs", options(nostack, preserves_flags));
                crate::arch::x86_64::exceptions::dispatch_next_or_idle("");
            }
        };
        // Same thread resumes on this core: it resumes via the IRQ frame's
        // iretq (registers intact). The default (single-node) build skips
        // the save entirely here — writing the TCB context corrupts threads
        // this core re-enters without a full round-trip (it broke DOMAINS
        // rotation). The smp build instead saves FIRST (below) so a later
        // MIGRATION dispatches the thread from a current context (FPU0002),
        // then takes the same early return after the save.
        #[cfg(not(feature = "smp"))]
        if Some(next) == interrupted {
            s.scheduler.set_current(Some(next));
            return;
        }
        if let Some(prev) = interrupted {
            let prev_tcb = s.scheduler.slab.get_mut(prev);
            // FULL context save. An IRQ can preempt any user
            // instruction, so the true rcx / r11 GPRs must survive;
            // RIP and RFLAGS go in their dedicated fields and the
            // thread is flagged for iretq resume (sysretq would
            // clobber rcx/r11 to restore RIP/RFLAGS). The old code
            // overwrote rcx with RIP — invisible while user threads
            // ran IF=0 (never preempted mid-computation), fatally
            // corrupting once IF sanitization made preemption real.
            prev_tcb.user_context.rax = ctx.rax;
            prev_tcb.user_context.rbx = ctx.rbx;
            prev_tcb.user_context.rcx = ctx.rcx;
            prev_tcb.user_context.rdx = ctx.rdx;
            prev_tcb.user_context.rsi = ctx.rsi;
            prev_tcb.user_context.rdi = ctx.rdi;
            prev_tcb.user_context.rbp = ctx.rbp;
            prev_tcb.user_context.r8 = ctx.r8;
            prev_tcb.user_context.r9 = ctx.r9;
            prev_tcb.user_context.r10 = ctx.r10;
            prev_tcb.user_context.r11 = ctx.r11;
            prev_tcb.user_context.r12 = ctx.r12;
            prev_tcb.user_context.r13 = ctx.r13;
            prev_tcb.user_context.r14 = ctx.r14;
            prev_tcb.user_context.r15 = ctx.r15;
            prev_tcb.user_context.rsp = ctx.rsp;
            prev_tcb.user_context.rip = ctx.rip;
            prev_tcb.user_context.rflags = ctx.rflags;
            prev_tcb.use_iretq_resume = true;
        }
        // smp: now take the same-core early return, AFTER having saved the
        // interrupted thread's context above (so a migration sees it).
        #[cfg(feature = "smp")]
        if Some(next) == interrupted {
            s.scheduler.set_current(Some(next));
            return;
        }
        // `use_iretq_resume` tracks the SAVE flavor (IRQ-preempted = true,
        // syscall = false) and persists until the thread is next saved —
        // do NOT clear it here. Clearing it on dispatch left the saved
        // context iretq-flavor (RIP in .rip, real rcx in .rcx) while the
        // flag claimed sysret-flavor, so reported_ip/resume_ip later read
        // .rcx (a live data value) as the RIP — a ReadRegisters→
        // WriteRegisters restart then resumed at that garbage (FPU0002).
        let use_iretq = s.scheduler.slab.get(next).use_iretq_resume;
        // activateThread — write a pending YieldTo consumed-report
        // before snapshotting the context we're about to load.
        crate::sched_context::complete_yield_if_pending(next);
        let next_ctx = s.scheduler.slab.get(next).user_context;
        ctx.rax = next_ctx.rax;
        ctx.rbx = next_ctx.rbx;
        ctx.rdx = next_ctx.rdx;
        ctx.rsi = next_ctx.rsi;
        ctx.rdi = next_ctx.rdi;
        ctx.rbp = next_ctx.rbp;
        ctx.r8 = next_ctx.r8;
        ctx.r9 = next_ctx.r9;
        ctx.r10 = next_ctx.r10;
        ctx.r12 = next_ctx.r12;
        ctx.r13 = next_ctx.r13;
        ctx.r14 = next_ctx.r14;
        ctx.r15 = next_ctx.r15;
        ctx.rsp = next_ctx.rsp;
        ctx.rcx = next_ctx.rcx;
        ctx.r11 = next_ctx.r11;
        if use_iretq {
            // Thread was primed by WriteRegisters with rcx / r11
            // carrying independent GPR values; its resume RIP and
            // RFLAGS live in the dedicated fields. Loading the
            // sysret-convention slots here would iretq to RIP=0
            // with IF=0.
            ctx.rip = next_ctx.rip;
            ctx.rflags = next_ctx.rflags;
        } else {
            // sysret convention: rcx doubles as RIP, r11 as RFLAGS.
            ctx.rip = next_ctx.rcx;
            ctx.rflags = next_ctx.r11;
        }
        // Whatever the source, never iretq into user mode with IF
        // clear — a spinning thread would shut the CPU off from
        // every maskable interrupt (timer ticks included).
        ctx.rflags = (ctx.rflags & 0xDD5) | 0x202;
        let next_cr3 = s.scheduler.slab.get(next).cpu_context.cr3;
        if next_cr3 != 0 {
            // This is a preemption of a *running* user thread (from_user
            // was true), so this core was active and received any TLB
            // shootdown IPIs — its TLB is coherent. Only reload CR3 on an
            // actual vspace change. (The stale-TLB-after-idle flush lives
            // in the from-idle dispatch paths: dispatch_next_or_idle and
            // the AP scheduler loop.)
            let cur_cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cur_cr3,
                options(nomem, nostack, preserves_flags));
            if next_cr3 != cur_cr3 {
                core::arch::asm!("mov cr3, {}", in(reg) next_cr3,
                    options(nostack, preserves_flags));
            }
        }
        // Restore the incoming thread's TLS base. Every other
        // dispatch site does this; missing it here meant an
        // IRQ-driven switch left the PREVIOUS thread's FS_BASE
        // live, so the new thread's %fs-relative reads (sel4runtime
        // keeps the IPC buffer pointer in TLS) dereferenced the
        // wrong thread's TLS block.
        crate::arch::x86_64::msr::wrmsr(
            crate::arch::x86_64::msr::IA32_FS_BASE,
            s.scheduler.slab.get(next).cpu_context.fs_base,
        );
        // Likewise the incoming thread's user %gs base. The IRQ entry stubs do
        // NOT swapgs (they save GPRs to the stack, not gs:[]), so the ACTIVE
        // IA32_GS_BASE — not KERNEL_GS_BASE — is what the resumed user thread
        // sees, exactly like FS_BASE above. Without this an IRQ-driven context
        // switch leaves the PREVIOUS thread's gs active, so the new thread's
        // `gs:[0x30]` (Windows NtCurrentTeb) reads a null/foreign TEB and #PFs.
        // (Writing KERNEL_GS_BASE here would instead be swapped in by the next
        // syscall entry, crashing the kernel on gs:[0x10] with a user gs base.)
        crate::arch::x86_64::msr::wrmsr(
            crate::arch::x86_64::msr::IA32_GS_BASE,
            s.scheduler.slab.get(next).cpu_context.gs_base,
        );
        // SMP: the running thread changed under this IRQ — make the
        // incoming thread's FPU state resident on this core.
        #[cfg(feature = "smp")]
        crate::arch::x86_64::fpu_ctx::fpu_switch_to(&mut s.scheduler.slab, next);
        s.scheduler.set_current(Some(next));
    }
}

/// Install IDT entries for IRQ vectors 1..15. Call after
/// `init_interrupts` and `pic::init_pic`. The PIT (IRQ 0) is
/// installed separately by `pit::enable_periodic_irq`.
///
/// IRQ 1's gate is set to DPL=3 so user-mode `int 0x21` can fire
/// it — this is the demo trigger for Phase 33b. Real seL4 keeps
/// every IDT entry at DPL=0 (only the hardware can raise an IRQ);
/// once we have a real device emitting IRQ 1 (e.g. PS/2 keyboard
/// in the rootserver) the DPL=3 hatch can be reverted.
pub fn install_irq_entries() {
    use super::pic::PIC1_VECTOR_BASE;
    unsafe {
        let base = PIC1_VECTOR_BASE as usize;
        // 0xEE = present, DPL=3, 64-bit interrupt gate. Software
        // INT 0x21 from user mode is allowed.
        IDT[base + 1]  = IdtEntry::new(irq1_entry  as u64, 0x08, 0, 0xEE);
        IDT[base + 2]  = IdtEntry::new(irq2_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 3]  = IdtEntry::new(irq3_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 4]  = IdtEntry::new(irq4_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 5]  = IdtEntry::new(irq5_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 6]  = IdtEntry::new(irq6_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 7]  = IdtEntry::new(irq7_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 8]  = IdtEntry::new(irq8_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 9]  = IdtEntry::new(irq9_entry  as u64, 0x08, 0, 0x8E);
        IDT[base + 10] = IdtEntry::new(irq10_entry as u64, 0x08, 0, 0x8E);
        IDT[base + 11] = IdtEntry::new(irq11_entry as u64, 0x08, 0, 0x8E);
        IDT[base + 12] = IdtEntry::new(irq12_entry as u64, 0x08, 0, 0x8E);
        IDT[base + 13] = IdtEntry::new(irq13_entry as u64, 0x08, 0, 0x8E);
        IDT[base + 14] = IdtEntry::new(irq14_entry as u64, 0x08, 0, 0x8E);
        IDT[base + 15] = IdtEntry::new(irq15_entry as u64, 0x08, 0, 0x8E);
    }
}
