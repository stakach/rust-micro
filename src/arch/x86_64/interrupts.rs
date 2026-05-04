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
    }
    super::pic::eoi(irq as u8);

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
            None => return,
        };
        if Some(next) == interrupted {
            s.scheduler.set_current(Some(next));
            return;
        }
        if let Some(prev) = interrupted {
            let prev_tcb = s.scheduler.slab.get_mut(prev);
            prev_tcb.user_context.rax = ctx.rax;
            prev_tcb.user_context.rbx = ctx.rbx;
            prev_tcb.user_context.rcx = ctx.rip;
            prev_tcb.user_context.rdx = ctx.rdx;
            prev_tcb.user_context.rsi = ctx.rsi;
            prev_tcb.user_context.rdi = ctx.rdi;
            prev_tcb.user_context.rbp = ctx.rbp;
            prev_tcb.user_context.r8 = ctx.r8;
            prev_tcb.user_context.r9 = ctx.r9;
            prev_tcb.user_context.r10 = ctx.r10;
            prev_tcb.user_context.r11 = ctx.rflags;
            prev_tcb.user_context.r12 = ctx.r12;
            prev_tcb.user_context.r13 = ctx.r13;
            prev_tcb.user_context.r14 = ctx.r14;
            prev_tcb.user_context.r15 = ctx.r15;
            prev_tcb.user_context.rsp = ctx.rsp;
        }
        let next_ctx = s.scheduler.slab.get(next).user_context;
        ctx.rax = next_ctx.rax;
        ctx.rbx = next_ctx.rbx;
        ctx.rip = next_ctx.rcx;
        ctx.rdx = next_ctx.rdx;
        ctx.rsi = next_ctx.rsi;
        ctx.rdi = next_ctx.rdi;
        ctx.rbp = next_ctx.rbp;
        ctx.r8 = next_ctx.r8;
        ctx.r9 = next_ctx.r9;
        ctx.r10 = next_ctx.r10;
        ctx.rflags = next_ctx.r11;
        ctx.r12 = next_ctx.r12;
        ctx.r13 = next_ctx.r13;
        ctx.r14 = next_ctx.r14;
        ctx.r15 = next_ctx.r15;
        ctx.rsp = next_ctx.rsp;
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