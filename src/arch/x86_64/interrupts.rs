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