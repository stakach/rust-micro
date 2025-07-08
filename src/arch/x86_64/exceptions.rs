use super::interrupts::{IDT, IdtEntry, interrupt, interrupt_with_error};

// Define all exception handlers using macros
interrupt!(divide_error_handler, handle_divide_error);
interrupt!(debug_handler, handle_debug);
interrupt!(nmi_handler, handle_nmi);
interrupt!(breakpoint_handler, handle_breakpoint);
interrupt!(overflow_handler, handle_overflow);
interrupt!(bound_range_handler, handle_bound_range);
interrupt!(invalid_opcode_handler, handle_invalid_opcode);
interrupt!(device_not_available_handler, handle_device_not_available);
interrupt_with_error!(double_fault_handler, handle_double_fault, 8);
interrupt_with_error!(invalid_tss_handler, handle_invalid_tss, 10);
interrupt_with_error!(segment_not_present_handler, handle_segment_not_present, 11);
interrupt_with_error!(stack_segment_fault_handler, handle_stack_segment_fault, 12);
interrupt_with_error!(general_protection_fault_handler, handle_general_protection_fault, 13);
interrupt_with_error!(page_fault_handler, handle_page_fault, 14);
interrupt!(x87_floating_point_handler, handle_x87_floating_point);
interrupt_with_error!(alignment_check_handler, handle_alignment_check, 17);
interrupt!(machine_check_handler, handle_machine_check);
interrupt!(simd_floating_point_handler, handle_simd_floating_point);
interrupt!(virtualization_handler, handle_virtualization);

pub fn init_exceptions() {
    unsafe {
        IDT[0] = IdtEntry::new(divide_error_handler as u64, 0x08, 0, 0x8E);
        IDT[1] = IdtEntry::new(debug_handler as u64, 0x08, 0, 0x8E);
        IDT[2] = IdtEntry::new(nmi_handler as u64, 0x08, 0, 0x8E);
        IDT[3] = IdtEntry::new(breakpoint_handler as u64, 0x08, 0, 0x8E);
        IDT[4] = IdtEntry::new(overflow_handler as u64, 0x08, 0, 0x8E);
        IDT[5] = IdtEntry::new(bound_range_handler as u64, 0x08, 0, 0x8E);
        IDT[6] = IdtEntry::new(invalid_opcode_handler as u64, 0x08, 0, 0x8E);
        IDT[7] = IdtEntry::new(device_not_available_handler as u64, 0x08, 0, 0x8E);
        IDT[8] = IdtEntry::new(double_fault_handler as u64, 0x08, 0, 0x8E);
        IDT[10] = IdtEntry::new(invalid_tss_handler as u64, 0x08, 0, 0x8E);
        IDT[11] = IdtEntry::new(segment_not_present_handler as u64, 0x08, 0, 0x8E);
        IDT[12] = IdtEntry::new(stack_segment_fault_handler as u64, 0x08, 0, 0x8E);
        IDT[13] = IdtEntry::new(general_protection_fault_handler as u64, 0x08, 0, 0x8E);
        IDT[14] = IdtEntry::new(page_fault_handler as u64, 0x08, 0, 0x8E);
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

extern "C" fn handle_debug(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Debug exception\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_nmi(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Non-maskable interrupt\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_breakpoint(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Breakpoint\n");
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
    crate::arch::log("EXCEPTION: Device not available\n");
    fatal_exception(exception_num, error_code);
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

extern "C" fn handle_general_protection_fault(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: General protection fault\n");
    fatal_exception(exception_num, error_code);
}

extern "C" fn handle_page_fault(error_code: u64, exception_num: u64) {
    crate::arch::log("EXCEPTION: Page fault\n");
    fatal_exception(exception_num, error_code);
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