//! QEMU `virt` PL011 console.
//!
//! The register offsets and TX-full polling match seL4's pinned
//! `src/drivers/serial/pl011.c` implementation.

const UART_BASE: usize = 0x0900_0000;
const UART_DR: usize = 0x000;
const UART_FR: usize = 0x018;
const UART_FR_TXFF: u32 = 1 << 5;

pub fn init_serial() {
    // QEMU's firmware/direct kernel loader leaves UART0 configured. The
    // kernel only needs the polled data-register interface used by seL4.
}

pub fn log(msg: &str) {
    for byte in msg.bytes() {
        unsafe { write_byte(byte) };
    }
}

unsafe fn write_byte(byte: u8) {
    let flags = (UART_BASE + UART_FR) as *const u32;
    let data = (UART_BASE + UART_DR) as *mut u32;
    while unsafe { core::ptr::read_volatile(flags) } & UART_FR_TXFF != 0 {
        core::hint::spin_loop();
    }
    unsafe { core::ptr::write_volatile(data, byte as u32) };
}
