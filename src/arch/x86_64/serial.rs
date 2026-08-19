const SERIAL_PORT: u16 = 0x3F8; // COM1
const SERIAL_LINE_STATUS: u16 = SERIAL_PORT + 5;
const SERIAL_THR_EMPTY: u8 = 0x20;
const SERIAL_WRITE_SPIN_LIMIT: usize = 256;

pub fn init_serial() {
    unsafe {
        outb(SERIAL_PORT + 1, 0x00); // Disable interrupts
        outb(SERIAL_PORT + 3, 0x80); // Enable DLAB
        outb(SERIAL_PORT + 0, 0x03); // Set baud rate divisor (LSB)
        outb(SERIAL_PORT + 1, 0x00); // Set baud rate divisor (MSB)
        outb(SERIAL_PORT + 3, 0x03); // 8 bits, no parity, one stop bit
        outb(SERIAL_PORT + 2, 0xC7); // Enable FIFO, clear them, 14-byte threshold
        outb(SERIAL_PORT + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }
}

pub fn log(msg: &str) {
    for byte in msg.bytes() {
        unsafe {
            write_byte(byte);
        }
    }
}

unsafe fn write_byte(byte: u8) {
    for _ in 0..SERIAL_WRITE_SPIN_LIMIT {
        if serial_thr_empty(unsafe { inb(SERIAL_LINE_STATUS) }) {
            unsafe {
                outb(SERIAL_PORT, byte);
            }
            return;
        }
        core::hint::spin_loop();
    }
    // Debug output must not become a kernel liveness dependency. If the UART or host-side serial
    // sink is backed up, drop this byte and let the caller continue.
}

#[inline(always)]
fn serial_thr_empty(line_status: u8) -> bool {
    line_status & SERIAL_THR_EMPTY != 0
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val);
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") value);
    value
}
