/// Exits QEMU using `isa-debug-exit` I/O port at 0x501
/// qemu-system-x86_64 -device isa-debug-exit,iobase=0x501,iosize=0x2
pub fn qemu_exit(code: u32) -> ! {
    let value = ((code << 1) | 1) as u16;
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") 0x501u16, in("ax") value);
    }
    loop {}
}
