/// Exits QEMU via semihosting (`-semihosting-config`)
/// qemu-system-aarch64 -semihosting-config enable=on,target=native
pub fn qemu_exit(code: u32) -> ! {
    const SEMIHOST_SYS_EXIT: u32 = 0x18;
    unsafe {
        core::arch::asm!(
            "mov x0, {nr}",
            "mov x1, {arg}",
            "hlt #0xf000",
            nr = const SEMIHOST_SYS_EXIT,
            arg = in(reg) code,
            options(noreturn)
        );
    }
}
