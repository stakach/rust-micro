/// Exits QEMU via semihosting (`-semihosting-config`)
/// qemu-system-aarch64 -semihosting-config enable=on,target=native
pub fn qemu_exit(code: u32) -> ! {
    const SEMIHOST_SYS_EXIT_EXTENDED: u64 = 0x20;
    const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x20026;
    let args = [ADP_STOPPED_APPLICATION_EXIT, code as u64];
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") SEMIHOST_SYS_EXIT_EXTENDED,
            in("x1") args.as_ptr(),
            options(noreturn)
        );
    }
}
