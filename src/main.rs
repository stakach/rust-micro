// configure Rust compiler
#![no_std]
#![no_main]

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
mod bootboot;

// Required for -Z build-std flag.
extern crate rlibc;

// Loads the appropriate architecture code
mod arch;

// Loads tests if we're running specs
#[cfg(feature = "spec")]
mod spec;

/******************************************
 * Entry point, called by BOOTBOOT Loader *
 ******************************************/
// NOTE: this code runs on all cores in parallel
#[no_mangle]
fn _start() -> ! {
    use bootboot::*;

    // use the BOOTBOOT_INFO as a pointer, dereference it and immediately borrow it.
    let bootboot_r = unsafe { & (*(BOOTBOOT_INFO as *const BOOTBOOT)) };

    arch::init_serial();
    arch::log("Serial initialized!\n");

    #[cfg(feature = "spec")]
    spec::test_main();
    loop {}
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch::log("PANIC: ");
    if let Some(loc) = info.location() {
        arch::log(loc.file());
        arch::log(":");

        let mut n = loc.line();
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        if let Ok(s) = core::str::from_utf8(&buf[i..]) {
            arch::log(s);
        }
    }
    arch::log("\n");

    #[cfg(feature = "spec")]
    arch::qemu_exit(255);

    #[cfg(not(feature = "spec"))]
    loop {}
}
