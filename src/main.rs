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
#[no_mangle] // don't mangle the name of this function
fn _start() -> ! {
    /*** NOTE: this code runs on all cores in parallel ***/
    use bootboot::*;

    //Lets use the BOOTBOOT_INFO as a pointer, dereference it and immediately borrow it.
    let bootboot_r = unsafe { & (*(BOOTBOOT_INFO as *const BOOTBOOT)) };

    if bootboot_r.fb_scanline > 0 {

        //As pointer arithmetic is not possible in rust, use the address as u64
        let fb = BOOTBOOT_FB as u64;

        // cross-hair to see screen dimension detected correctly
        for y in 0..bootboot_r.fb_height {
            let addr = fb
                + bootboot_r.fb_scanline as u64 * y as u64
                + bootboot_r.fb_width as u64 * 2;
            unsafe { *(addr as *mut u64) = 0x00FFFFFF };
        }
        for x in 0..bootboot_r.fb_width {
            let addr = fb
                + bootboot_r.fb_scanline as u64 * (bootboot_r.fb_height / 2) as u64 + (x * 4) as u64;
            unsafe { *(addr as *mut u64) = 0x00FFFFFF };
        }

        // red, green, blue boxes in order
        for y in 0..20 {
            for x in 0..20 {
                let addr = fb
                    + bootboot_r.fb_scanline as u64 * (y + 20) as u64
                    + (x + 20) * 4;
                unsafe { *(addr as *mut u64) = 0x00FF0000 };
            }
        }
        for y in 0..20 {
            for x in 0..20 {
                let addr = fb
                    + bootboot_r.fb_scanline as u64 * (y + 20) as u64
                    + (x + 50) * 4;
                unsafe { *(addr as *mut u64) = 0x0000FF00 };
            }
        }
        for y in 0..20 {
            for x in 0..20 {
                let addr = fb
                    + bootboot_r.fb_scanline as u64 * (y + 20) as u64
                    + (x + 80) * 4;
                unsafe { *(addr as *mut u64) = 0x000000FF };
            }
        }
    }

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
