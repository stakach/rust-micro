//! SURT demo rootserver.
//!
//! A standalone seL4 root task (loaded as its own ELF by the rust-micro kernel)
//! that runs the SURT ring-transport scenarios using the **published
//! `surt-sel4` crate** from crates.io. It doubles as a usage showcase and a
//! smoke-test: each scenario prints `PASS`/`FAIL`, then the `[microtest done]`
//! sentinel the kernel's serial hook watches for to `qemu_exit`.
//!
//! The seL4 ABI (syscalls, invocation helpers, `BootInfo`) comes from the
//! kernel's shared `sel4-rt` crate; the SURT usage lives in `scenarios.rs`,
//! built on `surt_sel4::{Sel4Env, Sel4Notify, drain_blocking, drain_adaptive}`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// Re-export the ABI at crate root so `scenarios.rs`'s `use crate::*` finds it.
pub use sel4_rt::*;

mod scenarios;

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    // First empty CNode slot (boot cap layout is not a fixed size) + the
    // rootserver's own image frame caps (copied read-only into component
    // VSpaces so a peer can execute surt-core unchanged).
    let empty_start = bi.empty.start;
    let img = bi.user_image_frames;
    scenarios::run(empty_start, img.start, img.end - img.start);
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_put_char(b'!');
    loop {
        yield_now();
    }
}
