//! seL4-style rootserver — Phase 29a.
//!
//! Loaded as a separate ELF by the kernel; runs in ring 3 in its
//! own VSpace + CSpace. For Phase 29a the body is intentionally
//! minimal: print a sentinel byte to confirm dispatch, then loop
//! on SysYield. Phase 29d/g layer on BootInfo reading + spawning
//! child workers.
//!
//! Build: `cargo build --release --target rootserver/triplet.json`
//! from the kernel repo root, with the `-Z build-std=core` flag.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

// ---------------------------------------------------------------------------
// Syscall numbers — must stay in sync with `codegen/syscall.xml`
// (mirrored in target/.../syscalls.rs after kernel build). Hand-listed
// here because the kernel doesn't currently expose its syscall ABI as
// a separate crate.
// ---------------------------------------------------------------------------

const SYS_DEBUG_PUT_CHAR: i64 = -9;
const SYS_YIELD: i64 = -7;

// ---------------------------------------------------------------------------
// Syscall stubs. The x86_64 SYSCALL ABI puts the syscall number in
// rax and arg-0..5 in rdi, rsi, rdx, r10, r8, r9. The kernel saves
// rcx (user RIP) and r11 (user RFLAGS) for sysretq.
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn syscall1(nr: i64, a0: u64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        in("rax") nr as u64,
        in("rdi") a0,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
unsafe fn syscall0(nr: i64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        in("rax") nr as u64,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
fn debug_put_char(c: u8) {
    unsafe { syscall1(SYS_DEBUG_PUT_CHAR, c as u64); }
}

#[inline(always)]
fn yield_now() {
    unsafe { syscall0(SYS_YIELD); }
}

// ---------------------------------------------------------------------------
// Entry. Prints a sentinel string so the kernel's serial output
// shows we're alive, then yields forever.
// ---------------------------------------------------------------------------

#[no_mangle]
#[link_section = ".text._start"]
pub unsafe extern "C" fn _start() -> ! {
    // The kernel sets up rsp to point at the top of our user stack,
    // so we can use Rust's normal stack-frame ABI from here.
    let banner = b"[rootserver alive]\n";
    for &b in banner {
        debug_put_char(b);
    }

    // Phase 29a sentinel — once Phase 29d wires BootInfo we'll read
    // from gs:0 / a known vaddr to find untypeds and spawn workers.
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Best-effort: print '!' then halt-loop via SysYield.
    debug_put_char(b'!');
    loop {
        yield_now();
    }
}
