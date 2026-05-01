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
// seL4_BootInfo subset. The kernel writes the full struct into our
// BootInfo page; we only decode the fields we use here.
//
// Field offsets must match `crate::types::seL4_BootInfo` in the
// kernel — keep them hand-listed for clarity since we don't share
// the codegen.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
struct SlotRegion { start: u64, end: u64 }

#[repr(C)]
#[derive(Copy, Clone)]
struct UntypedDesc {
    paddr: u64,
    size_bits: u8,
    is_device: u8,
    _padding: [u8; 6],
}

const MAX_BI_UNTYPED: usize = 230;

#[repr(C)]
struct BootInfo {
    extra_len: u64,
    node_id: u64,
    num_nodes: u64,
    num_iopt_levels: u64,
    ipc_buffer: *mut u8,
    empty: SlotRegion,
    shared_frames: SlotRegion,
    user_image_frames: SlotRegion,
    user_image_paging: SlotRegion,
    io_space_caps: SlotRegion,
    extra_bi_pages: SlotRegion,
    init_thread_cnode_size_bits: u64,
    init_thread_domain: u64,
    untyped: SlotRegion,
    untyped_list: [UntypedDesc; MAX_BI_UNTYPED],
}

// ---------------------------------------------------------------------------
// Helpers for printing decimal numbers. No allocator, so we use a
// fixed-size stack buffer.
// ---------------------------------------------------------------------------

fn print_str(s: &[u8]) {
    for &b in s {
        debug_put_char(b);
    }
}

fn print_u64(mut n: u64) {
    if n == 0 {
        debug_put_char(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    print_str(&buf[i..]);
}

// ---------------------------------------------------------------------------
// Entry. The kernel passes the BootInfo vaddr via `rdi` (System V
// ABI first arg), so we read it directly from our argument.
// ---------------------------------------------------------------------------

#[no_mangle]
#[link_section = ".text._start"]
pub unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    let n_untyped = bi.untyped.end - bi.untyped.start;

    print_str(b"[rootserver alive] node ");
    print_u64(bi.node_id);
    print_str(b"/");
    print_u64(bi.num_nodes);
    print_str(b", ");
    print_u64(n_untyped);
    print_str(b" untyped(s) of ");
    print_u64(1u64 << bi.untyped_list[0].size_bits);
    print_str(b" bytes\n");

    // Phase 29g will retype `bi.untyped_list[0]` into a child TCB +
    // CNode + Endpoint and IPC with it.
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
