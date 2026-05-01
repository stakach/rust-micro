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
const SYS_SEND: i64 = -3;
const SYS_RECV: i64 = -5;

/// `InvocationLabel`s we issue.
const LBL_UNTYPED_RETYPE: u64 = 1;
const LBL_TCB_WRITE_REGISTERS: u64 = 3;
const LBL_TCB_SET_SPACE: u64 = 10;
const LBL_TCB_RESUME: u64 = 12;

/// `seL4_ObjectType` values we use here.
const OBJ_TCB: u64 = 1;
const OBJ_ENDPOINT: u64 = 2;

/// Initial CNode slots (mirrors the kernel's `seL4_RootCNodeCapSlots`).
const CAP_INIT_THREAD_CNODE: u64 = 2;
const CAP_INIT_THREAD_VSPACE: u64 = 3;
const CAP_INIT_UNTYPED: u64 = 11;
/// First empty slot — see BootInfo `empty.start`.
const FIRST_EMPTY_SLOT: u64 = 12;
/// Slot we'll write the new Endpoint into.
const SLOT_ENDPOINT: u64 = 12;
/// Slot we'll write the new child TCB into.
const SLOT_CHILD_TCB: u64 = 13;

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

/// 5-arg SYSCALL — used for cap-based invocations like
/// `Untyped::Retype`. The kernel takes:
///   rdi=cap_ptr, rsi=MessageInfo, rdx=arg0, r10=arg1, r8=arg2.
#[inline(always)]
unsafe fn syscall5(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        in("rax") nr as u64,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        in("r8") a4,
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

/// Invoke `Untyped::Retype` on the cap at `untyped_cap_ptr`. The
/// kernel carves `num_objects` instances of `obj_type` out of the
/// untyped's free range and writes the resulting caps into our root
/// CNode starting at `dest_offset`.
///
/// Returns 0 on success, non-zero on error (kernel writes
/// `u64::MAX` into rax for any `KException::SyscallError`).
#[inline(always)]
fn untyped_retype(
    untyped_cap_ptr: u64,
    obj_type: u64,
    user_size_bits: u32,
    num_objects: u32,
    dest_offset: u64,
) -> u64 {
    let msg_info = LBL_UNTYPED_RETYPE << 12;
    let size_num = ((user_size_bits as u64) << 32) | (num_objects as u64);
    unsafe {
        syscall5(SYS_SEND, untyped_cap_ptr, msg_info, obj_type, size_num, dest_offset)
    }
}

/// `TCB::SetSpace(target, fault_ep, cnode_cptr, vspace_cptr)`.
#[inline(always)]
fn tcb_set_space(target: u64, fault_ep: u64, cnode: u64, vspace: u64) -> u64 {
    let msg_info = LBL_TCB_SET_SPACE << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, fault_ep, cnode, vspace) }
}

/// `TCB::WriteRegisters(target, rip, rsp, arg0)`.
#[inline(always)]
fn tcb_write_registers(target: u64, rip: u64, rsp: u64, arg0: u64) -> u64 {
    let msg_info = LBL_TCB_WRITE_REGISTERS << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, rip, rsp, arg0) }
}

/// `TCB::Resume(target)`.
#[inline(always)]
fn tcb_resume(target: u64) -> u64 {
    let msg_info = LBL_TCB_RESUME << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, 0, 0, 0) }
}

/// IPC `Send` on an Endpoint cap. `length` words are taken from
/// `msg_regs[]` (here just one — `data` goes through rdx → msg_regs[0]).
#[inline(always)]
fn ep_send_one(endpoint: u64, data: u64) -> u64 {
    // MessageInfo: bits 0..6 = length (1 word). label = 0.
    let msg_info: u64 = 1;
    unsafe { syscall5(SYS_SEND, endpoint, msg_info, data, 0, 0) }
}

/// IPC `Recv` on an Endpoint cap. The kernel fans IPC return into
/// rdi=badge, rsi=MessageInfo, rdx/r10/r8/r9=msg_regs[0..3]. Returns
/// `(rax, rdi, rsi, rdx)` so the caller can read the message.
#[inline(always)]
unsafe fn ep_recv(endpoint: u64) -> (u64, u64, u64, u64) {
    let rax: u64;
    let rdi: u64;
    let rsi: u64;
    let rdx: u64;
    asm!(
        "syscall",
        in("rax") SYS_RECV as u64,
        inout("rdi") endpoint => rdi,
        lateout("rax") rax,
        lateout("rsi") rsi,
        lateout("rdx") rdx,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    (rax, rdi, rsi, rdx)
}

// ---------------------------------------------------------------------------
// Child thread state. Phase 29h spawns a single worker pinned to the
// rootserver's VSpace; we own its stack here in BSS and pass the
// linker-known address of `child_entry` as its entry point.
// ---------------------------------------------------------------------------

#[repr(C, align(16))]
struct ChildStack([u8; 4096]);
static mut CHILD_STACK: ChildStack = ChildStack([0; 4096]);

/// Child-thread entry. Sends one IPC over the shared endpoint, then
/// yields forever. `extern "C"` so the calling convention matches
/// what the kernel sets up via `TCB::WriteRegisters`.
#[no_mangle]
#[link_section = ".text.child"]
pub unsafe extern "C" fn child_entry() -> ! {
    // 0xCAFE is the sentinel the rootserver receives on the other
    // side; we picked it for visibility in serial output.
    ep_send_one(SLOT_ENDPOINT, 0xCAFE);
    loop {
        yield_now();
    }
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

fn print_hex(n: u64) {
    if n == 0 {
        debug_put_char(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    let mut x = n;
    while x > 0 {
        i -= 1;
        let nyb = (x & 0xF) as u8;
        buf[i] = if nyb < 10 { b'0' + nyb } else { b'a' + nyb - 10 };
        x >>= 4;
    }
    print_str(&buf[i..]);
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

    // Phase 29g — retype the Untyped into one Endpoint, written
    // into our CNode at slot FIRST_EMPTY_SLOT.
    let r = untyped_retype(
        CAP_INIT_UNTYPED,
        OBJ_ENDPOINT,
        /* user_size_bits */ 0,
        /* num_objects */    1,
        /* dest_offset */    SLOT_ENDPOINT,
    );

    if r != 0 {
        print_str(b"[rootserver retype Endpoint FAILED]\n");
        loop { yield_now(); }
    }
    print_str(b"[rootserver retyped Untyped -> Endpoint at slot ");
    print_u64(SLOT_ENDPOINT);
    print_str(b"]\n");

    // Phase 29h — retype another TCB out of the same Untyped,
    // configure it (share rootserver's VSpace + CSpace), Resume,
    // then SysRecv on the endpoint we just made. The child sends
    // an IPC carrying 0xCAFE; we print it.
    let r = untyped_retype(
        CAP_INIT_UNTYPED,
        OBJ_TCB,
        /* user_size_bits */ 0,
        /* num_objects */    1,
        /* dest_offset */    SLOT_CHILD_TCB,
    );
    if r != 0 {
        print_str(b"[rootserver retype TCB FAILED]\n");
        loop { yield_now(); }
    }

    // SetSpace: child shares our CNode (slot 2) and VSpace (slot 3).
    // No fault EP for now (a2 = 0 → child faults are fatal).
    let r = tcb_set_space(
        SLOT_CHILD_TCB,
        /* fault_ep */ 0,
        CAP_INIT_THREAD_CNODE,
        CAP_INIT_THREAD_VSPACE,
    );
    if r != 0 { print_str(b"[setspace FAILED]\n"); loop { yield_now(); } }

    // WriteRegisters: child starts at child_entry with rsp at the
    // top of its dedicated stack page.
    let child_rip = child_entry as u64;
    let child_rsp = (&raw mut CHILD_STACK as u64) + 4096 - 8;
    let r = tcb_write_registers(
        SLOT_CHILD_TCB,
        child_rip,
        child_rsp,
        /* arg0 */ 0,
    );
    if r != 0 { print_str(b"[writeregs FAILED]\n"); loop { yield_now(); } }

    // Resume the child. It enters the scheduler queue at default
    // priority; the next dispatch picks one of us — when we block
    // on Recv below, the child runs.
    let r = tcb_resume(SLOT_CHILD_TCB);
    if r != 0 { print_str(b"[resume FAILED]\n"); loop { yield_now(); } }

    // Receive the child's message. Blocks until it arrives.
    let (rax, _badge, _info, payload) = ep_recv(SLOT_ENDPOINT);
    if rax != 0 {
        print_str(b"[recv FAILED]\n");
        loop { yield_now(); }
    }
    print_str(b"[rootserver got 0x");
    print_hex(payload);
    print_str(b" from child]\n");

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
