//! SURT demo rootserver.
//!
//! A standalone seL4 root task (loaded as its own ELF by the rust-micro kernel)
//! that runs the SURT ring-transport scenarios using the **published
//! `surt-sel4` crate** from crates.io. It doubles as a usage showcase and a
//! smoke-test: each scenario prints `PASS`/`FAIL`, then the `[microtest done]`
//! sentinel the kernel's serial hook watches for to `qemu_exit`.
//!
//! This file is the low-level bootstrap — the seL4 syscall stubs, invocation
//! helpers, `BootInfo` decoding, and `_start` — exactly what any downstream
//! seL4 root task writes for this kernel. The actual SURT usage lives in
//! `scenarios.rs`, built on `surt_sel4::{Sel4Env, Sel4Notify, drain_blocking}`.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

mod scenarios;

// --- Syscall numbers (mirror codegen/syscall.xml) --------------------------
const SYS_YIELD: i64 = -11;
const SYS_DEBUG_PUT_CHAR: i64 = -12;
const SYS_SEND: i64 = -5;
const SYS_RECV: i64 = -7;

// --- Invocation labels ------------------------------------------------------
const LBL_UNTYPED_RETYPE: u64 = 1;
const LBL_TCB_WRITE_REGISTERS: u64 = 3;
const LBL_TCB_SET_SPACE: u64 = 11;
const LBL_TCB_RESUME: u64 = 13;
const LBL_TCB_SET_PRIORITY: u64 = 6;
const LBL_SCHED_CONTROL_CONFIGURE: u64 = 37;
const LBL_SCHED_CONTEXT_BIND: u64 = 38;
const LBL_X86_PDPT_MAP: u64 = 43;
const LBL_X86_PAGE_DIRECTORY_MAP: u64 = 45;
const LBL_X86_PAGE_TABLE_MAP: u64 = 47;
const LBL_X86_PAGE_MAP: u64 = 51;
const LBL_X86_PAGE_UNMAP: u64 = 52;

// --- Object types -----------------------------------------------------------
const OBJ_TCB: u64 = 1;
const OBJ_ENDPOINT: u64 = 2;
const OBJ_NOTIFICATION: u64 = 3;
const OBJ_SCHED_CONTEXT: u64 = 5;
const OBJ_X86_PDPT: u64 = 7;
const OBJ_X86_PML4: u64 = 8;
const OBJ_X86_4K_PAGE: u64 = 9;
const OBJ_X86_PAGE_TABLE: u64 = 11;
const OBJ_X86_PAGE_DIRECTORY: u64 = 12;
const SCHED_CONTEXT_BITS: u32 = 8;
const PAGING_BITS: u32 = 12;

// --- Fixed boot caps --------------------------------------------------------
const CAP_INIT_THREAD_CNODE: u64 = 2;
const CAP_INIT_THREAD_VSPACE: u64 = 3;
const SLOT_SCHED_CONTROL: u64 = 16;
const CAP_INIT_UNTYPED: u64 = 20;

// ---------------------------------------------------------------------------
// Syscall stubs. `rax` is preserved across SYSCALL on this kernel, so these
// return 0 unconditionally; errors surface as later-stage symptoms (or, for
// Recv, in the returned message registers).
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn syscall1(nr: i64, a0: u64) -> u64 {
    asm!(
        "syscall",
        in("rdx") nr as u64,
        in("rdi") a0,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    0
}

#[inline(always)]
unsafe fn syscall0(nr: i64) -> u64 {
    asm!(
        "syscall",
        in("rdx") nr as u64,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    0
}

/// 5-arg SYSCALL for cap invocations: rdi=cap_ptr, rsi=MessageInfo,
/// r10/r8/r9 = msg_reg[0..2] (mirrors upstream seL4).
#[inline(always)]
unsafe fn syscall5(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    asm!(
        "syscall",
        in("rdx") nr as u64,
        in("rdi") a0,
        in("rsi") a1,
        in("r10") a2,
        in("r8")  a3,
        in("r9")  a4,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    0
}

#[inline(always)]
pub(crate) fn debug_put_char(c: u8) {
    unsafe {
        syscall1(SYS_DEBUG_PUT_CHAR, c as u64);
    }
}

#[inline(always)]
fn yield_now() {
    unsafe {
        syscall0(SYS_YIELD);
    }
}

/// `Untyped::Retype` — carve `num_objects` of `obj_type` into our CNode at
/// `dest_offset`.
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
    unsafe { syscall5(SYS_SEND, untyped_cap_ptr, msg_info, obj_type, size_num, dest_offset) }
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

/// `TCB::SetPriority(target, prio)`.
#[inline(always)]
fn tcb_set_priority(target: u64, prio: u64) -> u64 {
    let msg_info = LBL_TCB_SET_PRIORITY << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, prio, 0, 0) }
}

/// `SchedControl::ConfigureFlags(target_sc, budget, period)`.
#[inline(always)]
fn sched_control_configure(sched_control: u64, target_sc_cptr: u64, budget: u64, period: u64) -> u64 {
    let msg_info = LBL_SCHED_CONTROL_CONFIGURE << 12;
    unsafe { syscall5(SYS_SEND, sched_control, msg_info, target_sc_cptr, budget, period) }
}

/// `SchedContext::Bind(target_sc, tcb_cap)`.
#[inline(always)]
fn sched_context_bind(sc_cptr: u64, tcb_cptr: u64) -> u64 {
    let msg_info = LBL_SCHED_CONTEXT_BIND << 12;
    unsafe { syscall5(SYS_SEND, sc_cptr, msg_info, tcb_cptr, 0, 0) }
}

/// `X86Pdpt/PageDirectory/PageTable::Map(vaddr, vspace_cptr)`.
#[inline(always)]
fn paging_struct_map(struct_cptr: u64, label: u64, vaddr: u64, vspace_cptr: u64) -> u64 {
    let msg_info = label << 12;
    unsafe { syscall5(SYS_SEND, struct_cptr, msg_info, vaddr, vspace_cptr, 0) }
}

/// `X86Page::Map(vaddr, rights, vspace_cptr)`.
#[inline(always)]
fn page_map(frame_cptr: u64, vaddr: u64, rights: u64, vspace_cptr: u64) -> u64 {
    let msg_info = LBL_X86_PAGE_MAP << 12;
    unsafe { syscall5(SYS_SEND, frame_cptr, msg_info, vaddr, rights, vspace_cptr) }
}

/// `X86Page::Unmap()` — clears the cap's `mapped` field so the frame can be
/// remapped elsewhere.
#[inline(always)]
fn page_unmap(frame_cptr: u64) -> u64 {
    let msg_info = LBL_X86_PAGE_UNMAP << 12;
    unsafe { syscall5(SYS_SEND, frame_cptr, msg_info, 0, 0, 0) }
}

/// IPC `Send` on an Endpoint cap carrying one word.
#[inline(always)]
fn ep_send_one(endpoint: u64, data: u64) -> u64 {
    let msg_info: u64 = 1; // length 1, label 0
    unsafe { syscall5(SYS_SEND, endpoint, msg_info, data, 0, 0) }
}

/// IPC `Recv` on an Endpoint/Notification cap. Returns (0, badge, MessageInfo,
/// msg_reg[0]). The kernel returns msg_reg[1..3] in r8/r9/r15 — declared
/// clobbered so the compiler doesn't keep a live value across the syscall.
#[inline(always)]
unsafe fn ep_recv(endpoint: u64) -> (u64, u64, u64, u64) {
    let rdi: u64;
    let rsi: u64;
    let r10: u64;
    asm!(
        "syscall",
        in("rdx") SYS_RECV as u64,
        inout("rdi") endpoint => rdi,
        lateout("rax") _,
        lateout("rsi") rsi,
        lateout("r10") r10,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r15") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    (0, rdi, rsi, r10)
}

// --- BootInfo (must match the kernel's seL4_BootInfo layout) ----------------
#[repr(C)]
#[derive(Copy, Clone)]
struct SlotRegion {
    start: u64,
    end: u64,
}

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
    schedcontrol: SlotRegion,
    untyped: SlotRegion,
    untyped_list: [UntypedDesc; MAX_BI_UNTYPED],
}

// --- Print helpers (no allocator) -------------------------------------------
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

// --- Entry ------------------------------------------------------------------
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
