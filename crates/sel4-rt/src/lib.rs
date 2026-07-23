//! # `sel4-rt` — user-space ABI for the rust-micro kernel
//!
//! The syscall stubs, invocation labels, object types, `BootInfo` layout, and
//! invocation helpers every root task on this kernel needs. Factored out of the
//! rootserver so the demo rootserver, `vendor/surt-demo`, and the
//! `userspace-ntos` components all speak one ABI instead of each hand-rolling
//! (and silently drifting from) their own copy.
//!
//! `no_std`, no dependencies. Each binary still provides its own `_start`
//! (entry) and `#[panic_handler]`; everything reusable lives here.
//!
//! ## ABI notes
//! - This kernel **preserves `rax` across SYSCALL** — the stubs return `0`
//!   unconditionally; errors surface via message registers / fault delivery, not
//!   a return code. So `if r != 0 { ... }` on a helper's result is a no-op;
//!   verify by behaviour, not the return value.
//! - Cap invocations use the 5-arg form: `rdi=cap_ptr, rsi=MessageInfo,
//!   r10/r8/r9 = msg_reg[0..2]` (mirrors upstream seL4's x86-64 stubs).

#![no_std]

use core::arch::asm;

// --- Syscall numbers (mirror codegen/syscall.xml) --------------------------
pub const SYS_CALL: i64 = -1;
pub const SYS_SEND: i64 = -5;
pub const SYS_NB_SEND: i64 = -6;
pub const SYS_RECV: i64 = -7;
pub const SYS_YIELD: i64 = -11;
pub const SYS_DEBUG_PUT_CHAR: i64 = -12;

// --- Invocation labels ------------------------------------------------------
pub const LBL_UNTYPED_RETYPE: u64 = 1;
pub const LBL_TCB_WRITE_REGISTERS: u64 = 3;
pub const LBL_TCB_CONFIGURE: u64 = 5;
pub const LBL_TCB_SET_PRIORITY: u64 = 6;
pub const LBL_TCB_SET_IPC_BUFFER: u64 = 10;
pub const LBL_TCB_SET_SPACE: u64 = 11;
pub const LBL_TCB_RESUME: u64 = 13;
pub const LBL_CNODE_COPY: u64 = 25;
pub const LBL_CNODE_MINT: u64 = 26;
pub const LBL_IRQ_ISSUE_IRQ_HANDLER: u64 = 30;
pub const LBL_IRQ_SET_IRQ_HANDLER: u64 = 32;
pub const LBL_SCHED_CONTROL_CONFIGURE: u64 = 37;
pub const LBL_SCHED_CONTEXT_BIND: u64 = 38;
pub const LBL_X86_PDPT_MAP: u64 = 43;
pub const LBL_X86_PAGE_DIRECTORY_MAP: u64 = 45;
pub const LBL_X86_PAGE_TABLE_MAP: u64 = 47;
pub const LBL_X86_PAGE_MAP: u64 = 51;
pub const LBL_X86_PAGE_UNMAP: u64 = 52;

// --- Object types -----------------------------------------------------------
pub const OBJ_UNTYPED: u64 = 0;
pub const OBJ_TCB: u64 = 1;
pub const OBJ_ENDPOINT: u64 = 2;
pub const OBJ_NOTIFICATION: u64 = 3;
pub const OBJ_CNODE: u64 = 4; // CapTable
pub const OBJ_SCHED_CONTEXT: u64 = 5;
pub const OBJ_REPLY: u64 = 6;
pub const OBJ_X86_PDPT: u64 = 7;
pub const OBJ_X86_PML4: u64 = 8;
pub const OBJ_X86_4K_PAGE: u64 = 9;
pub const OBJ_X86_PAGE_TABLE: u64 = 11;
pub const OBJ_X86_PAGE_DIRECTORY: u64 = 12;

pub const SCHED_CONTEXT_BITS: u32 = 8;
pub const PAGING_BITS: u32 = 12;

/// MessageInfo `extraCaps` field shift (bits 7-8).
pub const MSG_EXTRA_CAPS_SHIFT: u64 = 7;

// --- Fixed boot caps --------------------------------------------------------
pub const CAP_INIT_THREAD_CNODE: u64 = 2;
pub const CAP_INIT_THREAD_VSPACE: u64 = 3;
pub const SLOT_IRQ_CONTROL: u64 = 4;
pub const SLOT_SCHED_CONTROL: u64 = 16;
pub const CAP_INIT_UNTYPED: u64 = 20;

// ---------------------------------------------------------------------------
// Syscall stubs.
// ---------------------------------------------------------------------------

/// 1-arg SYSCALL (rdi=a0).
#[inline(always)]
pub unsafe fn syscall1(nr: i64, a0: u64) -> u64 {
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

/// 0-arg SYSCALL.
#[inline(always)]
pub unsafe fn syscall0(nr: i64) -> u64 {
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
/// r10/r8/r9 = msg_reg[0..2].
#[inline(always)]
pub unsafe fn syscall5(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
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
pub fn debug_put_char(c: u8) {
    unsafe {
        syscall1(SYS_DEBUG_PUT_CHAR, c as u64);
    }
}

#[inline(always)]
pub fn yield_now() {
    unsafe {
        syscall0(SYS_YIELD);
    }
}

// ---------------------------------------------------------------------------
// Invocation helpers. Each returns the stub's `0` (see the ABI note above).
// ---------------------------------------------------------------------------

/// `Untyped::Retype` — carve `num_objects` of `obj_type` into the invoker's
/// CNode starting at `dest_offset`.
#[inline(always)]
pub fn untyped_retype(
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
pub fn tcb_set_space(target: u64, fault_ep: u64, cnode: u64, vspace: u64) -> u64 {
    let msg_info = LBL_TCB_SET_SPACE << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, fault_ep, cnode, vspace) }
}

/// `TCB::WriteRegisters(target, rip, rsp, arg0)`.
#[inline(always)]
pub fn tcb_write_registers(target: u64, rip: u64, rsp: u64, arg0: u64) -> u64 {
    let msg_info = LBL_TCB_WRITE_REGISTERS << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, rip, rsp, arg0) }
}

/// `TCB::Resume(target)`.
#[inline(always)]
pub fn tcb_resume(target: u64) -> u64 {
    let msg_info = LBL_TCB_RESUME << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, 0, 0, 0) }
}

/// `TCB::SetPriority(target, prio)`.
#[inline(always)]
pub fn tcb_set_priority(target: u64, prio: u64) -> u64 {
    let msg_info = LBL_TCB_SET_PRIORITY << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, prio, 0, 0) }
}

/// `TCB::SetIPCBuffer(target, vaddr, frame_cptr)` (legacy ABI: `a2=vaddr,
/// a3=frame_cptr`).
#[inline(always)]
pub fn tcb_set_ipc_buffer(target: u64, vaddr: u64, frame_cptr: u64) -> u64 {
    let msg_info = LBL_TCB_SET_IPC_BUFFER << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, vaddr, frame_cptr, 0) }
}

/// `TCBSetTLSBase` invocation label.
pub const LBL_TCB_SET_TLS_BASE: u64 = 20;

/// Set the target thread's user `%gs` base — the Windows TEB anchor (`%gs:[0x30]` = TEB self).
/// (a2 = base, a3 = 1 selects `%gs`; a3 = 0 would select `%fs`.)
#[inline(always)]
pub fn tcb_set_gs_base(target: u64, base: u64) -> u64 {
    let msg_info = LBL_TCB_SET_TLS_BASE << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, base, 1, 0) }
}

/// `SchedControl::ConfigureFlags(target_sc, budget, period)`.
#[inline(always)]
pub fn sched_control_configure(sched_control: u64, target_sc_cptr: u64, budget: u64, period: u64) -> u64 {
    let msg_info = LBL_SCHED_CONTROL_CONFIGURE << 12;
    unsafe { syscall5(SYS_SEND, sched_control, msg_info, target_sc_cptr, budget, period) }
}

/// `SchedContext::Bind(target_sc, tcb_cap)`.
#[inline(always)]
pub fn sched_context_bind(sc_cptr: u64, tcb_cptr: u64) -> u64 {
    let msg_info = LBL_SCHED_CONTEXT_BIND << 12;
    unsafe { syscall5(SYS_SEND, sc_cptr, msg_info, tcb_cptr, 0, 0) }
}

/// `IRQControl::IssueIRQHandler(irq, dest_slot)`.
#[inline(always)]
pub fn irq_control_issue_handler(irq_control: u64, irq: u64, dest_slot: u64) -> u64 {
    let msg_info = LBL_IRQ_ISSUE_IRQ_HANDLER << 12;
    unsafe { syscall5(SYS_SEND, irq_control, msg_info, irq, dest_slot, 0) }
}

/// `IRQHandler::SetIRQHandler(notification_cap)`.
#[inline(always)]
pub fn irq_handler_set_notification(irq_handler: u64, notification_cap: u64) -> u64 {
    let msg_info = LBL_IRQ_SET_IRQ_HANDLER << 12;
    unsafe { syscall5(SYS_SEND, irq_handler, msg_info, notification_cap, 0, 0) }
}

/// `X86Pdpt/PageDirectory/PageTable::Map(vaddr, vspace_cptr)`. Pass the matching
/// `LBL_X86_*_MAP` label.
#[inline(always)]
pub fn paging_struct_map(struct_cptr: u64, label: u64, vaddr: u64, vspace_cptr: u64) -> u64 {
    let msg_info = label << 12;
    unsafe { syscall5(SYS_SEND, struct_cptr, msg_info, vaddr, vspace_cptr, 0) }
}

/// `ExecuteNever` flag for the `page_map` rights word (bit 2). OR it into `rights`
/// to map a page non-executable (NX) — e.g. `3 | PAGE_EXECUTE_NEVER` for writable
/// non-executable data, giving a true W^X mapping.
pub const PAGE_EXECUTE_NEVER: u64 = 0b100;

/// `X86Page::Map(vaddr, rights, vspace_cptr)`. `rights`: bit1=read, bit0=write
/// (so `2` = RO, `3` = RW); OR in [`PAGE_EXECUTE_NEVER`] for a non-executable page.
#[inline(always)]
pub fn page_map(frame_cptr: u64, vaddr: u64, rights: u64, vspace_cptr: u64) -> u64 {
    let msg_info = LBL_X86_PAGE_MAP << 12;
    unsafe { syscall5(SYS_SEND, frame_cptr, msg_info, vaddr, rights, vspace_cptr) }
}

/// `X86Page::Unmap()` — clears the cap's `mapped` field so the frame can be
/// remapped elsewhere.
#[inline(always)]
pub fn page_unmap(frame_cptr: u64) -> u64 {
    let msg_info = LBL_X86_PAGE_UNMAP << 12;
    unsafe { syscall5(SYS_SEND, frame_cptr, msg_info, 0, 0, 0) }
}

/// `CNode::Copy` (legacy ABI): copy `src_cptr` (in the invoker's cspace_root)
/// into slot `dest_index` of `dest_root`.
#[inline(always)]
pub fn cnode_copy(dest_root: u64, dest_index: u64, src_cptr: u64) -> u64 {
    let msg_info = LBL_CNODE_COPY << 12;
    unsafe { syscall5(SYS_SEND, dest_root, msg_info, dest_index, src_cptr, 0) }
}

/// `CNode::Mint` (legacy ABI): mint `src_cptr` into slot `dest_index` of
/// `dest_root` with `badge` (for a CNode cap, `badge` encodes the guard:
/// `guard_size = badge & 0x3F`, `guard = badge >> 6`).
#[inline(always)]
pub fn cnode_mint(dest_root: u64, dest_index: u64, src_cptr: u64, badge: u64) -> u64 {
    let msg_info = LBL_CNODE_MINT << 12;
    unsafe { syscall5(SYS_SEND, dest_root, msg_info, dest_index, src_cptr, badge) }
}

/// IPC `Send` on an Endpoint cap carrying one word.
#[inline(always)]
pub fn ep_send_one(endpoint: u64, data: u64) -> u64 {
    let msg_info: u64 = 1; // length 1, label 0
    unsafe { syscall5(SYS_SEND, endpoint, msg_info, data, 0, 0) }
}

/// IPC `Recv` on an Endpoint/Notification cap. Returns `(0, badge, MessageInfo,
/// msg_reg[0])`. The kernel returns `msg_reg[1..3]` in r8/r9/r15 — declared
/// clobbered so the compiler doesn't keep a live value across the syscall.
#[inline(always)]
pub unsafe fn ep_recv(endpoint: u64) -> (u64, u64, u64, u64) {
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

// ---------------------------------------------------------------------------
// BootInfo — must match the kernel's `seL4_BootInfo` layout.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlotRegion {
    pub start: u64,
    pub end: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UntypedDesc {
    pub paddr: u64,
    pub size_bits: u8,
    pub is_device: u8,
    pub _padding: [u8; 6],
}

pub const MAX_BI_UNTYPED: usize = 230;

#[repr(C)]
pub struct BootInfo {
    pub extra_len: u64,
    pub node_id: u64,
    pub num_nodes: u64,
    pub num_iopt_levels: u64,
    pub ipc_buffer: *mut u8,
    pub empty: SlotRegion,
    pub shared_frames: SlotRegion,
    pub user_image_frames: SlotRegion,
    pub user_image_paging: SlotRegion,
    pub io_space_caps: SlotRegion,
    pub extra_bi_pages: SlotRegion,
    pub init_thread_cnode_size_bits: u64,
    pub init_thread_domain: u64,
    pub schedcontrol: SlotRegion,
    pub untyped: SlotRegion,
    pub untyped_list: [UntypedDesc; MAX_BI_UNTYPED],
    // Phase 0a — BOOTBOOT linear-framebuffer geometry, published by the
    // kernel when built with `extern-rootserver` (the only kernel that
    // boots this runtime). Mirrors the trailing gated fields of the
    // kernel's `seL4_BootInfo`. `fb_paddr` == 0 ⇒ no framebuffer. The
    // framebuffer's physical frames are the LAST device untyped in
    // `untyped_list` (is_device == 1, paddr == fb_paddr).
    pub fb_paddr: u64,
    pub fb_width: u32,
    pub fb_height: u32,
    pub fb_scanline: u32,
    pub fb_size: u32,
    pub fb_type: u32,
    /// Leading `user_image_frames` caps that back ELF PT_LOAD pages.
    /// Later caps are mappings private to the initial root task.
    pub user_image_elf_frame_count: u64,
}

// ---------------------------------------------------------------------------
// Serial print helpers (no allocator).
// ---------------------------------------------------------------------------

pub fn print_str(s: &[u8]) {
    for &b in s {
        debug_put_char(b);
    }
}

pub fn print_hex(n: u64) {
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

pub fn print_u64(mut n: u64) {
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
