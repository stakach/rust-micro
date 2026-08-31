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
//! - Ordinary syscall helpers clear the MCS reply register (`r12`) and this
//!   tree's direct-handoff marker register (`r13`). Helpers that intentionally
//!   offer or consume a reply cap must pass those registers explicitly.

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
pub const LBL_TCB_SET_BREAKPOINT: u64 = 16;
pub const LBL_TCB_GET_BREAKPOINT: u64 = 17;
pub const LBL_TCB_UNSET_BREAKPOINT: u64 = 18;
pub const LBL_TCB_CONFIGURE_SINGLE_STEPPING: u64 = 19;
pub const LBL_CNODE_COPY: u64 = 25;
pub const LBL_CNODE_MINT: u64 = 26;
pub const LBL_IRQ_ISSUE_IRQ_HANDLER: u64 = 30;
pub const LBL_IRQ_SET_IRQ_HANDLER: u64 = 32;
pub const LBL_SCHED_CONTROL_CONFIGURE: u64 = 37;
pub const LBL_SCHED_CONTEXT_BIND: u64 = 38;
pub const LBL_SCHED_CONTEXT_CONSUMED: u64 = 41;
pub const LBL_X86_PDPT_MAP: u64 = 43;
pub const LBL_X86_PAGE_DIRECTORY_MAP: u64 = 45;
pub const LBL_X86_PAGE_TABLE_MAP: u64 = 47;
pub const LBL_X86_PAGE_MAP: u64 = 51;
pub const LBL_X86_PAGE_UNMAP: u64 = 52;
pub const LBL_X86_ASID_POOL_ASSIGN: u64 = 56;
pub const LBL_TCB_SET_HOSTED_SYSCALLS: u64 = 66;
pub const LBL_TCB_READ_DEBUG_STATE: u64 = 67;
pub const LBL_SCHED_CONTEXT_READ_RUNTIME: u64 = 68;

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
pub const CAP_INIT_THREAD_ASID_POOL: u64 = 6;
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
        in("r12") 0u64,
        in("r13") 0u64,
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
        in("r12") 0u64,
        in("r13") 0u64,
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
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    0
}

/// Five-argument cap invocation that waits for a reply and returns its MessageInfo error label.
#[inline(always)]
pub unsafe fn syscall5_call(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let reply: u64;
    asm!(
        "syscall",
        in("rdx") SYS_CALL as u64,
        in("rdi") a0,
        inout("rsi") a1 => reply,
        in("r10") a2,
        in("r8")  a3,
        in("r9")  a4,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    reply >> 12
}

/// Five-argument cap invocation that waits for a reply and returns its
/// MessageInfo error label plus the first two message registers.
#[inline(always)]
pub unsafe fn syscall5_call_mr2(
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
) -> (u64, u64, u64) {
    let reply: u64;
    let mr0: u64;
    let mr1: u64;
    asm!(
        "syscall",
        in("rdx") SYS_CALL as u64,
        in("rdi") a0,
        inout("rsi") a1 => reply,
        inout("r10") a2 => mr0,
        inout("r8") a3 => mr1,
        in("r9") a4,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    (reply >> 12, mr0, mr1)
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
    unsafe {
        syscall5(
            SYS_SEND,
            untyped_cap_ptr,
            msg_info,
            obj_type,
            size_num,
            dest_offset,
        )
    }
}

/// Assign a freshly retyped PML4 an ASID from the initial pool.
///
/// This must run before installing paging structures or frames in the new VSpace. Frame caps retain
/// the assigned ASID so their later Unmap/Delete operation can locate the correct page-table root.
#[inline(always)]
pub fn vspace_assign_asid(pml4_cap_ptr: u64) -> u64 {
    unsafe {
        syscall5_call(
            CAP_INIT_THREAD_ASID_POOL,
            LBL_X86_ASID_POOL_ASSIGN << 12,
            pml4_cap_ptr,
            0,
            0,
        )
    }
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
pub fn sched_control_configure(
    sched_control: u64,
    target_sc_cptr: u64,
    budget: u64,
    period: u64,
) -> u64 {
    let msg_info = LBL_SCHED_CONTROL_CONFIGURE << 12;
    unsafe {
        syscall5(
            SYS_SEND,
            sched_control,
            msg_info,
            target_sc_cptr,
            budget,
            period,
        )
    }
}

/// `SchedContext::Bind(target_sc, tcb_cap)`.
#[inline(always)]
pub fn sched_context_bind(sc_cptr: u64, tcb_cptr: u64) -> u64 {
    let msg_info = LBL_SCHED_CONTEXT_BIND << 12;
    unsafe { syscall5(SYS_SEND, sc_cptr, msg_info, tcb_cptr, 0, 0) }
}

/// Report and reset the standard seL4 MCS consumed counter.
#[inline(always)]
pub fn sched_context_consumed(sc_cptr: u64) -> Result<u64, u64> {
    let (error, consumed_us, _) = unsafe {
        syscall5_call_mr2(
            sc_cptr,
            LBL_SCHED_CONTEXT_CONSUMED << 12,
            0,
            0,
            0,
        )
    };
    if error == 0 {
        Ok(consumed_us)
    } else {
        Err(error)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SchedContextRuntime {
    pub bound_time_us: u64,
    pub donated_time_us: u64,
}

/// Read cumulative scheduler time for the SC without resetting either
/// counter. This rust-micro extension preserves the standard consumed-report
/// ABI while giving hosted kernels authoritative user/server accounting.
#[inline(always)]
pub fn sched_context_read_runtime(sc_cptr: u64) -> Result<SchedContextRuntime, u64> {
    let (error, bound_time_us, donated_time_us) = unsafe {
        syscall5_call_mr2(
            sc_cptr,
            LBL_SCHED_CONTEXT_READ_RUNTIME << 12,
            0,
            0,
            0,
        )
    };
    if error == 0 {
        Ok(SchedContextRuntime {
            bound_time_us,
            donated_time_us,
        })
    } else {
        Err(error)
    }
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
        in("r12") 0u64,
        in("r13") 0u64,
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
pub const BOOT_WALL_CLOCK_VALID: u32 = 1 << 0;
pub const BOOT_WALL_CLOCK_UTC: u32 = 1 << 1;
pub const BOOT_PERSISTENT_CLOCK_VALID: u16 = 1 << 0;
pub const BOOT_PERSISTENT_CLOCK_CENTURY: u16 = 1 << 1;
pub const BOOT_PERSISTENT_CLOCK_PC_CMOS: u16 = 1;
pub const BOOT_ACPI_ROOT_VALID: u16 = 1 << 0;
pub const BOOT_ACPI_ROOT_RSDT: u16 = 1;
pub const BOOT_ACPI_ROOT_XSDT: u16 = 2;
pub const MAX_BOOT_IOAPICS: usize = 16;
pub const BOOTINFO_HEADER_IOAPIC_TOPOLOGY: u64 = u64::from_le_bytes(*b"NTIOAPIC");
pub const MAX_BOOT_FIRMWARE_MEMORY_RANGES: usize = 160;
pub const BOOTINFO_HEADER_FIRMWARE_MEMORY_MAP: u64 = u64::from_le_bytes(*b"NTFWMAP1");

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootWallClock {
    pub unix_seconds: i64,
    pub timezone_minutes: i32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootPcCmosClock {
    pub index_port: u16,
    pub data_port: u16,
    pub century_register: Option<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootAcpiRootKind {
    Rsdt,
    Xsdt,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootAcpiRootTable {
    pub paddr: u64,
    pub length: u32,
    pub kind: BootAcpiRootKind,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootIoApic {
    pub gsi_base: u32,
    pub redirection_entries: u16,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootFirmwareMemoryRange {
    pub base: u64,
    pub length: u64,
    pub e820_type: u32,
    pub extended_attributes: u32,
}

#[repr(C)]
struct BootIoApicTopology {
    count: u16,
    reserved: [u8; 6],
    controllers: [BootIoApic; MAX_BOOT_IOAPICS],
}

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
    // kernel's `seL4_BootInfo`. `fb_paddr` == 0 ⇒ no framebuffer. These
    // fields are scanout geometry; physical authority is the single PCI
    // BAR device untyped in `untyped_list` containing that range.
    pub fb_paddr: u64,
    pub fb_width: u32,
    pub fb_height: u32,
    pub fb_scanline: u32,
    pub fb_size: u32,
    pub fb_type: u32,
    /// Leading `user_image_frames` caps that back ELF PT_LOAD pages.
    /// Later caps are mappings private to the initial root task.
    pub user_image_elf_frame_count: u64,
    /// Validated UTC snapshot supplied by the platform boot adapter. Zero flags mean unavailable.
    pub wall_clock_unix_seconds: i64,
    pub wall_clock_timezone_minutes: i32,
    pub wall_clock_flags: u32,
    pub persistent_clock_kind: u16,
    pub persistent_clock_flags: u16,
    pub persistent_clock_index_port: u16,
    pub persistent_clock_data_port: u16,
    pub persistent_clock_century_register: u8,
    pub persistent_clock_reserved: [u8; 7],
    pub acpi_root_table_paddr: u64,
    pub acpi_root_table_length: u32,
    pub acpi_root_table_kind: u16,
    pub acpi_root_table_flags: u16,
    pub tsc_frequency_hz: u64,
}

impl BootInfo {
    pub fn wall_clock(&self) -> Option<BootWallClock> {
        let required = BOOT_WALL_CLOCK_VALID | BOOT_WALL_CLOCK_UTC;
        if self.wall_clock_flags & required != required {
            return None;
        }
        Some(BootWallClock {
            unix_seconds: self.wall_clock_unix_seconds,
            timezone_minutes: self.wall_clock_timezone_minutes,
        })
    }

    pub fn persistent_pc_cmos_clock(&self) -> Option<BootPcCmosClock> {
        if self.persistent_clock_kind != BOOT_PERSISTENT_CLOCK_PC_CMOS
            || self.persistent_clock_flags & BOOT_PERSISTENT_CLOCK_VALID == 0
            || self.persistent_clock_index_port == self.persistent_clock_data_port
        {
            return None;
        }
        Some(BootPcCmosClock {
            index_port: self.persistent_clock_index_port,
            data_port: self.persistent_clock_data_port,
            century_register: (self.persistent_clock_flags & BOOT_PERSISTENT_CLOCK_CENTURY != 0)
                .then_some(self.persistent_clock_century_register),
        })
    }

    pub fn acpi_root_table(&self) -> Option<BootAcpiRootTable> {
        if self.acpi_root_table_flags & BOOT_ACPI_ROOT_VALID == 0
            || self.acpi_root_table_paddr == 0
            || self.acpi_root_table_length < 36
        {
            return None;
        }
        let kind = match self.acpi_root_table_kind {
            BOOT_ACPI_ROOT_RSDT => BootAcpiRootKind::Rsdt,
            BOOT_ACPI_ROOT_XSDT => BootAcpiRootKind::Xsdt,
            _ => return None,
        };
        Some(BootAcpiRootTable {
            paddr: self.acpi_root_table_paddr,
            length: self.acpi_root_table_length,
            kind,
        })
    }

    pub fn tsc_frequency_hz(&self) -> Option<u64> {
        (self.tsc_frequency_hz != 0).then_some(self.tsc_frequency_hz)
    }

    pub fn ioapic_topology(&self) -> Option<&[BootIoApic]> {
        let topology = self
            .extra_bootinfo_chunk(BOOTINFO_HEADER_IOAPIC_TOPOLOGY)
            .and_then(|payload| {
                if payload.len() != core::mem::size_of::<BootIoApicTopology>() {
                    return None;
                }
                Some(unsafe { &*(payload.as_ptr() as *const BootIoApicTopology) })
            })?;
        if topology.reserved != [0; 6]
            || topology.count == 0
            || topology.count as usize > MAX_BOOT_IOAPICS
        {
            return None;
        }
        let controllers = &topology.controllers[..topology.count as usize];
        for (left_index, left) in controllers.iter().enumerate() {
            if left.reserved != 0 || left.redirection_entries == 0 {
                return None;
            }
            let left_end = left
                .gsi_base
                .checked_add(left.redirection_entries as u32)?;
            for right in &controllers[left_index + 1..] {
                let right_end = right
                    .gsi_base
                    .checked_add(right.redirection_entries as u32)?;
                if left.gsi_base < right_end && right.gsi_base < left_end {
                    return None;
                }
            }
        }
        Some(controllers)
    }

    /// Return the firmware-ordered BOOTBOOT memory map published by the kernel. These records are
    /// information only; physical authority still comes exclusively from BootInfo capabilities.
    pub fn firmware_memory_map(&self) -> Option<&[BootFirmwareMemoryRange]> {
        let payload = self.extra_bootinfo_chunk(BOOTINFO_HEADER_FIRMWARE_MEMORY_MAP)?;
        if payload.len() < 8 || payload[2..8] != [0; 6] {
            return None;
        }
        let count = u16::from_le_bytes(payload[..2].try_into().ok()?) as usize;
        if count == 0 || count > MAX_BOOT_FIRMWARE_MEMORY_RANGES {
            return None;
        }
        let records_len = count.checked_mul(core::mem::size_of::<BootFirmwareMemoryRange>())?;
        if payload.len() != 8usize.checked_add(records_len)? {
            return None;
        }
        let records = unsafe {
            core::slice::from_raw_parts(
                payload[8..].as_ptr() as *const BootFirmwareMemoryRange,
                count,
            )
        };
        for record in records {
            if record.length == 0
                || record.base.checked_add(record.length).is_none()
                || !(1..=4).contains(&record.e820_type)
                || record.extended_attributes & 1 == 0
            {
                return None;
            }
        }
        Some(records)
    }

    fn extra_bootinfo_chunk(&self, wanted: u64) -> Option<&[u8]> {
        const HEADER_LEN: usize = 16;
        let total = usize::try_from(self.extra_len).ok()?;
        if total == 0 || total > 4096 {
            return None;
        }
        let base = (self as *const Self as usize).checked_add(4096)? as *const u8;
        let bytes = unsafe { core::slice::from_raw_parts(base, total) };
        let mut offset = 0usize;
        while offset < total {
            let header_end = offset.checked_add(HEADER_LEN).filter(|end| *end <= total)?;
            let id = u64::from_le_bytes(bytes[offset..offset + 8].try_into().ok()?);
            let length = usize::try_from(u64::from_le_bytes(
                bytes[offset + 8..header_end].try_into().ok()?,
            ))
            .ok()?;
            let end = offset
                .checked_add(length)
                .filter(|end| length >= HEADER_LEN && *end <= total)?;
            if id == wanted {
                return Some(&bytes[header_end..end]);
            }
            offset = end;
        }
        None
    }
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
        buf[i] = if nyb < 10 {
            b'0' + nyb
        } else {
            b'a' + nyb - 10
        };
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
