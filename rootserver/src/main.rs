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

#[cfg(feature = "microtest")]
mod microtest;

// ---------------------------------------------------------------------------
// Syscall numbers — must stay in sync with `codegen/syscall.xml`
// (mirrored in target/.../syscalls.rs after kernel build). Hand-listed
// here because the kernel doesn't currently expose its syscall ABI as
// a separate crate.
// ---------------------------------------------------------------------------

// Phase 36b — MCS syscall numbering (api-mcs block).
const SYS_DEBUG_PUT_CHAR: i64 = -12;
const SYS_YIELD: i64 = -11;
const SYS_SEND: i64 = -5;
const SYS_RECV: i64 = -7;

/// `InvocationLabel`s we issue. Phase 32a flipped CONFIG_KERNEL_MCS
/// on so the TCB labels shifted: SetSpace went 10 → 11, Resume
/// went 12 → 13. (WriteRegisters at 3 is identical across both.)
const LBL_UNTYPED_RETYPE: u64 = 1;
const LBL_TCB_WRITE_REGISTERS: u64 = 3;
const LBL_TCB_SET_SPACE: u64 = 11;
const LBL_TCB_RESUME: u64 = 13;
/// Phase 32g — MCS labels, generated under CONFIG_KERNEL_MCS.
const LBL_SCHED_CONTROL_CONFIGURE: u64 = 33;
const LBL_SCHED_CONTEXT_BIND: u64 = 34;
const LBL_TCB_SET_PRIORITY: u64 = 6;
/// Phase 33b — IRQ-handler invocations.
const LBL_IRQ_ISSUE_IRQ_HANDLER: u64 = 26;
const LBL_IRQ_SET_IRQ_HANDLER: u64 = 28;
/// Phase 33d — X86 paging map invocations. Each `Map` invocation
/// installs a paging structure or frame at a vaddr in a vspace
/// (passed via args.a3 / a4 — see `decode_pt_map` &c. in the
/// kernel).
const LBL_X86_PDPT_MAP: u64 = 39;
const LBL_X86_PAGE_DIRECTORY_MAP: u64 = 41;
const LBL_X86_PAGE_TABLE_MAP: u64 = 43;
const LBL_X86_PAGE_MAP: u64 = 45;
const LBL_X86_PAGE_UNMAP: u64 = 46;

/// `seL4_ObjectType` values we use here.
const OBJ_TCB: u64 = 1;
const OBJ_ENDPOINT: u64 = 2;
const OBJ_NOTIFICATION: u64 = 3;
/// `ObjectType::SchedContext` — order in `object_type.rs`. We use the
/// minimum 8 bits = 256 bytes per SC, well above the SchedContext
/// struct's footprint.
const OBJ_SCHED_CONTEXT: u64 = 5;
const SCHED_CONTEXT_BITS: u32 = 8;
/// Phase 33d — x86 paging-structure object types. Numeric tags
/// match `object_type::X86_*`. The kernel's `untyped::create_object`
/// expects size_bits=12 (one 4 KiB page) for each paging level.
// Phase 42 — must match upstream libsel4's seL4_X86_*Object enum
// values for compatibility with sel4test-built userland (which uses
// the same numbers). With NonArchObjectTypeCount = 7 (MCS) and
// ModeObjectTypeCount = 9 (no HUGE_PAGE on x86_64).
const OBJ_X86_PDPT: u64 = 7;
const OBJ_X86_PML4: u64 = 8;
const OBJ_X86_4K_PAGE: u64 = 9;
const OBJ_X86_PAGE_TABLE: u64 = 11;
const OBJ_X86_PAGE_DIRECTORY: u64 = 12;
const PAGING_BITS: u32 = 12;

/// Initial CNode slots (mirrors the kernel's `seL4_RootCNodeCapSlots`).
/// Phase 36e — moved to upstream-canonical layout. Slots 0..15
/// are the canonical initial caps; 16..19 hold per-CPU
/// SchedControl caps; 20 holds the boot Untyped; 21+ is empty.
const CAP_INIT_THREAD_CNODE: u64 = 2;
const CAP_INIT_THREAD_VSPACE: u64 = 3;
/// Phase 33b — slot the kernel installs a `Cap::IrqControl` into.
const SLOT_IRQ_CONTROL: u64 = 4;
const CAP_INIT_UNTYPED: u64 = 20;
/// First empty slot — see BootInfo `empty.start`.
const FIRST_EMPTY_SLOT: u64 = 21;
/// Slot we'll write the new Endpoint into.
const SLOT_ENDPOINT: u64 = 21;
/// Slot we'll write the new child TCB into.
const SLOT_CHILD_TCB: u64 = 22;
/// Phase 32g — first per-CPU SchedControl cap (core 0). Phase 36e
/// moved this from a single slot at 14 to a region at 16+.
const SLOT_SCHED_CONTROL: u64 = 16;
/// Slots for the two MCS children's SchedContext + TCB caps.
const SLOT_SC_HIGH: u64 = 23;
const SLOT_SC_LOW: u64 = 24;
const SLOT_TCB_HIGH: u64 = 25;
const SLOT_TCB_LOW: u64 = 26;
/// IRQ demo slots.
const SLOT_IRQ_NTFN: u64 = 27;
const SLOT_IRQ_HANDLER: u64 = 28;
/// IRQ used in the demo (PIC1 line 1 → IDT vector 0x21).
const DEMO_IRQ: u64 = 1;
/// Phase 33d — multi-VSpace demo slots.
const SLOT_NEW_PML4: u64 = 29;
const SLOT_NEW_PDPT: u64 = 30;
const SLOT_NEW_PD:   u64 = 31;
const SLOT_NEW_PT:   u64 = 32;
const SLOT_NEW_FRAME: u64 = 33;
/// Vaddr inside the new vspace where we'll map the test frame.
/// Picked at PML4[1] (well above the rootserver's own image at
/// PML4[2]) so it doesn't collide with anything cloned from the
/// live PML4 by the kernel-half copy.
const NEW_VSPACE_FRAME_VADDR: u64 = 0x0000_0080_0000_0000;

/// Phase 33d follow-up — full-isolation child dispatch.
///
/// The new PML4 (slot 21) is cloned with kernel-half + identity
/// only, so the child runs in a vspace where PML4[1..256] is
/// initially empty — the rootserver image at PML4[2] is *not*
/// visible. We use the PDPT/PD/PT chain installed by
/// `multi_vspace_demo` (slots 22/23/24, rooted at PML4[1] of the
/// new PML4) to map the child's code + stack at fresh PT entries.
///
/// To bootstrap the code page's contents, the rootserver maps the
/// (initially-blank) frame in its OWN vspace at a scratch vaddr
/// inside a freshly-retyped PT (slot 26) installed at PD[4] of
/// the rootserver's PD. After memcpy, `X86PageUnmap` clears the
/// cap's `mapped` flag so we can re-map the same Frame in the
/// new vspace.
const SLOT_OWN_SCRATCH_PT: u64 = 34;
const SLOT_VSPACE_CODE_FRAME: u64 = 35;
const SLOT_VSPACE_STACK_FRAME: u64 = 36;
const SLOT_VSPACE_CHILD_TCB: u64 = 37;
/// Vaddr inside the rootserver's own vspace where we temporarily
/// stage the child's code page for memcpy. PD[4] is empty in the
/// rootserver's PD (PD[2] is the image PT), so we can install a
/// fresh PT there without colliding with the rootserver's own
/// mappings.
const OWN_SCRATCH_VADDR: u64 = 0x0000_0100_0080_0000;
/// Vaddrs in the new vspace where the child runs. Both share
/// slot 24's PT (mapped at PML4[1] PDPT[0] PD[0] in the new PML4),
/// so they fall in the same 2 MiB window. PT[0] is occupied by
/// the 33d demo frame; we use PT[16] / PT[32] which are unused.
const VSPACE_CODE_VADDR: u64 = NEW_VSPACE_FRAME_VADDR + 16 * 0x1000;
const VSPACE_STACK_VADDR: u64 = NEW_VSPACE_FRAME_VADDR + 32 * 0x1000;

/// Hand-assembled child code: send IPC carrying 0xBEEF over the
/// endpoint at SLOT_ENDPOINT, then yield-loop forever.
///
/// Phase 36b: syscall numbers shifted to the MCS layout.
/// Phase 36e: SLOT_ENDPOINT moved 12 → 21 (canonical initial-cap
/// layout pushed Untyped + first-empty past the upstream slot
/// reservations).
/// Phase 38c: SYSCALL ABI aligned to upstream seL4 — syscall number
/// in rdx (was rax), msg_reg[0] in r10 (was rdx).
///   mov rdx, -5       ; SYS_SEND
///   mov rdi, 21       ; endpoint cap_ptr (= SLOT_ENDPOINT)
///   mov rsi, 1        ; MessageInfo: length=1, label=0
///   mov r10, 0xBEEF   ; msg_reg[0] = payload
///   syscall
/// .loop:
///   mov rdx, -11      ; SYS_YIELD
///   syscall
///   jmp .loop
static VSPACE_CHILD_CODE: [u8; 41] = [
    0x48, 0xC7, 0xC2, 0xFB, 0xFF, 0xFF, 0xFF, // mov rdx, -5
    0x48, 0xC7, 0xC7, 0x15, 0x00, 0x00, 0x00, // mov rdi, 21
    0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, // mov rsi, 1
    0x49, 0xC7, 0xC2, 0xEF, 0xBE, 0x00, 0x00, // mov r10, 0xBEEF
    0x0F, 0x05,                               // syscall
    0x48, 0xC7, 0xC2, 0xF5, 0xFF, 0xFF, 0xFF, // mov rdx, -11
    0x0F, 0x05,                               // syscall
    0xEB, 0xF5,                               // jmp -11 → mov rdx, -11
];

// ---------------------------------------------------------------------------
// Syscall stubs — upstream-seL4 SYSCALL ABI (Phase 38c) with the
// 38c-followup that drops the kernel's rax-as-result extension:
//   rdx = syscall number
//   rdi = capRegister / cap_ptr (a0)
//   rsi = msgInfoRegister (a1)
//   r10, r8, r9, r15 = msg_regs[0..3] (a2..a5)
//   rcx (clobbered by SYSCALL HW) = saved user RIP
//   r11 (clobbered by SYSCALL HW) = saved user RFLAGS
//   rax = preserved across the syscall (matches upstream).
//
// We mark rax as `lateout("rax") _` so the compiler knows it may be
// clobbered and won't keep live values there across the asm block.
// The stubs return 0 unconditionally — error detection now goes via
// msginfo labels and fault delivery, not via a kernel-set rax. The
// existing `if r != 0 { return Err(...) }` checks in tests become
// no-ops; failures show up as later-stage symptoms instead.
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

/// 5-arg SYSCALL — used for cap-based invocations like
/// `Untyped::Retype`. Upstream seL4 takes:
///   rdi=cap_ptr, rsi=MessageInfo, r10=msg_reg[0], r8=msg_reg[1],
///   r9=msg_reg[2]. We mirror that — a2..a4 land in r10/r8/r9.
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

/// `TCB::SetPriority(target, prio)`. Required by the MCS demo so
/// the children share the rootserver's priority and get scheduled
/// when it yields (a fresh TCB is priority 0 by default).
#[inline(always)]
fn tcb_set_priority(target: u64, prio: u64) -> u64 {
    let msg_info = LBL_TCB_SET_PRIORITY << 12;
    unsafe { syscall5(SYS_SEND, target, msg_info, prio, 0, 0) }
}

/// `SchedControl::ConfigureFlags(target_sc=cptr, budget, period)`.
/// ABI: a0 = SchedControl cptr (consumed by handle_send),
/// a2 = target SC cptr, a3 = budget, a4 = period.
#[inline(always)]
fn sched_control_configure(
    sched_control: u64,
    target_sc_cptr: u64,
    budget: u64,
    period: u64,
) -> u64 {
    let msg_info = LBL_SCHED_CONTROL_CONFIGURE << 12;
    unsafe {
        syscall5(SYS_SEND, sched_control, msg_info, target_sc_cptr, budget, period)
    }
}

/// `SchedContext::Bind(target_sc, tcb_cap)`. Ties the SC's refill
/// schedule to the TCB so PIT-driven mcs_tick charges/parks/wakes it.
#[inline(always)]
fn sched_context_bind(sc_cptr: u64, tcb_cptr: u64) -> u64 {
    let msg_info = LBL_SCHED_CONTEXT_BIND << 12;
    unsafe { syscall5(SYS_SEND, sc_cptr, msg_info, tcb_cptr, 0, 0) }
}

/// `IRQControl::IssueIRQHandler(irq, dest_slot)`. The kernel
/// installs an `IRQHandler { irq }` cap at `dest_slot` of the
/// invoker's CSpace.
#[inline(always)]
fn irq_control_issue_handler(irq_control: u64, irq: u64, dest_slot: u64) -> u64 {
    let msg_info = LBL_IRQ_ISSUE_IRQ_HANDLER << 12;
    unsafe { syscall5(SYS_SEND, irq_control, msg_info, irq, dest_slot, 0) }
}

/// `IRQHandler::SetIRQHandler(notification_cap)`. Binds the IRQ
/// to a notification — when the IRQ fires, the kernel signals
/// the notification.
#[inline(always)]
fn irq_handler_set_notification(irq_handler: u64, notification_cap: u64) -> u64 {
    let msg_info = LBL_IRQ_SET_IRQ_HANDLER << 12;
    unsafe { syscall5(SYS_SEND, irq_handler, msg_info, notification_cap, 0, 0) }
}

/// `X86Pdpt/PageDirectory/PageTable::Map(vaddr, vspace_cptr)`.
/// Installs the paging structure at `vaddr` in `vspace_cptr`'s
/// PML4 chain (when `vspace_cptr == 0` the kernel falls back to
/// the live CR3, which is the pre-Phase-33d behaviour).
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

/// `X86Page::Unmap()`. The kernel clears the cap's `mapped` field
/// (so the Frame can be remapped elsewhere) and, outside spec
/// mode, walks the live CR3's page tables to clear the leaf PTE.
#[inline(always)]
fn page_unmap(frame_cptr: u64) -> u64 {
    let msg_info = LBL_X86_PAGE_UNMAP << 12;
    unsafe { syscall5(SYS_SEND, frame_cptr, msg_info, 0, 0, 0) }
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
/// rdi=badge, rsi=MessageInfo, r10/r8/r9/r15=msg_regs[0..3] (matches
/// upstream seL4's `x64_sys_recv` stub). Phase 38c-followup — rax is
/// preserved (no longer carries a result code); the tuple's first
/// slot returns 0 to keep the existing `if rax != 0` checks
/// trivially false.
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
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    (0, rdi, rsi, r10)
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
// Phase 32g — mixed-criticality demo. We spawn two children; each
// runs a tight `print + yield` loop printing a single-byte tag. The
// SchedContext bound to each child rate-limits its CPU time:
//   high — period=10 budget=8 → ~80% of ticks → emits 'H'
//   low  — period=10 budget=2 → ~20% of ticks → emits 'B'
// The kernel's syscall_entry exit hook samples the bytes and exits
// QEMU once we've seen enough of each to verify the ratio.
// ---------------------------------------------------------------------------

static mut HIGH_STACK: ChildStack = ChildStack([0; 4096]);
static mut LOW_STACK: ChildStack = ChildStack([0; 4096]);

#[no_mangle]
#[link_section = ".text.high"]
pub unsafe extern "C" fn high_child_entry() -> ! {
    loop {
        debug_put_char(b'H');
        yield_now();
    }
}

#[no_mangle]
#[link_section = ".text.low"]
pub unsafe extern "C" fn low_child_entry() -> ! {
    loop {
        debug_put_char(b'B');
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
    /// Phase 36c — per-CPU SchedControl caps under MCS.
    schedcontrol: SlotRegion,
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
    // Phase 34a — when built with `--features microtest`, replace
    // the legacy demos with the structured test harness. The
    // harness prints `[microtest done]\n` when finished; the
    // kernel's exit hook in syscall_entry catches that sentinel
    // and qemu_exits.
    #[cfg(feature = "microtest")]
    {
        let _ = bootinfo;
        microtest::run();
        loop { yield_now(); }
    }

    #[cfg(not(feature = "microtest"))]
    {
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

    // -----------------------------------------------------------------
    // Phase 33b — IRQ → Notification demo. Issue an IRQHandler for
    // a free vector, bind a notification, fire the IRQ via `int
    // 0x21`, then `SysRecv` on the notification (which returns
    // immediately since the IRQ already signalled it).
    // -----------------------------------------------------------------
    irq_demo();

    // -----------------------------------------------------------------
    // Phase 33d — multi-VSpace setup. Retype a fresh PML4 + PDPT +
    // PD + PT + Frame, install them in the hierarchy, then map the
    // frame at a chosen vaddr.
    // -----------------------------------------------------------------
    multi_vspace_demo();

    // -----------------------------------------------------------------
    // Phase 33d follow-up — dispatch a child TCB into the new
    // VSpace. The child runs hand-assembled code copied into a
    // freshly-retyped frame, sends an IPC carrying 0xBEEF, and
    // we confirm receipt to verify the dispatch worked.
    // -----------------------------------------------------------------
    vspace_child_dispatch_demo();

    // -----------------------------------------------------------------
    // Phase 32g — mixed-criticality demo. The kernel's exit hook
    // counts H/B prints from the children to verify MCS budget
    // enforcement.
    // -----------------------------------------------------------------
    spawn_mcs_children();

    loop {
        yield_now();
    }
    } // end #[cfg(not(feature = "microtest"))]
}

unsafe fn irq_demo() {
    // 1. Retype a notification out of the rootserver's Untyped.
    let r = untyped_retype(
        CAP_INIT_UNTYPED, OBJ_NOTIFICATION,
        /* user_size_bits */ 0, /* num_objects */ 1, SLOT_IRQ_NTFN);
    if r != 0 { print_str(b"[irq retype ntfn FAILED]\n"); return; }

    // 2. Issue an IRQHandler for IRQ 1 into slot SLOT_IRQ_HANDLER.
    let r = irq_control_issue_handler(SLOT_IRQ_CONTROL, DEMO_IRQ, SLOT_IRQ_HANDLER);
    if r != 0 { print_str(b"[irq issue handler FAILED]\n"); return; }

    // 3. Bind the notification to the IRQ.
    let r = irq_handler_set_notification(SLOT_IRQ_HANDLER, SLOT_IRQ_NTFN);
    if r != 0 { print_str(b"[irq set ntfn FAILED]\n"); return; }

    // 4. Fire the IRQ. Vector 0x21 = PIC1_VECTOR_BASE (0x20) + 1.
    //    The kernel installs IDT[0x21] with DPL=3 for the demo, so
    //    user-mode `int 0x21` is allowed.
    asm!("int 0x21", options(nostack, preserves_flags));

    // 5. Wait on the notification. The IRQ already signalled, so
    //    this returns immediately with rax=0.
    let (rax, _badge, _info, _payload) = ep_recv(SLOT_IRQ_NTFN);
    if rax != 0 {
        print_str(b"[irq recv FAILED]\n");
        return;
    }
    print_str(b"[rootserver got irq signal -- IRQ -> Notification path live]\n");
}

unsafe fn multi_vspace_demo() {
    // 1. Retype the four paging structures + a frame, all 4 KiB
    //    each. They're carved sequentially out of the same
    //    Untyped — the kernel handles alignment.
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4,
                           PAGING_BITS, 1, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[mvs retype PML4 FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT,
                           PAGING_BITS, 1, SLOT_NEW_PDPT);
    if r != 0 { print_str(b"[mvs retype PDPT FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY,
                           PAGING_BITS, 1, SLOT_NEW_PD);
    if r != 0 { print_str(b"[mvs retype PD FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE,
                           PAGING_BITS, 1, SLOT_NEW_PT);
    if r != 0 { print_str(b"[mvs retype PT FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
                           PAGING_BITS, 1, SLOT_NEW_FRAME);
    if r != 0 { print_str(b"[mvs retype Frame FAILED]\n"); return; }

    // 2. Install the paging hierarchy in the new PML4. Each level
    //    walks down to the leaf vaddr `NEW_VSPACE_FRAME_VADDR`.
    let r = paging_struct_map(SLOT_NEW_PDPT, LBL_X86_PDPT_MAP,
                              NEW_VSPACE_FRAME_VADDR, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[mvs PDPT::Map FAILED]\n"); return; }
    let r = paging_struct_map(SLOT_NEW_PD, LBL_X86_PAGE_DIRECTORY_MAP,
                              NEW_VSPACE_FRAME_VADDR, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[mvs PD::Map FAILED]\n"); return; }
    let r = paging_struct_map(SLOT_NEW_PT, LBL_X86_PAGE_TABLE_MAP,
                              NEW_VSPACE_FRAME_VADDR, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[mvs PT::Map FAILED]\n"); return; }

    // 3. Map the leaf frame. Rights word = ReadWrite (FrameRights
    //    encoding mirrors `cap.rs`: ReadWrite = 3).
    let r = page_map(SLOT_NEW_FRAME, NEW_VSPACE_FRAME_VADDR,
                     /* rights ReadWrite */ 3, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[mvs Page::Map FAILED]\n"); return; }

    print_str(b"[multi-vspace setup ok -- PML4/PDPT/PD/PT/Frame mapped]\n");
}

/// Phase 33d follow-up — fully-isolated child dispatch.
///
/// The new PML4 is cloned with kernel-half + identity only, so the
/// child runs in a vspace where the user-half (PML4[1..256]) is
/// entirely fresh — the rootserver image at PML4[2] is invisible.
/// To make the child runnable we:
///   1. retype a fresh PT (`SLOT_OWN_SCRATCH_PT`) and map it into
///      a free slot of the rootserver's own PD (PD[4]) so the
///      rootserver can stage memory at `OWN_SCRATCH_VADDR`.
///   2. retype a code Frame, map it at `OWN_SCRATCH_VADDR`,
///      memcpy the hand-assembled child stub, then `X86PageUnmap`
///      to release the Frame's `mapped` flag.
///   3. retype a stack Frame.
///   4. map the code Frame at `VSPACE_CODE_VADDR` and the stack
///      Frame at `VSPACE_STACK_VADDR` in the new vspace
///      (both share the existing 33d-setup PT at slot 24).
///   5. retype a child TCB, `SetSpace` with the new PML4 + shared
///      CNode, `WriteRegisters`, `SetPriority`, `Resume`.
///   6. block on `SysRecv` for the child's 0xBEEF IPC over the
///      shared endpoint at slot 12.
///
/// No memory is shared between the rootserver and child user
/// vspaces beyond the slot-12 endpoint cap (which is in the shared
/// CSpace, not in either vspace's user half).
unsafe fn vspace_child_dispatch_demo() {
    // Step 1 — install a scratch PT in the rootserver's own vspace.
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE,
                           PAGING_BITS, 1, SLOT_OWN_SCRATCH_PT);
    if r != 0 { print_str(b"[vspace retype own PT FAILED]\n"); return; }
    let r = paging_struct_map(SLOT_OWN_SCRATCH_PT, LBL_X86_PAGE_TABLE_MAP,
                              OWN_SCRATCH_VADDR, CAP_INIT_THREAD_VSPACE);
    if r != 0 { print_str(b"[vspace own PT map FAILED]\n"); return; }

    // Step 2 — code Frame, mapped at OWN_SCRATCH_VADDR, populated,
    // then unmapped from own vspace.
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
                           PAGING_BITS, 1, SLOT_VSPACE_CODE_FRAME);
    if r != 0 { print_str(b"[vspace retype code FAILED]\n"); return; }
    let r = page_map(SLOT_VSPACE_CODE_FRAME, OWN_SCRATCH_VADDR,
                     /* RW */ 3, CAP_INIT_THREAD_VSPACE);
    if r != 0 { print_str(b"[vspace code stage map FAILED]\n"); return; }
    let dst = OWN_SCRATCH_VADDR as *mut u8;
    for (i, &b) in VSPACE_CHILD_CODE.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), b);
    }
    let r = page_unmap(SLOT_VSPACE_CODE_FRAME);
    if r != 0 { print_str(b"[vspace code unmap FAILED]\n"); return; }

    // Step 3 — stack Frame. No staging needed (zero-init is fine
    // for an initial stack).
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
                           PAGING_BITS, 1, SLOT_VSPACE_STACK_FRAME);
    if r != 0 { print_str(b"[vspace retype stack FAILED]\n"); return; }

    // Step 4 — install both frames in the *new* vspace via the
    // existing 33d-setup PT (slot 24, mapped at PML4[1] PDPT[0]
    // PD[0] of the new PML4).
    let r = page_map(SLOT_VSPACE_CODE_FRAME, VSPACE_CODE_VADDR,
                     3, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[vspace code map new FAILED]\n"); return; }
    let r = page_map(SLOT_VSPACE_STACK_FRAME, VSPACE_STACK_VADDR,
                     3, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[vspace stack map FAILED]\n"); return; }

    // Step 5 — retype + dispatch the child.
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB,
                           /* user_size_bits */ 0, 1, SLOT_VSPACE_CHILD_TCB);
    if r != 0 { print_str(b"[vspace retype tcb FAILED]\n"); return; }
    let r = tcb_set_space(SLOT_VSPACE_CHILD_TCB, /* fault_ep */ 0,
                          CAP_INIT_THREAD_CNODE, SLOT_NEW_PML4);
    if r != 0 { print_str(b"[vspace setspace FAILED]\n"); return; }
    let stack_top = VSPACE_STACK_VADDR + 4096 - 8;
    let r = tcb_write_registers(SLOT_VSPACE_CHILD_TCB,
                                VSPACE_CODE_VADDR, stack_top, /* arg0 */ 0);
    if r != 0 { print_str(b"[vspace writeregs FAILED]\n"); return; }
    let r = tcb_set_priority(SLOT_VSPACE_CHILD_TCB, 100);
    if r != 0 { print_str(b"[vspace setprio FAILED]\n"); return; }
    let r = tcb_resume(SLOT_VSPACE_CHILD_TCB);
    if r != 0 { print_str(b"[vspace resume FAILED]\n"); return; }

    // Step 6 — wait for the child's 0xBEEF IPC.
    let (rax, _badge, _info, payload) = ep_recv(SLOT_ENDPOINT);
    if rax != 0 {
        print_str(b"[vspace recv FAILED]\n");
        return;
    }
    print_str(b"[vspace child sent 0x");
    print_hex(payload);
    print_str(b" via isolated PML4]\n");
}

unsafe fn spawn_mcs_children() {
    // 1. Retype two SchedContexts out of the rootserver's Untyped.
    //    Each is the minimum size (256 bytes — small but enough,
    //    since the kernel-side `SchedContext` lives in the static
    //    pool, not in this memory).
    let r = untyped_retype(
        CAP_INIT_UNTYPED,
        OBJ_SCHED_CONTEXT,
        SCHED_CONTEXT_BITS,
        /* num_objects */ 2,
        SLOT_SC_HIGH,
    );
    if r != 0 { print_str(b"[mcs retype SC FAILED]\n"); return; }

    // 2. Configure budgets. period=10, high gets 8 ticks, low gets 2.
    let r = sched_control_configure(
        SLOT_SCHED_CONTROL, SLOT_SC_HIGH, /* budget */ 8, /* period */ 10);
    if r != 0 { print_str(b"[mcs configure high FAILED]\n"); return; }
    let r = sched_control_configure(
        SLOT_SCHED_CONTROL, SLOT_SC_LOW,  /* budget */ 2, /* period */ 10);
    if r != 0 { print_str(b"[mcs configure low FAILED]\n"); return; }

    // 3. Retype two TCBs.
    let r = untyped_retype(
        CAP_INIT_UNTYPED, OBJ_TCB, /* user_size_bits */ 0, /* num_objects */ 2,
        SLOT_TCB_HIGH);
    if r != 0 { print_str(b"[mcs retype TCB FAILED]\n"); return; }

    // 4. Wire each child: SetSpace (share our CSpace + VSpace),
    //    WriteRegisters (entry + stack), SetPriority (so the
    //    scheduler picks them when we yield), Bind to its SC,
    //    Resume.
    if !configure_child(SLOT_TCB_HIGH, high_child_entry as u64,
                        (&raw mut HIGH_STACK as u64) + 4096 - 8,
                        SLOT_SC_HIGH, b"H") { return; }
    if !configure_child(SLOT_TCB_LOW, low_child_entry as u64,
                        (&raw mut LOW_STACK as u64) + 4096 - 8,
                        SLOT_SC_LOW, b"B") { return; }

    print_str(b"[mcs demo: H/B children launched]\n");
}

unsafe fn configure_child(
    tcb_slot: u64, rip: u64, rsp: u64, sc_slot: u64, tag: &[u8],
) -> bool {
    let r = tcb_set_space(tcb_slot, /* fault_ep */ 0,
                          CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
    if r != 0 {
        print_str(b"[mcs setspace ");
        print_str(tag);
        print_str(b" FAILED]\n");
        return false;
    }
    let r = tcb_write_registers(tcb_slot, rip, rsp, /* arg0 */ 0);
    if r != 0 {
        print_str(b"[mcs writeregs ");
        print_str(tag);
        print_str(b" FAILED]\n");
        return false;
    }
    // Match the rootserver's priority so the scheduler picks this
    // child when the rootserver yields. Default priority of a fresh
    // TCB is 0, which is below the rootserver's 100 — without this
    // the child would never be dispatched.
    let r = tcb_set_priority(tcb_slot, /* prio */ 100);
    if r != 0 {
        print_str(b"[mcs setprio ");
        print_str(tag);
        print_str(b" FAILED]\n");
        return false;
    }
    let r = sched_context_bind(sc_slot, tcb_slot);
    if r != 0 {
        print_str(b"[mcs bind ");
        print_str(tag);
        print_str(b" FAILED]\n");
        return false;
    }
    let r = tcb_resume(tcb_slot);
    if r != 0 {
        print_str(b"[mcs resume ");
        print_str(tag);
        print_str(b" FAILED]\n");
        return false;
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Best-effort: print '!' then halt-loop via SysYield.
    debug_put_char(b'!');
    loop {
        yield_now();
    }
}
