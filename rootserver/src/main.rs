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
use core::sync::atomic::{AtomicUsize, Ordering};

// The kernel's shared user-space ABI — syscall stubs, invocation labels, object
// types, invocation helpers, and BootInfo. Re-exported at crate root so the
// demo code below and `microtest`'s `use crate::*` resolve it unchanged.
pub use sel4_rt::*;

#[cfg(feature = "microtest")]
mod microtest;

/// IRQ used in the demo (PIC1 line 1 → IDT vector 0x21).
const DEMO_IRQ: u64 = 1;

/// Base of the empty CNode region, captured from `BootInfo.empty.start`
/// in `_start`. The boot cap layout is not a fixed size (it grows with
/// the runtime user-image frame caps), so every destination slot the
/// demo retypes into must be derived from this base — a hardcoded slot
/// number targets an occupied slot and the retype fails `DeleteFirst`.
static EMPTY_BASE: AtomicUsize = AtomicUsize::new(0);
#[inline]
fn empty_slot(off: u64) -> u64 {
    EMPTY_BASE.load(Ordering::Relaxed) as u64 + off
}
// Named destination slots, as offsets from the empty base.
#[inline] fn slot_endpoint() -> u64 { empty_slot(0) }
#[inline] fn slot_child_tcb() -> u64 { empty_slot(1) }
#[inline] fn slot_sc_high() -> u64 { empty_slot(2) }
#[inline] fn slot_sc_low() -> u64 { empty_slot(3) }
#[inline] fn slot_tcb_high() -> u64 { empty_slot(4) }
#[inline] fn slot_tcb_low() -> u64 { empty_slot(5) }
#[inline] fn slot_irq_ntfn() -> u64 { empty_slot(6) }
#[inline] fn slot_irq_handler() -> u64 { empty_slot(7) }
#[inline] fn slot_new_pml4() -> u64 { empty_slot(8) }
#[inline] fn slot_new_pdpt() -> u64 { empty_slot(9) }
#[inline] fn slot_new_pd() -> u64 { empty_slot(10) }
#[inline] fn slot_new_pt() -> u64 { empty_slot(11) }
#[inline] fn slot_new_frame() -> u64 { empty_slot(12) }
#[inline] fn slot_own_scratch_pt() -> u64 { empty_slot(13) }
#[inline] fn slot_vspace_code_frame() -> u64 { empty_slot(14) }
#[inline] fn slot_vspace_stack_frame() -> u64 { empty_slot(15) }
#[inline] fn slot_vspace_child_tcb() -> u64 { empty_slot(16) }
#[inline] fn slot_endpoint_child_sc() -> u64 { empty_slot(17) }
#[inline] fn slot_vspace_child_sc() -> u64 { empty_slot(18) }
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
/// new vspace. (These four are `slot_own_scratch_pt()` …
/// `slot_vspace_child_tcb()`, offsets 13..16 from the empty base.)
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
/// endpoint at slot_endpoint(), then yield-loop forever.
///
/// Phase 36b: syscall numbers shifted to the MCS layout.
/// Phase 36e: slot_endpoint() moved 12 → 21 (canonical initial-cap
/// layout pushed Untyped + first-empty past the upstream slot
/// reservations).
/// Phase 38c: SYSCALL ABI aligned to upstream seL4 — syscall number
/// in rdx (was rax), msg_reg[0] in r10 (was rdx).
///   mov rdx, -5       ; SYS_SEND
///   mov rdi, 21       ; endpoint cap_ptr (= slot_endpoint())
///   mov rsi, 1        ; MessageInfo: length=1, label=0
///   mov r10, 0xBEEF   ; msg_reg[0] = payload
///   syscall
/// .loop:
///   mov rdx, -11      ; SYS_YIELD
///   syscall
///   jmp .loop
static VSPACE_CHILD_CODE: [u8; 41] = [
    0x48, 0xC7, 0xC2, 0xFB, 0xFF, 0xFF, 0xFF, // mov rdx, -5
    0x48, 0xC7, 0xC7, 0x15, 0x00, 0x00, 0x00, // mov rdi, <ep> (imm32 patched at runtime, offset 10)
    0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, // mov rsi, 1
    0x49, 0xC7, 0xC2, 0xEF, 0xBE, 0x00, 0x00, // mov r10, 0xBEEF
    0x0F, 0x05,                               // syscall
    0x48, 0xC7, 0xC2, 0xF5, 0xFF, 0xFF, 0xFF, // mov rdx, -11
    0x0F, 0x05,                               // syscall
    0xEB, 0xF5,                               // jmp -11 → mov rdx, -11
];

/// Retype a fresh SchedContext into `sc_slot`, configure it round-robin
/// (budget == period ⇒ always runnable), and bind it to `tcb_slot`. Under
/// MCS a TCB with no bound SchedContext is Resume-able but never dispatched,
/// so every worker the demo expects to actually run needs this. Returns true
/// on success.
fn attach_sc_to(tcb_slot: u64, sc_slot: u64) -> bool {
    let r = untyped_retype(
        CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc_slot);
    if r != 0 { return false; }
    // Legacy/spec ABI: budget/period in raw ticks (tick = 1 ms).
    let r = sched_control_configure(SLOT_SCHED_CONTROL, sc_slot, 10, 10);
    if r != 0 { return false; }
    sched_context_bind(sc_slot, tcb_slot) == 0
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
    ep_send_one(slot_endpoint(), 0xCAFE);
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
        // The kernel maps our IPC buffer at a vaddr it derives from the loaded
        // image's layout (ELF-driven, commit df8c734) and publishes it here.
        // It is NOT a fixed address — pass it to the harness rather than
        // hardcoding (a stale constant faults once the binary size shifts it).
        let ipc_buffer_vaddr = (*bootinfo).ipc_buffer as u64;
        // The first empty CNode slot the kernel hands us. The boot cap layout
        // (initial caps + untypeds + schedcontrol + user-image frame caps) is
        // not a fixed size, so the harness must allocate slots from here rather
        // than hardcoding — otherwise its retypes target occupied slots and
        // fail with seL4_DeleteFirst (silently, since rax is preserved).
        let empty_start = (*bootinfo).empty.start;
        microtest::run(ipc_buffer_vaddr, empty_start);
        loop { yield_now(); }
    }

    #[cfg(not(feature = "microtest"))]
    {
        let bi = &*bootinfo;
        // Anchor every demo destination slot to the kernel-reported first
        // empty slot (the boot cap layout is not a fixed size).
        EMPTY_BASE.store(bi.empty.start as usize, Ordering::Relaxed);
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
        /* dest_offset */    slot_endpoint(),
    );

    if r != 0 {
        print_str(b"[rootserver retype Endpoint FAILED]\n");
        loop { yield_now(); }
    }
    print_str(b"[rootserver retyped Untyped -> Endpoint at slot ");
    print_u64(slot_endpoint());
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
        /* dest_offset */    slot_child_tcb(),
    );
    if r != 0 {
        print_str(b"[rootserver retype TCB FAILED]\n");
        loop { yield_now(); }
    }

    // SetSpace: child shares our CNode (slot 2) and VSpace (slot 3).
    // No fault EP for now (a2 = 0 → child faults are fatal).
    let r = tcb_set_space(
        slot_child_tcb(),
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
        slot_child_tcb(),
        child_rip,
        child_rsp,
        /* arg0 */ 0,
    );
    if r != 0 { print_str(b"[writeregs FAILED]\n"); loop { yield_now(); } }

    // MCS: bind a SchedContext so the child is actually schedulable when we
    // block on Recv below (a no-SC TCB is Resume-able but never dispatched).
    if !attach_sc_to(slot_child_tcb(), slot_endpoint_child_sc()) {
        print_str(b"[child SC bind FAILED]\n"); loop { yield_now(); }
    }

    // Resume the child. It enters the scheduler queue at default
    // priority; the next dispatch picks one of us — when we block
    // on Recv below, the child runs.
    let r = tcb_resume(slot_child_tcb());
    if r != 0 { print_str(b"[resume FAILED]\n"); loop { yield_now(); } }

    // Receive the child's message. Blocks until it arrives.
    let (rax, _badge, _info, payload) = ep_recv(slot_endpoint());
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
        /* user_size_bits */ 0, /* num_objects */ 1, slot_irq_ntfn());
    if r != 0 { print_str(b"[irq retype ntfn FAILED]\n"); return; }

    // 2. Issue an IRQHandler for IRQ 1 into slot slot_irq_handler().
    let r = irq_control_issue_handler(SLOT_IRQ_CONTROL, DEMO_IRQ, slot_irq_handler());
    if r != 0 { print_str(b"[irq issue handler FAILED]\n"); return; }

    // 3. Bind the notification to the IRQ.
    let r = irq_handler_set_notification(slot_irq_handler(), slot_irq_ntfn());
    if r != 0 { print_str(b"[irq set ntfn FAILED]\n"); return; }

    // 4. Fire the IRQ. Vector 0x21 = PIC1_VECTOR_BASE (0x20) + 1.
    //    The kernel installs IDT[0x21] with DPL=3 for the demo, so
    //    user-mode `int 0x21` is allowed.
    asm!("int 0x21", options(nostack, preserves_flags));

    // 5. Wait on the notification. The IRQ already signalled, so
    //    this returns immediately with rax=0.
    let (rax, _badge, _info, _payload) = ep_recv(slot_irq_ntfn());
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
                           PAGING_BITS, 1, slot_new_pml4());
    if r != 0 { print_str(b"[mvs retype PML4 FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT,
                           PAGING_BITS, 1, slot_new_pdpt());
    if r != 0 { print_str(b"[mvs retype PDPT FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY,
                           PAGING_BITS, 1, slot_new_pd());
    if r != 0 { print_str(b"[mvs retype PD FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE,
                           PAGING_BITS, 1, slot_new_pt());
    if r != 0 { print_str(b"[mvs retype PT FAILED]\n"); return; }
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
                           PAGING_BITS, 1, slot_new_frame());
    if r != 0 { print_str(b"[mvs retype Frame FAILED]\n"); return; }

    // 2. Install the paging hierarchy in the new PML4. Each level
    //    walks down to the leaf vaddr `NEW_VSPACE_FRAME_VADDR`.
    let r = paging_struct_map(slot_new_pdpt(), LBL_X86_PDPT_MAP,
                              NEW_VSPACE_FRAME_VADDR, slot_new_pml4());
    if r != 0 { print_str(b"[mvs PDPT::Map FAILED]\n"); return; }
    let r = paging_struct_map(slot_new_pd(), LBL_X86_PAGE_DIRECTORY_MAP,
                              NEW_VSPACE_FRAME_VADDR, slot_new_pml4());
    if r != 0 { print_str(b"[mvs PD::Map FAILED]\n"); return; }
    let r = paging_struct_map(slot_new_pt(), LBL_X86_PAGE_TABLE_MAP,
                              NEW_VSPACE_FRAME_VADDR, slot_new_pml4());
    if r != 0 { print_str(b"[mvs PT::Map FAILED]\n"); return; }

    // 3. Map the leaf frame. Rights word = ReadWrite (FrameRights
    //    encoding mirrors `cap.rs`: ReadWrite = 3).
    let r = page_map(slot_new_frame(), NEW_VSPACE_FRAME_VADDR,
                     /* rights ReadWrite */ 3, slot_new_pml4());
    if r != 0 { print_str(b"[mvs Page::Map FAILED]\n"); return; }

    print_str(b"[multi-vspace setup ok -- PML4/PDPT/PD/PT/Frame mapped]\n");
}

/// Phase 33d follow-up — fully-isolated child dispatch.
///
/// The new PML4 is cloned with kernel-half + identity only, so the
/// child runs in a vspace where the user-half (PML4[1..256]) is
/// entirely fresh — the rootserver image at PML4[2] is invisible.
/// To make the child runnable we:
///   1. retype a fresh PT (`slot_own_scratch_pt()`) and map it into
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
                           PAGING_BITS, 1, slot_own_scratch_pt());
    if r != 0 { print_str(b"[vspace retype own PT FAILED]\n"); return; }
    let r = paging_struct_map(slot_own_scratch_pt(), LBL_X86_PAGE_TABLE_MAP,
                              OWN_SCRATCH_VADDR, CAP_INIT_THREAD_VSPACE);
    if r != 0 { print_str(b"[vspace own PT map FAILED]\n"); return; }

    // Step 2 — code Frame, mapped at OWN_SCRATCH_VADDR, populated,
    // then unmapped from own vspace.
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
                           PAGING_BITS, 1, slot_vspace_code_frame());
    if r != 0 { print_str(b"[vspace retype code FAILED]\n"); return; }
    let r = page_map(slot_vspace_code_frame(), OWN_SCRATCH_VADDR,
                     /* RW */ 3, CAP_INIT_THREAD_VSPACE);
    if r != 0 { print_str(b"[vspace code stage map FAILED]\n"); return; }
    let dst = OWN_SCRATCH_VADDR as *mut u8;
    for (i, &b) in VSPACE_CHILD_CODE.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), b);
    }
    // Patch the baked-in endpoint cptr: the code's `mov rdi, imm32` (the send
    // target) has its imm32 at code offset 10. The real endpoint slot is
    // runtime now (empty.start-relative), not the hardcoded 21 in the bytes.
    let ep_le = (slot_endpoint() as u32).to_le_bytes();
    for (i, &b) in ep_le.iter().enumerate() {
        core::ptr::write_volatile(dst.add(10 + i), b);
    }
    let r = page_unmap(slot_vspace_code_frame());
    if r != 0 { print_str(b"[vspace code unmap FAILED]\n"); return; }

    // Step 3 — stack Frame. No staging needed (zero-init is fine
    // for an initial stack).
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
                           PAGING_BITS, 1, slot_vspace_stack_frame());
    if r != 0 { print_str(b"[vspace retype stack FAILED]\n"); return; }

    // Step 4 — install both frames in the *new* vspace via the
    // existing 33d-setup PT (slot 24, mapped at PML4[1] PDPT[0]
    // PD[0] of the new PML4).
    let r = page_map(slot_vspace_code_frame(), VSPACE_CODE_VADDR,
                     3, slot_new_pml4());
    if r != 0 { print_str(b"[vspace code map new FAILED]\n"); return; }
    let r = page_map(slot_vspace_stack_frame(), VSPACE_STACK_VADDR,
                     3, slot_new_pml4());
    if r != 0 { print_str(b"[vspace stack map FAILED]\n"); return; }

    // Step 5 — retype + dispatch the child.
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB,
                           /* user_size_bits */ 0, 1, slot_vspace_child_tcb());
    if r != 0 { print_str(b"[vspace retype tcb FAILED]\n"); return; }
    let r = tcb_set_space(slot_vspace_child_tcb(), /* fault_ep */ 0,
                          CAP_INIT_THREAD_CNODE, slot_new_pml4());
    if r != 0 { print_str(b"[vspace setspace FAILED]\n"); return; }
    let stack_top = VSPACE_STACK_VADDR + 4096 - 8;
    let r = tcb_write_registers(slot_vspace_child_tcb(),
                                VSPACE_CODE_VADDR, stack_top, /* arg0 */ 0);
    if r != 0 { print_str(b"[vspace writeregs FAILED]\n"); return; }
    let r = tcb_set_priority(slot_vspace_child_tcb(), 100);
    if r != 0 { print_str(b"[vspace setprio FAILED]\n"); return; }
    // MCS: bind a SchedContext so the isolated-VSpace child gets dispatched.
    if !attach_sc_to(slot_vspace_child_tcb(), slot_vspace_child_sc()) {
        print_str(b"[vspace SC bind FAILED]\n"); return;
    }
    let r = tcb_resume(slot_vspace_child_tcb());
    if r != 0 { print_str(b"[vspace resume FAILED]\n"); return; }

    // Step 6 — wait for the child's 0xBEEF IPC.
    let (rax, _badge, _info, payload) = ep_recv(slot_endpoint());
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
        slot_sc_high(),
    );
    if r != 0 { print_str(b"[mcs retype SC FAILED]\n"); return; }

    // 2. Configure budgets. period=10, high gets 8 ticks, low gets 2.
    let r = sched_control_configure(
        SLOT_SCHED_CONTROL, slot_sc_high(), /* budget */ 8, /* period */ 10);
    if r != 0 { print_str(b"[mcs configure high FAILED]\n"); return; }
    let r = sched_control_configure(
        SLOT_SCHED_CONTROL, slot_sc_low(),  /* budget */ 2, /* period */ 10);
    if r != 0 { print_str(b"[mcs configure low FAILED]\n"); return; }

    // 3. Retype two TCBs.
    let r = untyped_retype(
        CAP_INIT_UNTYPED, OBJ_TCB, /* user_size_bits */ 0, /* num_objects */ 2,
        slot_tcb_high());
    if r != 0 { print_str(b"[mcs retype TCB FAILED]\n"); return; }

    // 4. Wire each child: SetSpace (share our CSpace + VSpace),
    //    WriteRegisters (entry + stack), SetPriority (so the
    //    scheduler picks them when we yield), Bind to its SC,
    //    Resume.
    if !configure_child(slot_tcb_high(), high_child_entry as u64,
                        (&raw mut HIGH_STACK as u64) + 4096 - 8,
                        slot_sc_high(), b"H") { return; }
    if !configure_child(slot_tcb_low(), low_child_entry as u64,
                        (&raw mut LOW_STACK as u64) + 4096 - 8,
                        slot_sc_low(), b"B") { return; }

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
    // Match the rootserver's priority (255) so the scheduler round-robins to
    // this child when the rootserver yields. A lower priority would never be
    // picked over the still-runnable rootserver (SysYield only rotates within
    // the same priority class); the old 100 predated the rootserver moving to
    // seL4_MaxPrio, so the MCS children were launched but never dispatched.
    let r = tcb_set_priority(tcb_slot, /* prio */ 255);
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
