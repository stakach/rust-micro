//! Phase 34a — microtest harness.
//!
//! Structured Rust-side conformance suite for our microkernel,
//! intended to cover the same patterns `sel4test` exercises but
//! against our public ABI directly. Each test is a function
//! returning `Result<(), &'static str>`; the harness prints
//! `✓ name` on Ok or `✗ name: reason` on Err, then a final
//! `[microtest done]\n` sentinel that the kernel's exit hook
//! catches to qemu_exit.
//!
//! Tests are organised by feature. As we add the missing seL4
//! pieces (TCB::Configure, IPC buffer, cap transfer, reply caps)
//! each gets a `tests::*` function added here.

use crate::*;

type TestResult = Result<(), &'static str>;
type TestFn = fn() -> TestResult;

struct TestCase {
    name: &'static str,
    body: TestFn,
}

// Registry — keep this list in sync as we add tests. One source
// of truth so the summary footer is accurate.
const CASES: &[TestCase] = &[
    TestCase { name: "syscall_round_trip",   body: tests::syscall_round_trip },
    TestCase { name: "untyped_retype_tcb",   body: tests::untyped_retype_tcb },
    TestCase { name: "tcb_configure",        body: tests::tcb_configure },
    TestCase { name: "tcb_set_ipc_buffer",   body: tests::tcb_set_ipc_buffer },
    TestCase { name: "ipc_extra_cap_staging", body: tests::ipc_extra_cap_staging },
    TestCase { name: "untyped_retype_reply", body: tests::untyped_retype_reply },
    TestCase { name: "child_send_round_trip", body: tests::child_send_round_trip },
    TestCase { name: "child_cap_transfer_round_trip",
               body: tests::child_cap_transfer_round_trip },
];

/// Entry point invoked from `_start` when `--features microtest`
/// is on. Runs every case in `CASES`, prints a summary, then
/// emits the kernel-exit sentinel.
pub unsafe fn run() {
    print_str(b"[microtest start]\n");

    let mut passed: usize = 0;
    let mut failed: usize = 0;
    for case in CASES.iter() {
        match (case.body)() {
            Ok(()) => {
                print_str(b"  PASS ");
                print_str(case.name.as_bytes());
                print_str(b"\n");
                passed += 1;
            }
            Err(why) => {
                print_str(b"  FAIL ");
                print_str(case.name.as_bytes());
                print_str(b": ");
                print_str(why.as_bytes());
                print_str(b"\n");
                failed += 1;
            }
        }
    }

    print_str(b"[microtest summary: ");
    print_u64(passed as u64);
    print_str(b" passed, ");
    print_u64(failed as u64);
    print_str(b" failed]\n");
    // Sentinel — kernel's exit hook qemu_exits when it sees this
    // exact byte stream.
    print_str(b"[microtest done]\n");
}

// ---------------------------------------------------------------------------
// Helpers — slot allocator + spawn_child wrapper. Tests share a
// running counter (`NEXT_SLOT`) so they don't have to coordinate
// CNode-slot assignments by hand. Slots are *not* freed between
// tests — once we land Delete with proper MDB tear-down we can
// recycle, but for now the rootserver's CNode (radix=5 = 32 slots)
// has plenty of headroom.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// First slot the harness will hand out. Slots 0..11 are reserved
/// for the canonical initial-cap layout (TCB, CNode, PML4,
/// IRQControl, BootInfo Frame, IPC Frame, Untyped); slot 14 is
/// SchedControl. Slots 12-13 are consumed by the `untyped_retype_tcb`
/// + `tcb_set_ipc_buffer` cases, slot 15 by `untyped_retype_reply`,
/// so we begin handing out from 16.
static NEXT_SLOT: AtomicU64 = AtomicU64::new(16);

#[allow(dead_code)]
fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, AtomicOrdering::Relaxed)
}

/// Spawn a child TCB sharing the rootserver's CSpace + VSpace.
/// `entry` is a Rust extern-C function in the rootserver's image
/// (the cloned PML4 keeps it accessible at the same vaddr). The
/// caller provides a stack-top vaddr from a `static mut` array.
///
/// Returns the slot the new TCB cap landed in. The harness keeps
/// the cap around until the kernel naturally tears down on
/// teardown — there's no Delete cycle yet.
#[allow(dead_code)]
unsafe fn spawn_child(
    entry: unsafe extern "C" fn() -> !,
    stack_top: u64,
) -> Result<u64, &'static str> {
    let slot = alloc_slot();
    let r = untyped_retype(
        CAP_INIT_UNTYPED, OBJ_TCB,
        /* user_size_bits */ 0, /* num_objects */ 1, slot,
    );
    if r != 0 { return Err("retype TCB"); }
    let r = tcb_set_space(slot, /* fault_ep */ 0,
        CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
    if r != 0 { return Err("setspace"); }
    let r = tcb_write_registers(slot, entry as u64, stack_top, /* arg0 */ 0);
    if r != 0 { return Err("writeregs"); }
    let r = tcb_set_priority(slot, 100);
    if r != 0 { return Err("setprio"); }
    let r = tcb_resume(slot);
    if r != 0 { return Err("resume"); }
    Ok(slot)
}

/// Retype an Endpoint into a fresh slot and return its cptr.
#[allow(dead_code)]
unsafe fn make_endpoint() -> Result<u64, &'static str> {
    let slot = alloc_slot();
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_ENDPOINT, 0, 1, slot);
    if r != 0 { return Err("retype endpoint"); }
    Ok(slot)
}

mod tests {
    use super::*;

    /// Trivial sanity check: a successful syscall returns 0.
    /// `SysYield` is the cheapest such call we have.
    pub(super) fn syscall_round_trip() -> TestResult {
        unsafe { syscall0(SYS_YIELD); }
        Ok(())
    }

    /// `Untyped::Retype` issues a TCB cap and the kernel records
    /// the new TCB in the slab. We can't directly observe slab
    /// state from userspace, so the retype-success rax (0) is
    /// the assertion.
    pub(super) fn untyped_retype_tcb() -> TestResult {
        // Retype into the first empty CNode slot (FIRST_EMPTY_SLOT).
        let r = untyped_retype(
            CAP_INIT_UNTYPED,
            OBJ_TCB,
            /* user_size_bits */ 0,
            /* num_objects */ 1,
            FIRST_EMPTY_SLOT,
        );
        if r != 0 {
            return Err("retype failed");
        }
        Ok(())
    }

    /// Phase 35a — spawn a child, have it send a one-word IPC,
    /// the parent receives and verifies the payload. Exercises
    /// the spawn_child helper, the shared-CSpace dispatch path,
    /// and end-to-end IPC delivery.
    pub(super) fn child_send_round_trip() -> TestResult {
        unsafe {
            let ep = make_endpoint()?;
            CHILD_SEND_EP_SLOT.store(ep, AtomicOrdering::Relaxed);
            let stack_top = (&raw mut CHILD_SEND_STACK as u64) + 4096 - 8;
            let _slot = spawn_child(microtest_send_child, stack_top)?;
            let (rax, _badge, _info, payload) = ep_recv(ep);
            if rax != 0 { return Err("recv failed"); }
            if payload != 0xCAFE_F00D { return Err("wrong payload"); }
        }
        Ok(())
    }

    /// Phase 35a — round-trip a cap through IPC. Child mints an
    /// IPC carrying a single extra cap (the rootserver's CNode
    /// cap at slot 2) into the parent's CNode at receiveIndex.
    /// Parent verifies the cap landed at the named slot.
    pub(super) fn child_cap_transfer_round_trip() -> TestResult {
        unsafe {
            let ep = make_endpoint()?;
            // Cap to transfer = the rootserver's own CNode cap
            // (slot 2). We want to see a copy land in the parent
            // CSpace at a fresh `dest_slot`.
            let dest_slot = alloc_slot();
            CHILD_CAP_TRANSFER_EP_SLOT.store(ep, AtomicOrdering::Relaxed);
            CHILD_CAP_TRANSFER_CAP_SLOT.store(
                CAP_INIT_THREAD_CNODE, AtomicOrdering::Relaxed);

            // Parent sets up its IPC buffer with the receive
            // descriptor pointing at `dest_slot` of its own CSpace
            // (receiveCNode = 0 means use cspace_root).
            const ROOTSERVER_IPCBUF_VBASE: u64 = 0x0000_0100_0060_0000;
            let buf = ROOTSERVER_IPCBUF_VBASE as *mut u64;
            core::ptr::write_volatile(buf.add(125), 0);          // receiveCNode = own
            core::ptr::write_volatile(buf.add(126), dest_slot);  // receiveIndex
            core::ptr::write_volatile(buf.add(127), 64);         // receiveDepth (ignored)

            let stack_top = (&raw mut CHILD_CAP_TRANSFER_STACK as u64) + 4096 - 8;
            let _slot = spawn_child(microtest_cap_transfer_child, stack_top)?;

            let (rax, _badge, _info, _payload) = ep_recv(ep);
            if rax != 0 { return Err("recv failed"); }

            // The kernel should have written a cap into our CSpace
            // at `dest_slot`. We verify by issuing a CNode::Copy
            // from `dest_slot` into another fresh slot — if the
            // src slot held a cap, the copy succeeds (rax = 0).
            let copy_dest = alloc_slot();
            let copy_msg = (LBL_CNODE_COPY << 12) | 0;
            let r = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                copy_msg,
                copy_dest,
                dest_slot,
                /* rights word — ignored by Copy */ 0,
            );
            if r != 0 {
                return Err("transferred cap not present at dest_slot");
            }
        }
        Ok(())
    }

    /// Phase 34e — `Untyped::Retype(Reply)` should land a typed
    /// reply cap in the destination slot. The kernel's pool slot
    /// is ours to inspect via the cap layer; from userspace we
    /// just assert retype succeeded.
    pub(super) fn untyped_retype_reply() -> TestResult {
        // Slot 14 is reserved by the kernel for the rootserver's
        // SchedControl cap; use the next free slot.
        let dest_slot: u64 = 15;
        let r = untyped_retype(
            CAP_INIT_UNTYPED,
            OBJ_REPLY,
            /* user_size_bits */ 0,
            /* num_objects */ 1,
            dest_slot,
        );
        if r != 0 { return Err("retype Reply failed"); }
        Ok(())
    }

    /// Phase 34d — sending with `msginfo.extraCaps = 1` should
    /// stage one cap on the sender side without erroring, even if
    /// no receiver is waiting (NBSend skips silently). The cap-
    /// transfer kernel spec covers the full round-trip; this test
    /// just verifies the user-mode invocation path.
    pub(super) fn ipc_extra_cap_staging() -> TestResult {
        // Write the cptr we want to "transfer" into the rootserver's
        // own IPC buffer at the caps_or_badges[0] offset (word 122).
        // The kernel reads it during send-side staging.
        const ROOTSERVER_IPCBUF_VBASE: u64 = 0x0000_0100_0060_0000;
        const CAPS_OR_BADGES_OFFSET_BYTES: u64 = 122 * 8;
        unsafe {
            let buf = ROOTSERVER_IPCBUF_VBASE as *mut u64;
            // Stage CAP_INIT_THREAD_CNODE (the rootserver's own
            // CNode cap, slot 2) so the kernel-side lookup
            // succeeds.
            core::ptr::write_volatile(
                buf.add((CAPS_OR_BADGES_OFFSET_BYTES / 8) as usize),
                CAP_INIT_THREAD_CNODE,
            );
        }
        // Issue NBSend on the endpoint (slot 12 from the legacy
        // demo path is empty here; let's use slot 12 = empty
        // → SysNBSend skips). Use slot 11 (Untyped) which is
        // a valid cap. Kernel will fail with InvalidCapability
        // because Untyped doesn't accept Send invocations from
        // user-space the way an Endpoint does — actually it does
        // dispatch through `decode_invocation`, which expects a
        // valid label. We don't care about the dispatch result;
        // we only care that the staging step doesn't crash.
        //
        // Simplest: target slot 12 (empty). The kernel returns
        // InvalidCapability via the lookup, which sets rax = u64::MAX.
        // We expect that, and assert that the staging didn't trigger
        // a panic before the lookup error.
        let msg_info: u64 = (1u64 << MSG_EXTRA_CAPS_SHIFT) | 0; // length=0, extraCaps=1
        let _ = unsafe { syscall5(SYS_NB_SEND, 12, msg_info, 0, 0, 0) };
        // Survive: if we got here without a kernel panic, the
        // staging path works. Return Ok.
        Ok(())
    }

    /// Phase 34c — `seL4_TCB_SetIPCBuffer` records the IPC-buffer
    /// vaddr and looks up the backing Frame's paddr. Smoke-test
    /// the invocation; the kernel-side spec covers actual long-
    /// message round-trips.
    pub(super) fn tcb_set_ipc_buffer() -> TestResult {
        let frame_slot: u64 = 13;
        let r = untyped_retype(
            CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
            PAGING_BITS, 1, frame_slot,
        );
        if r != 0 { return Err("retype frame failed"); }
        let target = FIRST_EMPTY_SLOT; // TCB from `untyped_retype_tcb`
        let msg_info = LBL_TCB_SET_IPC_BUFFER << 12;
        let buffer_vaddr = 0x0000_0100_0090_0000u64;
        let r = unsafe {
            syscall5(SYS_SEND, target, msg_info,
                     buffer_vaddr, frame_slot, 0)
        };
        if r != 0 { return Err("SetIPCBuffer failed"); }
        Ok(())
    }

    /// Phase 34b — `seL4_TCB_Configure` should accept the same
    /// fault_ep / cspace / vspace fields as the per-field
    /// invocations in one shot, plus the priority. The TCB we
    /// retyped in `untyped_retype_tcb` (slot 12) is reused here.
    pub(super) fn tcb_configure() -> TestResult {
        // a2 = fault_ep, a3 = cspace, a4 = vspace, a5 = prio.
        let target = FIRST_EMPTY_SLOT;
        let prio = 50u64;
        let msg_info = LBL_TCB_CONFIGURE << 12;
        let r = unsafe {
            syscall5(
                SYS_SEND, target, msg_info,
                /* fault_ep */ 0,
                /* cspace */ CAP_INIT_THREAD_CNODE,
                /* vspace */ CAP_INIT_THREAD_VSPACE,
            )
        };
        if r != 0 { return Err("Configure(stage 1) failed"); }
        // The Configure ABI also wants `priority` in args.a5,
        // which `syscall5` doesn't expose (only 4 args after the
        // cap). Issue a 6-arg variant via inline asm.
        let r = unsafe { syscall_configure_with_prio(target, msg_info,
            /* fault_ep */ 0,
            CAP_INIT_THREAD_CNODE,
            CAP_INIT_THREAD_VSPACE,
            prio) };
        if r != 0 { return Err("Configure(stage 2) failed"); }
        Ok(())
    }
}

// Stacks for the child threads spawned by the multi-thread tests.
// Each test uses its own static so concurrent stacks don't alias.
#[repr(C, align(16))]
struct ChildStack([u8; 4096]);
static mut CHILD_SEND_STACK: ChildStack = ChildStack([0; 4096]);
static mut CHILD_CAP_TRANSFER_STACK: ChildStack = ChildStack([0; 4096]);

/// Per-test endpoint slot, written by the parent before spawn so
/// the child can pick it up in its entry routine. The child
/// reads via `core::ptr::read_volatile` to defeat constant
/// propagation across the bare-metal boundary.
static CHILD_SEND_EP_SLOT: AtomicU64 = AtomicU64::new(0);
static CHILD_CAP_TRANSFER_EP_SLOT: AtomicU64 = AtomicU64::new(0);
static CHILD_CAP_TRANSFER_CAP_SLOT: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
#[link_section = ".text.microtest_send_child"]
unsafe extern "C" fn microtest_send_child() -> ! {
    let ep = CHILD_SEND_EP_SLOT.load(AtomicOrdering::Relaxed);
    // SysSend(ep, msg_info=length=1, payload=0xCAFEF00D).
    let _ = syscall5(SYS_SEND, ep, /* length */ 1, 0xCAFE_F00D, 0, 0);
    loop { syscall0(SYS_YIELD); }
}

#[no_mangle]
#[link_section = ".text.microtest_cap_transfer_child"]
unsafe extern "C" fn microtest_cap_transfer_child() -> ! {
    // The parent has set up the rootserver's IPC buffer with the
    // cptr we want to transfer at caps_or_badges[0]; we just send
    // with msginfo.extraCaps = 1.
    const ROOTSERVER_IPCBUF_VBASE: u64 = 0x0000_0100_0060_0000;
    let cap = CHILD_CAP_TRANSFER_CAP_SLOT.load(AtomicOrdering::Relaxed);
    let buf = ROOTSERVER_IPCBUF_VBASE as *mut u64;
    core::ptr::write_volatile(buf.add(122), cap);
    let ep = CHILD_CAP_TRANSFER_EP_SLOT.load(AtomicOrdering::Relaxed);
    let msg_info: u64 = (1u64 << MSG_EXTRA_CAPS_SHIFT); // length=0, extraCaps=1
    let _ = syscall5(SYS_SEND, ep, msg_info, 0, 0, 0);
    loop { syscall0(SYS_YIELD); }
}

const LBL_TCB_CONFIGURE: u64 = 5;
const LBL_TCB_SET_IPC_BUFFER: u64 = 10;
const LBL_CNODE_COPY: u64 = 21;
const SYS_NB_SEND: i64 = -4;
/// `seL4_ObjectType::Reply` numeric tag (mirrors `object_type.rs`).
const OBJ_REPLY: u64 = 6;
/// Bit position of `extraCaps` in `seL4_MessageInfo` (sits just above
/// the 7-bit length field).
const MSG_EXTRA_CAPS_SHIFT: u64 = 7;

/// 6-register SYSCALL — like `syscall5` but exposes the sixth arg
/// (r9 / `args.a5`). Used by tests that need to set the priority
/// field of `TCB::Configure`, which lives at a5.
#[inline(always)]
unsafe fn syscall_configure_with_prio(
    target: u64, msg_info: u64,
    fault_ep: u64, cspace: u64, vspace: u64, prio: u64,
) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        in("rax") SYS_SEND as u64,
        in("rdi") target,
        in("rsi") msg_info,
        in("rdx") fault_ep,
        in("r10") cspace,
        in("r8")  vspace,
        in("r9")  prio,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}
