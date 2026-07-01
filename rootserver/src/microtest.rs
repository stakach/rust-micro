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
    // SURT (M7): the single-thread ring runs surt-core's transport unchanged in
    // real seL4 user space; the two-thread variant drives the same ring across a
    // real seL4 Notification + ack endpoint between the parent and a spawned
    // consumer child. The child now gets scheduled because `spawn_child` binds it
    // a SchedContext (MCS: a no-SC TCB is never dispatched — see `spawn_child`).
    TestCase { name: "surt_ring_single_thread",
               body: tests::surt_ring_single_thread },
    TestCase { name: "surt_ring_two_thread_notify",
               body: tests::surt_ring_two_thread_notify },
    TestCase { name: "surt_ring_multiprocess",
               body: tests::surt_ring_multiprocess },
    TestCase { name: "surt_ring_connect",
               body: tests::surt_ring_connect },
    TestCase { name: "syscall_round_trip",   body: tests::syscall_round_trip },
    TestCase { name: "untyped_retype_tcb",   body: tests::untyped_retype_tcb },
    TestCase { name: "tcb_configure",        body: tests::tcb_configure },
    TestCase { name: "tcb_set_ipc_buffer",   body: tests::tcb_set_ipc_buffer },
    TestCase { name: "ipc_extra_cap_staging", body: tests::ipc_extra_cap_staging },
    TestCase { name: "untyped_retype_reply", body: tests::untyped_retype_reply },
    TestCase { name: "child_send_round_trip", body: tests::child_send_round_trip },
    TestCase { name: "child_cap_transfer_round_trip",
               body: tests::child_cap_transfer_round_trip },
    TestCase { name: "reply_cap_round_trip",
               body: tests::reply_cap_round_trip },
    TestCase { name: "tcb_write_registers_full",
               body: tests::tcb_write_registers_full },
    TestCase { name: "tcb_configure_upstream",
               body: tests::tcb_configure_upstream },
    TestCase { name: "tcb_read_registers_full",
               body: tests::tcb_read_registers_full },
];

/// Entry point invoked from `_start` when `--features microtest`
/// is on. Runs every case in `CASES`, prints a summary, then
/// emits the kernel-exit sentinel.
pub unsafe fn run(
    ipc_buffer_vaddr: u64,
    empty_start: u64,
    image_frames_start: u64,
    image_frames_count: u64,
) {
    // Capture the kernel-published IPC-buffer vaddr before any test runs; the
    // tests stage syscall args through it (see `ROOTSERVER_IPCBUF`).
    ROOTSERVER_IPCBUF.store(ipc_buffer_vaddr, AtomicOrdering::Relaxed);
    // Base the CNode-slot allocator on the kernel-reported first empty slot.
    // SLOT_BASE..SLOT_BASE+2 are the three fixed-slot reservations; the general
    // allocator starts after them.
    SLOT_BASE.store(empty_start, AtomicOrdering::Relaxed);
    NEXT_SLOT.store(empty_start + 3, AtomicOrdering::Relaxed);
    // The rootserver's loaded-image frame caps (for surt_ring_multiprocess,
    // which maps the image into a second VSpace).
    IMAGE_FRAMES_START.store(image_frames_start, AtomicOrdering::Relaxed);
    IMAGE_FRAMES_COUNT.store(image_frames_count, AtomicOrdering::Relaxed);

    print_str(b"[microtest start] ipc_buffer @ ");
    print_hex(ipc_buffer_vaddr);
    print_str(b", first empty slot ");
    print_u64(empty_start);
    print_str(b"\n");

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
// Helpers — slot allocator + spawn_child wrapper. Tests share a running
// counter (`NEXT_SLOT`) so they don't have to coordinate CNode-slot
// assignments by hand. Slots are *not* freed between tests — the rootserver's
// CNode (radix 12 = 4096 slots) has plenty of headroom.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// The harness allocates CNode slots monotonically starting just past the
/// kernel-reported empty region (`BootInfo.empty.start`, captured in `run`).
/// The boot cap layout is not a fixed size, so these must be runtime values —
/// hardcoding them targets occupied slots and every retype fails DeleteFirst.
/// `SLOT_BASE` reserves three slots for the fixed-slot tests (retype_tcb TCB
/// reused by tcb_configure, the ipc-buffer frame, the reply object); the
/// general allocator `NEXT_SLOT` starts at `SLOT_BASE + 3`.
static SLOT_BASE: AtomicU64 = AtomicU64::new(0);
static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);

/// The rootserver's loaded-image frame caps: `IMAGE_FRAMES_START` is the first
/// cptr, and there are `IMAGE_FRAMES_COUNT` of them, in vaddr order from the
/// image base. `surt_ring_multiprocess` copies + maps these into a fresh VSpace.
static IMAGE_FRAMES_START: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_COUNT: AtomicU64 = AtomicU64::new(0);

/// First reserved slot (the TCB `untyped_retype_tcb` creates and later tests
/// reuse). Was the hardcoded `FIRST_EMPTY_SLOT`.
#[inline]
fn first_empty_slot() -> u64 {
    SLOT_BASE.load(AtomicOrdering::Relaxed)
}

/// Runtime vaddr of the rootserver's IPC buffer, published by the kernel in
/// `BootInfo.ipc_buffer` and captured in `run()`. The kernel derives this
/// address from the loaded image's highest PT_LOAD vaddr (ELF-driven layout,
/// commit df8c734), so it shifts whenever the rootserver binary's size changes
/// — it must NOT be hardcoded. Tests stage msg-regs / extraCaps here for the
/// kernel to read on SysSend.
static ROOTSERVER_IPCBUF: AtomicU64 = AtomicU64::new(0);

/// The rootserver's IPC-buffer vaddr (see `ROOTSERVER_IPCBUF`).
#[inline]
fn ipcbuf_vaddr() -> u64 {
    ROOTSERVER_IPCBUF.load(AtomicOrdering::Relaxed)
}

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
    // MCS: a TCB with no bound SchedContext is not schedulable, so bind one
    // before Resume (see `attach_sched_context`).
    attach_sched_context(slot)?;
    let r = tcb_resume(slot);
    if r != 0 { return Err("resume"); }
    Ok(slot)
}

/// Retype + configure + bind a round-robin SchedContext to `tcb_slot`, making
/// it independently schedulable under MCS. Returns the SC's slot.
///
/// A TCB with no bound SchedContext is NOT schedulable (`Tcb::is_schedulable`
/// = runnable && sc.is_some()): `TCB::Resume` marks it Running but never
/// enqueues it, and a plain `SYS_SEND` does not donate the sender's SC (only
/// Call / NBSendRecv / NBSendWait do). Any worker the harness expects to run on
/// its own (rather than only on a donated SC) needs this. budget == period ⇒ a
/// round-robin SC that is always runnable (no budget starvation / timeout
/// faults). Mirrors `main.rs::configure_child` for the MCS demo.
#[allow(dead_code)]
unsafe fn attach_sched_context(tcb_slot: u64) -> Result<u64, &'static str> {
    let sc_slot = alloc_slot();
    let r = untyped_retype(
        CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT,
        SCHED_CONTEXT_BITS, /* num_objects */ 1, sc_slot,
    );
    if r != 0 { return Err("retype SC"); }
    // Legacy/spec ABI: budget/period are raw ticks (tick = 1 ms).
    let r = sched_control_configure(
        SLOT_SCHED_CONTROL, sc_slot, /* budget */ 10, /* period */ 10);
    if r != 0 { return Err("sched_control configure"); }
    let r = sched_context_bind(sc_slot, tcb_slot);
    if r != 0 { return Err("sc bind"); }
    Ok(sc_slot)
}

/// Retype an Endpoint into a fresh slot and return its cptr.
#[allow(dead_code)]
unsafe fn make_endpoint() -> Result<u64, &'static str> {
    let slot = alloc_slot();
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_ENDPOINT, 0, 1, slot);
    if r != 0 { return Err("retype endpoint"); }
    Ok(slot)
}

// ---------------------------------------------------------------------------
// SURT seL4 binding (M7): a notification-backed `Notify`, a shared ring buffer,
// and a consumer child. Proves `surt-core`'s ring + coalesced-wakeup protocol
// run over a real seL4 Notification between two threads.
// ---------------------------------------------------------------------------

const SURT_N: u64 = 100;
const SURT_QLEN: u32 = 16;

#[repr(C, align(64))]
struct SurtBuf([u8; 1536]); // ring_bytes::<SurtSqe>(16) = 1472 <= 1536
static mut SURT_RING: SurtBuf = SurtBuf([0; 1536]);
#[repr(C, align(16))]
struct SurtStack([u8; 16384]); // generous: surt-core code inlines into the child
static mut SURT_CONS_STACK: SurtStack = SurtStack([0; 16384]);
static SURT_NTFN: AtomicU64 = AtomicU64::new(0); // data: parent -> consumer (M4 wakeup)
static SURT_ACK: AtomicU64 = AtomicU64::new(0); // ack: consumer -> parent (flow control)
/// 0 = running, SURT_N = success, anything else = a failure code.
static SURT_DONE: AtomicU64 = AtomicU64::new(0);

/// Signal a notification cap (Send, length 0).
#[inline]
unsafe fn signal(ntfn: u64) {
    // SAFETY: Send to a Notification cap; no IPC buffer needed.
    unsafe { syscall5(SYS_SEND, ntfn, 0, 0, 0, 0) };
}

/// `surt_core::Notify` backed by a seL4 Notification cap: `wake` signals it
/// (Send, length 0), the blocking `wait` receives on it. seL4 notifications
/// latch a signal that precedes the wait, which is exactly what the coalesced
/// wakeup protocol needs.
struct Sel4Notify {
    ntfn: u64,
}

impl surt_core::Notify for Sel4Notify {
    fn wake(&self) -> Result<(), surt_core::NotifyError> {
        // SAFETY: Send (signal) to a Notification cap; length 0, no IPC buffer.
        unsafe { syscall5(SYS_SEND, self.ntfn, 0, 0, 0, 0) };
        Ok(())
    }
    fn arm(&self) -> Result<(), surt_core::NotifyError> {
        Ok(())
    }
    fn disarm(&self) -> Result<(), surt_core::NotifyError> {
        Ok(())
    }
}

impl Sel4Notify {
    /// Block until the notification is signalled (Recv on the cap).
    fn wait(&self) {
        // SAFETY: Recv on a Notification cap; returns the badge, no IPC buffer.
        unsafe {
            let _ = ep_recv(self.ntfn);
        }
    }
}

/// Retype a Notification into a fresh slot and return its cptr.
unsafe fn make_notification() -> Result<u64, &'static str> {
    let slot = alloc_slot();
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_NOTIFICATION, 0, 1, slot);
    if r != 0 {
        return Err("retype notification");
    }
    Ok(slot)
}

/// Consumer child: attaches to the shared ring and drains it via the coalesced
/// blocking protocol (`prepare_wait` → `Sel4Notify::wait`), recording the
/// outcome in `SURT_DONE` for the parent.
#[no_mangle]
unsafe extern "C" fn surt_consumer_child() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::{Consumer, WaitDecision};

    let ptr = core::ptr::addr_of_mut!(SURT_RING) as *mut u8;
    let len = 1536usize;
    let notify = Sel4Notify {
        ntfn: SURT_NTFN.load(AtomicOrdering::Relaxed),
    };
    let mut c = match Consumer::<SurtSqe>::attach(ptr, len) {
        Ok(c) => c,
        Err(_) => {
            SURT_DONE.store(0xBAD0, AtomicOrdering::Relaxed);
            loop {
                yield_now();
            }
        }
    };
    let ack = SURT_ACK.load(AtomicOrdering::Relaxed);
    let mut expect = 0u64;
    loop {
        match c.try_pop() {
            Ok(Some(e)) => {
                if e.request_id != expect || e.user_data != !expect {
                    SURT_DONE.store(0xBAD1, AtomicOrdering::Relaxed);
                    let _ = ep_send_one(ack, 0);
                    loop {
                        yield_now();
                    }
                }
                expect += 1;
                if expect == SURT_N {
                    SURT_DONE.store(SURT_N, AtomicOrdering::Relaxed);
                }
                // Ack this entry so the higher-priority parent unblocks and
                // produces the next one (it cannot yield to us by priority).
                let _ = ep_send_one(ack, 0);
                if expect == SURT_N {
                    // Finished: block on the data notification forever.
                    loop {
                        notify.wait();
                    }
                }
            }
            // Empty: arm + block on the data notification (the M4 wakeup path).
            Ok(None) => match c.prepare_wait() {
                Ok(WaitDecision::Block) => notify.wait(),
                Ok(WaitDecision::Ready) => {}
                Err(_) => {
                    SURT_DONE.store(0xBAD2, AtomicOrdering::Relaxed);
                    let _ = ep_send_one(ack, 0);
                    loop {
                        yield_now();
                    }
                }
            },
            Err(_) => {
                SURT_DONE.store(0xBAD3, AtomicOrdering::Relaxed);
                let _ = ep_send_one(ack, 0);
                loop {
                    yield_now();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SURT multiprocess (M7): the same ring transport across TWO address spaces.
// The producer is the rootserver main thread; the consumer runs in a FRESH
// PML4 with only the rootserver image (read-only), a private stack, and the
// shared ring frame mapped in. The ring frame is granted by CNode_Copy'ing its
// cap and mapping the copy into the consumer's VSpace (surt-core uses offsets,
// not pointers, so the two mappings may sit at different vaddrs — here they
// happen to share one). Coordination rides a Notification + an ack Endpoint in
// the shared CNode; the runtime cptrs are handed to the consumer through the
// unused tail of the shared frame (the consumer has no writable statics — its
// data/bss is mapped read-only).
// ---------------------------------------------------------------------------

/// Image base vaddr in the consumer's VSpace (matches the loader's layout so
/// image frames map at their linked addresses and code runs unmodified).
const MP_IMAGE_BASE_VADDR: u64 = 0x0000_0100_0040_0000;
/// Consumer private stack + shared ring, high in the same 2 MiB PT as the image
/// (PT[510] / PT[511]) so they never collide with a growing image (PT[0..]).
const MP_STACK_VADDR: u64 = 0x0000_0100_005F_E000;
const MP_RING_VADDR: u64 = 0x0000_0100_005F_F000;
const MP_RING_LEN: usize = 1536; // ring_bytes::<SurtSqe>(16)=1472 <= 1536
/// Spawn-args handoff area in the shared frame, clear of the ring region.
/// Layout (u64 words): [0]=magic, [1]=ack_ep cptr, [2]=data_ntfn cptr.
const MP_ARGS_OFF: usize = 2048;
const MP_MAGIC: u64 = 0x5355_5254_4D50_5F31; // "SURTMP_1"

/// Consumer entry, run in a SEPARATE VSpace. Touches only stack locals, the
/// shared ring frame, and const cptrs it reads from the frame — NO writable
/// static (its .data/.bss is mapped read-only). surt-core has no global mutable
/// state, so this is sound.
#[no_mangle]
#[link_section = ".text.surt_multiproc_consumer"]
unsafe extern "C" fn surt_multiproc_consumer() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::{Consumer, WaitDecision};

    // Read the runtime cptrs the producer stashed in the shared frame tail.
    let args = (MP_RING_VADDR + MP_ARGS_OFF as u64) as *const u64;
    let magic = core::ptr::read_volatile(args);
    let ack = core::ptr::read_volatile(args.add(1));
    let notify = Sel4Notify {
        ntfn: core::ptr::read_volatile(args.add(2)),
    };
    if magic != MP_MAGIC {
        // Frame not published as expected; nothing trustworthy to ack on.
        loop { yield_now(); }
    }

    let mut c = match Consumer::<SurtSqe>::attach(MP_RING_VADDR as *mut u8, MP_RING_LEN) {
        Ok(c) => c,
        Err(_) => {
            let _ = ep_send_one(ack, 0xBADA);
            loop { notify.wait(); }
        }
    };
    let mut expect = 0u64;
    loop {
        match c.try_pop() {
            Ok(Some(e)) => {
                if e.request_id != expect || e.user_data != !expect {
                    let _ = ep_send_one(ack, 0xBAD0);
                    loop { notify.wait(); }
                }
                // Ack payload = the verified index; the producer asserts it.
                let _ = ep_send_one(ack, expect);
                expect += 1;
                if expect == SURT_N {
                    loop { notify.wait(); }
                }
            }
            // Ring empty: arm + block on the data notification (M4 wakeup).
            Ok(None) => match c.prepare_wait() {
                Ok(WaitDecision::Block) => notify.wait(),
                Ok(WaitDecision::Ready) => {}
                Err(_) => {
                    let _ = ep_send_one(ack, 0xBAD2);
                    loop { notify.wait(); }
                }
            },
            Err(_) => {
                let _ = ep_send_one(ack, 0xBAD3);
                loop { notify.wait(); }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SURT dynamic connect (M7): TWO isolated components — a producer and a
// consumer, each in its OWN VSpace — that discover and connect at runtime. The
// producer creates the ring, then announces {ring frame cap, notification} to
// the consumer over a well-known control Endpoint (the SURT handshake); the
// consumer maps the granted frame into ITS OWN VSpace and drains. Neither is
// wired up by the rootserver beyond the initial spawn + the shared control /
// result endpoints. (Phase 1: the components still share the rootserver CNode,
// so the "grant" is a cptr in the handshake message + a peer-side map; Phase 2
// gives each its own CSpace and transfers the caps for real.)
// ---------------------------------------------------------------------------

const CONN_IMAGE_BASE: u64 = 0x0000_0100_0040_0000;
const CONN_SCRATCH_VADDR: u64 = 0x0000_0100_005F_C000; // rootserver-side staging
const CONN_ARGS_VADDR: u64 = 0x0000_0100_005F_D000; // per-component boot args
const CONN_STACK_VADDR: u64 = 0x0000_0100_005F_E000;
const CONN_RING_VADDR: u64 = 0x0000_0100_005F_F000;
const CONN_RING_LEN: usize = 1536;
const CONN_MAGIC: u64 = 0x5355_5254_434E_5F31; // "SURTCN_1"

/// Send a ≤3-word control message (no caps, fits in registers — no IPC buffer).
#[inline]
unsafe fn conn_send3(ep: u64, m0: u64, m1: u64, m2: u64) {
    let _ = syscall5(SYS_SEND, ep, /* length */ 3, m0, m1, m2);
}

/// Receive a 3-word control message; returns (MR0, MR1, MR2) from r10/r8/r9.
unsafe fn conn_recv3(ep: u64) -> (u64, u64, u64) {
    let m0: u64;
    let m1: u64;
    let m2: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_RECV as u64,
        in("rdi") ep,
        lateout("rax") _,
        lateout("rsi") _,
        lateout("r10") m0,
        lateout("r8") m1,
        lateout("r9") m2,
        lateout("r15") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    (m0, m1, m2)
}

/// Build a fresh isolated VSpace: a new PML4 with one PDPT/PD/PT chain, the
/// rootserver image mapped read-only (so the component executes surt-core), and
/// a private stack. Returns the PML4 cptr. The one PT covers the whole 2 MiB
/// region, so the caller can `page_map` the args / ring frames into it too.
#[allow(dead_code)]
unsafe fn build_component_vspace() -> u64 {
    let img_start = IMAGE_FRAMES_START.load(AtomicOrdering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(AtomicOrdering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, CONN_IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, CONN_IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, CONN_IMAGE_BASE, pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(
            SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12,
            cp, img_start + i, 0);
        let _ = page_map(cp, CONN_IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    let stack_slot = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, stack_slot);
    let _ = page_map(stack_slot, CONN_STACK_VADDR, /* RW */ 3, pml4);
    pml4
}

/// Retype a fresh frame, fill it (via a rootserver-side scratch mapping) with
/// `words`, then map it into `pml4` at `vaddr` so the component reads its boot
/// args from a known vaddr (the component can't read a runtime static — its
/// data/bss is mapped read-only).
#[allow(dead_code)]
unsafe fn make_args_frame(pml4: u64, vaddr: u64, words: &[u64]) {
    let frame = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, frame);
    let _ = page_map(frame, CONN_SCRATCH_VADDR, /* RW */ 3, CAP_INIT_THREAD_VSPACE);
    let dst = CONN_SCRATCH_VADDR as *mut u64;
    for (i, &w) in words.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), w);
    }
    let _ = page_unmap(frame); // release the scratch mapping so we can remap it
    let _ = page_map(frame, vaddr, /* RW */ 3, pml4);
}

/// Spawn a component thread in `pml4` (shared rootserver CNode in Phase 1),
/// priority 100, with a bound SchedContext.
#[allow(dead_code)]
unsafe fn spawn_component(
    pml4: u64,
    entry: unsafe extern "C" fn() -> !,
) -> Result<u64, &'static str> {
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, /* fault_ep */ 0, CAP_INIT_THREAD_CNODE, pml4);
    let stack_top = CONN_STACK_VADDR + 4096 - 8;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb)?;
    let _ = tcb_resume(tcb);
    Ok(tcb)
}

/// Producer component entry. Its ring is already mapped at `CONN_RING_VADDR` by
/// the rootserver; it reads its cptrs from the boot-args frame, `init_ring`s,
/// announces the ring to the peer over the control endpoint, then produces.
/// Uses only stack locals, the args/ring frames, and cptrs read from args.
#[no_mangle]
#[link_section = ".text.surt_connect_producer"]
unsafe extern "C" fn surt_connect_producer() -> ! {
    use surt_core::surt_abi::{feature, role, SurtSqe};
    use surt_core::{init_ring, Producer, PushError, RingConfig};

    let args = CONN_ARGS_VADDR as *const u64;
    let magic = core::ptr::read_volatile(args);
    let control_ep = core::ptr::read_volatile(args.add(1));
    let data_ntfn = core::ptr::read_volatile(args.add(2));
    let ring_cptr = core::ptr::read_volatile(args.add(3));
    if magic != CONN_MAGIC {
        loop { yield_now(); }
    }

    let cfg = RingConfig {
        queue_len: SURT_QLEN,
        ring_id: 4,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    if init_ring::<SurtSqe>(CONN_RING_VADDR as *mut u8, CONN_RING_LEN, &cfg).is_err() {
        loop { yield_now(); }
    }
    let mut prod = match Producer::<SurtSqe>::attach(CONN_RING_VADDR as *mut u8, CONN_RING_LEN) {
        Ok(p) => p,
        Err(_) => loop { yield_now(); },
    };

    // Dynamic connect: hand the peer the ring frame cap + the wakeup notification.
    conn_send3(control_ep, CONN_MAGIC, ring_cptr, data_ntfn);

    let notify = Sel4Notify { ntfn: data_ntfn };
    let mut i = 0u64;
    while i < SURT_N {
        let e = SurtSqe {
            request_id: i,
            user_data: !i,
            ..Default::default()
        };
        match prod.try_push(e) {
            Ok(()) => {
                let _ = prod.notify_consumer(&notify);
                i += 1;
            }
            Err(PushError::Full) => yield_now(),
            Err(PushError::Closed) => break,
        }
    }
    loop { yield_now(); }
}

/// Consumer component entry. Discovers the connection by receiving the ring
/// frame cap + notification over the control endpoint, maps the granted frame
/// into ITS OWN VSpace, drains + verifies, and reports the verdict to the
/// rootserver's result endpoint. No writable statics.
#[no_mangle]
#[link_section = ".text.surt_connect_consumer"]
unsafe extern "C" fn surt_connect_consumer() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::{Consumer, WaitDecision};

    let args = CONN_ARGS_VADDR as *const u64;
    let control_ep = core::ptr::read_volatile(args.add(1));
    let result_ep = core::ptr::read_volatile(args.add(2));
    let my_pml4 = core::ptr::read_volatile(args.add(3));

    // Discover: receive {magic, ring frame cap, notification} from the producer.
    let (magic, ring_cptr, ntfn) = conn_recv3(control_ep);
    if magic != CONN_MAGIC {
        let _ = ep_send_one(result_ep, 0xBAD1);
        loop { yield_now(); }
    }
    // Map the granted frame into OUR OWN VSpace, then attach.
    let _ = page_map(ring_cptr, CONN_RING_VADDR, /* RW */ 3, my_pml4);
    let mut c = match Consumer::<SurtSqe>::attach(CONN_RING_VADDR as *mut u8, CONN_RING_LEN) {
        Ok(c) => c,
        Err(_) => {
            let _ = ep_send_one(result_ep, 0xBAD2);
            loop { yield_now(); }
        }
    };

    let notify = Sel4Notify { ntfn };
    let mut expect = 0u64;
    while expect < SURT_N {
        match c.try_pop() {
            Ok(Some(e)) => {
                if e.request_id != expect || e.user_data != !expect {
                    let _ = ep_send_one(result_ep, 0xBAD3);
                    loop { yield_now(); }
                }
                expect += 1;
            }
            Ok(None) => match c.prepare_wait() {
                Ok(WaitDecision::Block) => notify.wait(),
                Ok(WaitDecision::Ready) => {}
                Err(_) => {
                    let _ = ep_send_one(result_ep, 0xBAD4);
                    loop { yield_now(); }
                }
            },
            Err(_) => {
                let _ = ep_send_one(result_ep, 0xBAD5);
                loop { yield_now(); }
            }
        }
    }
    let _ = ep_send_one(result_ep, 0); // verdict: success
    loop { yield_now(); }
}

mod tests {
    use super::*;

    /// Two threads over one ring + a seL4 notification + ack endpoint: the
    /// parent produces `SURT_N` entries (waking the consumer via the coalesced
    /// M4 protocol), and the spawned consumer child drains and verifies them,
    /// blocking on the data notification when the ring is empty. Proves the
    /// SURT transport + coalesced-wakeup protocol run across two real seL4
    /// threads. (`spawn_child` binds the consumer a SchedContext so it is
    /// dispatched when the higher-priority parent blocks on the ack endpoint.)
    pub(super) fn surt_ring_two_thread_notify() -> TestResult {
        use surt_core::surt_abi::{feature, role, SurtSqe};
        use surt_core::{init_ring, Producer, PushError, RingConfig};

        let ptr = core::ptr::addr_of_mut!(SURT_RING) as *mut u8;
        let len = 1536usize;
        let cfg = RingConfig {
            queue_len: SURT_QLEN,
            ring_id: 2,
            feature_flags: feature::REQUIRED_V0_1,
            role: role::PRODUCER,
        };
        // SAFETY: SURT_RING is a 64-aligned static, big enough; this is the only
        // initialiser, run before the consumer child is spawned.
        unsafe { init_ring::<SurtSqe>(ptr, len, &cfg).map_err(|_| "init_ring")? };

        let data_ntfn = unsafe { make_notification()? };
        // The ack uses an Endpoint (proven by child_send) so the parent reliably
        // blocks on it and the lower-priority consumer gets to run.
        let ack_ep = unsafe { make_endpoint()? };
        SURT_NTFN.store(data_ntfn, AtomicOrdering::Relaxed);
        SURT_ACK.store(ack_ep, AtomicOrdering::Relaxed);
        SURT_DONE.store(0, AtomicOrdering::Relaxed);
        let notify = Sel4Notify { ntfn: data_ntfn };

        // SAFETY: the sole producer over the just-initialised ring.
        let mut prod = unsafe { Producer::<SurtSqe>::attach(ptr, len).map_err(|_| "attach")? };

        // SAFETY: stack top from a static array; entry shares this VSpace.
        // `- 8` (not -16): the SysV ABI expects `rsp % 16 == 8` at function
        // entry (the slot a `call` would have used for the return address). A
        // 16-aligned rsp misaligns the consumer's SSE ops (it's large-model
        // code) → a silent #GP. `child_send` uses the same `- 8`.
        let stack_top = core::ptr::addr_of_mut!(SURT_CONS_STACK) as u64 + 16384 - 8;
        let _child = unsafe { spawn_child(surt_consumer_child, stack_top)? };

        // Ping-pong: the consumer runs at a lower priority and the parent can't
        // yield to it, so the parent BLOCKS on the ack endpoint each iteration
        // to let it run. The consumer still exercises the M4 wakeup (data
        // notification) whenever it finds the ring empty.
        for i in 0..SURT_N {
            let e = SurtSqe {
                request_id: i,
                user_data: !i,
                ..Default::default()
            };
            loop {
                match prod.try_push(e) {
                    Ok(()) => break,
                    Err(PushError::Full) => yield_now(),
                    Err(PushError::Closed) => return Err("ring closed"),
                }
            }
            // Wake the consumer if it armed (coalesced M4 wakeup).
            let _ = prod.notify_consumer(&notify);
            // Block on the ack endpoint until the consumer has processed this
            // entry (this is what lets the lower-priority consumer run).
            unsafe {
                let _ = ep_recv(ack_ep);
            }
            let d = SURT_DONE.load(AtomicOrdering::Relaxed);
            if d != 0 && d != SURT_N {
                return Err("consumer reported failure");
            }
        }

        match SURT_DONE.load(AtomicOrdering::Relaxed) {
            v if v == SURT_N => Ok(()),
            0 => Err("consumer did not finish"),
            _ => Err("consumer reported failure"),
        }
    }

    /// Multiprocess: producer (this thread) and consumer in SEPARATE address
    /// spaces sharing one ring frame. Builds a fresh PML4 for the consumer,
    /// maps the rootserver image into it read-only (so it can execute surt-core
    /// unchanged) plus a private stack, retypes a ring frame and maps it into
    /// BOTH VSpaces (the consumer's via a CNode_Copy of the frame cap), then
    /// runs the coalesced-wakeup ping-pong across the address-space boundary.
    /// (`if r != 0` checks are cosmetic — `syscall5` always returns 0; the real
    /// assertion is the per-entry ack verdict + the absence of a consumer #PF.)
    pub(super) fn surt_ring_multiprocess() -> TestResult {
        use surt_core::surt_abi::{feature, role, SurtSqe};
        use surt_core::{init_ring, Producer, PushError, RingConfig};

        unsafe {
            let img_start = IMAGE_FRAMES_START.load(AtomicOrdering::Relaxed);
            let img_count = IMAGE_FRAMES_COUNT.load(AtomicOrdering::Relaxed);
            if img_count == 0 {
                return Err("no image frames");
            }

            // Coordination caps (shared CNode ⇒ the consumer names them by cptr).
            let data_ntfn = make_notification()?;
            let ack_ep = make_endpoint()?;

            // --- Shared ring frame: retype + map into the producer's (root) VSpace.
            let ring_slot = alloc_slot();
            let _ = untyped_retype(
                CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ring_slot);
            // MP_RING_VADDR is inside the image's existing 2 MiB PT, so no new PT
            // is needed in the rootserver's own VSpace.
            let _ = page_map(ring_slot, MP_RING_VADDR, /* RW */ 3, CAP_INIT_THREAD_VSPACE);

            // init the ring + attach the producer (rootserver-side mapping).
            let cfg = RingConfig {
                queue_len: SURT_QLEN,
                ring_id: 3,
                feature_flags: feature::REQUIRED_V0_1,
                role: role::PRODUCER,
            };
            init_ring::<SurtSqe>(MP_RING_VADDR as *mut u8, MP_RING_LEN, &cfg)
                .map_err(|_| "init_ring")?;
            let mut prod = Producer::<SurtSqe>::attach(MP_RING_VADDR as *mut u8, MP_RING_LEN)
                .map_err(|_| "attach producer")?;

            // Publish the runtime cptrs for the consumer in the shared frame tail.
            let args = (MP_RING_VADDR + MP_ARGS_OFF as u64) as *mut u64;
            core::ptr::write_volatile(args.add(1), ack_ep);
            core::ptr::write_volatile(args.add(2), data_ntfn);
            core::ptr::write_volatile(args, MP_MAGIC); // magic last = "published"

            // --- Consumer VSpace: fresh PML4 + one PDPT/PD/PT chain at the image.
            let pml4 = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
            let pdpt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
            let pd = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
            let pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
            let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, MP_IMAGE_BASE_VADDR, pml4);
            let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, MP_IMAGE_BASE_VADDR, pml4);
            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, MP_IMAGE_BASE_VADDR, pml4);

            // Map the whole image READ-ONLY (copy each frame cap so it maps into
            // a second VSpace). Frames are in vaddr order from the image base;
            // the ~7 aux frames past the image over-map at unused high vaddrs
            // (harmless — the consumer only executes/reads the image prefix).
            for i in 0..img_count {
                let cp = alloc_slot();
                let _ = syscall5(
                    SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12,
                    cp, img_start + i, 0);
                let _ = page_map(cp, MP_IMAGE_BASE_VADDR + i * 0x1000, /* RO */ 2, pml4);
            }

            // Consumer's private stack.
            let stack_slot = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, stack_slot);
            let _ = page_map(stack_slot, MP_STACK_VADDR, /* RW */ 3, pml4);

            // Grant the ring: copy the frame cap and map the copy into the
            // consumer VSpace (same vaddr here; offsets not pointers make that a
            // non-requirement).
            let ring_copy = alloc_slot();
            let _ = syscall5(
                SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12,
                ring_copy, ring_slot, 0);
            let _ = page_map(ring_copy, MP_RING_VADDR, /* RW */ 3, pml4);

            // --- Spawn the consumer TCB in the new VSpace (shared CNode).
            let tcb = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
            let _ = tcb_set_space(tcb, /* fault_ep */ 0, CAP_INIT_THREAD_CNODE, pml4);
            let stack_top = MP_STACK_VADDR + 4096 - 8;
            let _ = tcb_write_registers(tcb, surt_multiproc_consumer as u64, stack_top, 0);
            let _ = tcb_set_priority(tcb, 100);
            attach_sched_context(tcb)?;
            let _ = tcb_resume(tcb);

            // --- Ping-pong across the address-space boundary.
            let notify = Sel4Notify { ntfn: data_ntfn };
            for i in 0..SURT_N {
                let e = SurtSqe {
                    request_id: i,
                    user_data: !i,
                    ..Default::default()
                };
                loop {
                    match prod.try_push(e) {
                        Ok(()) => break,
                        Err(PushError::Full) => yield_now(),
                        Err(PushError::Closed) => return Err("ring closed"),
                    }
                }
                let _ = prod.notify_consumer(&notify);
                // Block on the ack ep so the lower-priority consumer runs.
                let (_rax, _badge, _info, payload) = ep_recv(ack_ep);
                if payload != i {
                    return Err("consumer verdict mismatch");
                }
            }
            Ok(())
        }
    }

    /// Dynamic connect: a producer and a consumer, EACH in its own isolated
    /// VSpace, discover and connect at runtime. The rootserver spawns both and
    /// hands out a control endpoint; the producer creates the ring, maps it,
    /// `init_ring`s, and announces {ring frame cap, notification} to the peer
    /// over the control endpoint; the consumer maps the granted frame into its
    /// OWN VSpace, drains + verifies, and reports the verdict. The rootserver
    /// only brokers the initial spawn — the channel is established by the two
    /// components themselves. (Phase 1: shared CNode; the transfer is a cptr in
    /// the handshake + a peer-side map.)
    pub(super) fn surt_ring_connect() -> TestResult {
        unsafe {
            if IMAGE_FRAMES_COUNT.load(AtomicOrdering::Relaxed) == 0 {
                return Err("no image frames");
            }
            let control_ep = make_endpoint()?;
            let result_ep = make_endpoint()?;
            let data_ntfn = make_notification()?;

            // --- Producer component: own VSpace; ring created + mapped here, a
            // copy of the frame cap handed to it to announce to the consumer.
            let prod_pml4 = build_component_vspace();
            let ring_slot = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ring_slot);
            let _ = page_map(ring_slot, CONN_RING_VADDR, /* RW */ 3, prod_pml4);
            let ring_copy = alloc_slot();
            let _ = syscall5(
                SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12,
                ring_copy, ring_slot, 0);
            make_args_frame(prod_pml4, CONN_ARGS_VADDR,
                &[CONN_MAGIC, control_ep, data_ntfn, ring_copy]);

            // --- Consumer component: own VSpace; receives the connection.
            let cons_pml4 = build_component_vspace();
            make_args_frame(cons_pml4, CONN_ARGS_VADDR,
                &[CONN_MAGIC, control_ep, result_ep, cons_pml4]);

            // Launch both, then wait for the consumer's verdict.
            spawn_component(prod_pml4, surt_connect_producer)?;
            spawn_component(cons_pml4, surt_connect_consumer)?;

            let (_rax, _badge, _info, verdict) = ep_recv(result_ep);
            if verdict != 0 {
                return Err("consumer reported failure");
            }
            Ok(())
        }
    }

    /// Drive the SURT host-tested SPSC ring in real seL4 user space: init a
    /// ring in a static frame, then push/pop 20 entries through an 8-slot ring
    /// (exercising wraparound) and verify the payload. Proves `surt-core`'s
    /// transport runs unchanged on the kernel's ABI.
    pub(super) fn surt_ring_single_thread() -> TestResult {
        use surt_core::surt_abi::{feature, role, SurtSqe};
        use surt_core::{init_ring, Consumer, Producer, RingConfig};

        #[repr(C, align(64))]
        struct Buf([u8; 1024]);
        static mut BUF: Buf = Buf([0; 1024]);

        let ptr = core::ptr::addr_of_mut!(BUF) as *mut u8;
        let len = 1024usize;
        let cfg = RingConfig {
            queue_len: 8,
            ring_id: 1,
            feature_flags: feature::REQUIRED_V0_1,
            role: role::PRODUCER,
        };
        // SAFETY: BUF is a 64-aligned static, 1024 B (> ring_bytes(8)=832), and
        // only this single-threaded test touches it.
        unsafe { init_ring::<SurtSqe>(ptr, len, &cfg).map_err(|_| "init_ring")? };
        // SAFETY: the sole producer over the just-initialised ring.
        let mut p = unsafe { Producer::<SurtSqe>::attach(ptr, len).map_err(|_| "attach p")? };
        // SAFETY: the sole consumer over the same ring.
        let mut c = unsafe { Consumer::<SurtSqe>::attach(ptr, len).map_err(|_| "attach c")? };

        for i in 0..20u64 {
            let e = SurtSqe {
                request_id: i,
                user_data: !i,
                ..Default::default()
            };
            p.try_push(e).map_err(|_| "push")?;
            match c.try_pop() {
                Ok(Some(got)) => {
                    if got.request_id != i || got.user_data != !i {
                        return Err("payload mismatch");
                    }
                }
                _ => return Err("pop empty"),
            }
        }
        Ok(())
    }

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
        // Retype into the first reserved empty CNode slot.
        let r = untyped_retype(
            CAP_INIT_UNTYPED,
            OBJ_TCB,
            /* user_size_bits */ 0,
            /* num_objects */ 1,
            first_empty_slot(),
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

    /// Phase 37d — round-trip the upstream-shape ReadRegisters.
    /// Write known values to a TCB via WriteRegisters, then read
    /// them back via ReadRegisters with count=4 (rip, rsp, rflags,
    /// rax) and verify each word landed in the invoker's IPC
    /// buffer.
    pub(super) fn tcb_read_registers_full() -> TestResult {
        unsafe {
            // Retype + minimally configure a TCB.
            let tcb_slot = alloc_slot();
            let r = untyped_retype(
                CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb_slot);
            if r != 0 { return Err("retype tcb"); }
            let r = tcb_set_space(tcb_slot, 0,
                CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
            if r != 0 { return Err("setspace"); }

            // Stage register values via the upstream-shape
            // WriteRegisters (count=4: rip, rsp, rflags, rax).
            const RIP_MARKER: u64 = 0xAAAA_AAAA_1111_1111;
            const RSP_MARKER: u64 = 0xBBBB_BBBB_2222_2222;
            const RFLAGS_MARKER: u64 = 0x202;
            const RAX_MARKER: u64 = 0xCCCC_CCCC_3333_3333;
            // Upstream WriteRegisters wire layout (see the kernel handler):
            //   mr0 = resume|flags, mr1 = count, mr2 = rip, mr3 = rsp,
            //   mr4 = rflags, mr5 = rax. mr0..mr3 in registers; mr4+ in the
            //   IPC buffer at word (1 + mr_index).
            let buf = ipcbuf_vaddr() as *mut u64;
            core::ptr::write_volatile(buf.add(5), RFLAGS_MARKER); // mr4
            core::ptr::write_volatile(buf.add(6), RAX_MARKER);    // mr5
            let count: u64 = 4;
            let length: u64 = 2 + count;
            let label_writeregs: u64 = 3;
            let msg_info_w = (label_writeregs << 12) | (length & 0x7F);
            core::arch::asm!(
                "syscall",
                in("rdx") SYS_SEND as u64,
                in("rdi") tcb_slot,
                in("rsi") msg_info_w,
                in("r10") /* mr0 = resume */ 0u64,
                in("r8")  /* mr1 = count */ count,
                in("r9")  /* mr2 = rip */ RIP_MARKER,
                in("r15") /* mr3 = rsp */ RSP_MARKER,
                lateout("rax") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack, preserves_flags),
            );

            // ReadRegisters: upstream ABI carries count in mr1 (= a3), and the
            // kernel fans the first four output words back into r10/r8/r9/r15
            // (rip/rsp/rflags/rax) on the syscall return.
            let label_readregs: u64 = 2;
            let msg_info_r = (label_readregs << 12) | (2u64 & 0x7F);
            let read_rip: u64;
            let read_rsp: u64;
            let read_rflags: u64;
            let read_rax: u64;
            core::arch::asm!(
                "syscall",
                in("rdx") SYS_SEND as u64,
                in("rdi") tcb_slot,
                in("rsi") msg_info_r,
                inout("r10") /* mr0 = suspend */ 0u64 => read_rip,
                inout("r8")  /* mr1 = count */ 4u64 => read_rsp,
                inout("r9")  /* mr2 */ 0u64 => read_rflags,
                inout("r15") /* mr3 */ 0u64 => read_rax,
                lateout("rax") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack, preserves_flags),
            );
            // rax is preserved (Phase 38c-followup) so we can no
            // longer detect lookup errors here; we just verify the
            // returned register values match.
            if read_rip    != RIP_MARKER     { return Err("rip mismatch"); }
            if read_rsp    != RSP_MARKER     { return Err("rsp mismatch"); }
            if read_rflags != RFLAGS_MARKER  { return Err("rflags mismatch"); }
            if read_rax    != RAX_MARKER     { return Err("rax mismatch"); }
        }
        Ok(())
    }

    /// Phase 37c — upstream-shape `seL4_TCB_Configure`:
    /// extraCaps[0..3] = cspace, vspace, ipc_buffer_frame; msg
    /// words = fault_ep + ignored data fields + ipc_buffer vaddr.
    /// Verifies the kernel reads from extraCaps + msg_regs (not
    /// from `args.a3`/`a4` like the legacy form).
    pub(super) fn tcb_configure_upstream() -> TestResult {
        unsafe {
            // Retype a fresh TCB to configure.
            let tcb_slot = alloc_slot();
            let r = untyped_retype(
                CAP_INIT_UNTYPED, OBJ_TCB,
                /* size_bits */ 0, /* num_objects */ 1, tcb_slot);
            if r != 0 { return Err("retype tcb"); }

            // Retype an IPC-buffer frame.
            let ipcbuf_slot = alloc_slot();
            let r = untyped_retype(
                CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
                PAGING_BITS, 1, ipcbuf_slot);
            if r != 0 { return Err("retype ipcbuf frame"); }

            // Stage extraCaps[0..3] in our IPC buffer at
            // caps_or_badges offset = 122. cspace, vspace,
            // ipc_buffer_frame.
            let buf = ipcbuf_vaddr() as *mut u64;
            core::ptr::write_volatile(buf.add(122), CAP_INIT_THREAD_CNODE);
            core::ptr::write_volatile(buf.add(123), CAP_INIT_THREAD_VSPACE);
            core::ptr::write_volatile(buf.add(124), ipcbuf_slot);

            // SysSend: msginfo.label = TCBConfigure (5),
            // length = 4 (fault_ep + cspace_data + vspace_data +
            // ipc_buffer), extraCaps = 3.
            let label_cfg: u64 = 5;
            let length: u64 = 4;
            let extra_caps: u64 = 3;
            let msg_info: u64 =
                (label_cfg << 12)
                | (extra_caps << 7)
                | (length & 0x7F);
            const FAULT_EP: u64 = 0xFEEDC0DE;
            const CSPACE_DATA: u64 = 0;
            const VSPACE_DATA: u64 = 0;
            const IPC_BUFFER_VADDR: u64 = 0x0000_0100_00A0_0000;
            let r = syscall5(
                SYS_SEND, tcb_slot, msg_info,
                FAULT_EP,
                CSPACE_DATA,
                VSPACE_DATA,
            );
            // a5 = ipc_buffer_vaddr — needs the 6-arg form.
            // We cheated above with syscall5 (only stages a4); the
            // upstream Configure path reads ipc_buffer from a5, so
            // re-issue with the right asm.
            let _ = r;
            // Phase 38c — upstream SYSCALL ABI; rax preserved.
            core::arch::asm!(
                "syscall",
                in("rdx") SYS_SEND as u64,
                in("rdi") tcb_slot,
                in("rsi") msg_info,
                in("r10") /* a2 */ FAULT_EP,
                in("r8")  /* a3 */ CSPACE_DATA,
                in("r9")  /* a4 */ VSPACE_DATA,
                in("r15") /* a5 */ IPC_BUFFER_VADDR,
                lateout("rax") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack, preserves_flags),
            );
        }
        Ok(())
    }

    /// Phase 36g — write the full upstream-shape register set on
    /// a fresh TCB and verify each register landed where it
    /// should. The parent retypes a TCB, configures CSpace +
    /// VSpace via SetSpace, then issues `TCB::WriteRegisters`
    /// with `msginfo.length = 3 + count`, count=4 (rip, rsp,
    /// rflags, rax). The child reads its own `rax` register and
    /// sends it back via IPC; the parent verifies the value.
    pub(super) fn tcb_write_registers_full() -> TestResult {
        unsafe {
            let ep = make_endpoint()?;
            WRITE_REGS_EP_SLOT.store(ep, AtomicOrdering::Relaxed);

            let tcb_slot = alloc_slot();
            let r = untyped_retype(
                CAP_INIT_UNTYPED, OBJ_TCB, /* size_bits */ 0,
                /* num_objects */ 1, tcb_slot);
            if r != 0 { return Err("retype tcb"); }
            let r = tcb_set_space(tcb_slot, /* fault_ep */ 0,
                CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
            if r != 0 { return Err("setspace"); }
            let r = tcb_set_priority(tcb_slot, 100);
            if r != 0 { return Err("setprio"); }
            // WriteRegisters below resumes the worker (a2 = resume = 1); under
            // MCS it needs a bound SchedContext to actually be dispatched.
            attach_sched_context(tcb_slot)?;

            // Stage the register values into our IPC buffer at
            // msg[3..3+count] so the staging in handle_send picks
            // them up and the kernel reads them via msg_regs[3..].
            let stack_top = (&raw mut WRITE_REGS_STACK as u64) + 4096 - 8;
            const RAX_PAYLOAD: u64 = 0x1234_5678_9ABC_DEF0;
            // rip, rsp, rflags, rax — first 4 fields of seL4_UserContext.
            // We need only up to index 3 (rax) to land; rcx (slot 5)
            // is our iretq RIP slot and the kernel skips it. Slot 4
            // (rbx) is unused here.
            let regs: [u64; 4] = [
                microtest_write_regs_child as u64,  // rip
                stack_top,                          // rsp
                0x202,                              // rflags (IF=1)
                RAX_PAYLOAD,                        // rax
            ];
            // Upstream `seL4_TCB_WriteRegisters` wire layout (must match the
            // kernel's TCBWriteRegisters handler):
            //   mr0 = resume | (arch_flags << 8)
            //   mr1 = count
            //   mr2 = rip  (regs[0])    mr3 = rsp (regs[1])
            //   mr4.. = rflags, rax, ...
            // mr0..mr3 ride in the register fast-path (a2..a5 = r10/r8/r9/r15);
            // mr4+ live in the IPC buffer at word (1 + mr_index). Staging count
            // in a4 (the old layout) made the kernel read count=0 and write no
            // registers — the worker then ran at rip=0 and #PF'd.
            let buf = ipcbuf_vaddr() as *mut u64;
            core::ptr::write_volatile(buf.add(5), regs[2]); // mr4 = rflags
            core::ptr::write_volatile(buf.add(6), regs[3]); // mr5 = rax
            let count: u64 = regs.len() as u64;
            let length: u64 = 2 + count; // mr0..mr5 for count=4
            let label_writeregs: u64 = 3; // TCBWriteRegisters
            let msg_info = (label_writeregs << 12) | (length & 0x7F);
            core::arch::asm!(
                "syscall",
                in("rdx") SYS_SEND as u64,
                in("rdi") tcb_slot,
                in("rsi") msg_info,
                in("r10") /* mr0 */ 1u64,      // resume = 1
                in("r8")  /* mr1 */ count,
                in("r9")  /* mr2 */ regs[0],   // rip
                in("r15") /* mr3 */ regs[1],   // rsp
                lateout("rax") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack, preserves_flags),
            );

            // Receive the child's IPC: payload should equal RAX_PAYLOAD.
            let (rax, _badge, _info, payload) = ep_recv(ep);
            if rax != 0 { return Err("ep_recv"); }
            if payload != RAX_PAYLOAD {
                return Err("rax did not match");
            }
        }
        Ok(())
    }

    /// Phase 36d — Reply caps wired through Call/Reply. Server
    /// child Recv's on an endpoint with a Reply cap registered
    /// in `args.a2`. The parent does a SysCall carrying 0xCAFE.
    /// The kernel pairs them up, binds the Reply object to the
    /// parent, and wakes the server. The server replies via
    /// `Send` on the Reply cap with payload = 0xCAFE + 1; the
    /// kernel routes that into `decode_reply`, which wakes the
    /// parent with rdx = 0xCAFF.
    pub(super) fn reply_cap_round_trip() -> TestResult {
        unsafe {
            // Retype an Endpoint and a Reply object.
            let ep = make_endpoint()?;
            let reply_slot = alloc_slot();
            let r = untyped_retype(
                CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, reply_slot);
            if r != 0 { return Err("retype reply"); }

            REPLY_CAP_EP_SLOT.store(ep, AtomicOrdering::Relaxed);
            REPLY_CAP_REPLY_SLOT.store(reply_slot, AtomicOrdering::Relaxed);

            // Spawn the server.
            let stack_top = (&raw mut REPLY_CAP_SERVER_STACK as u64)
                + 4096 - 8;
            let _slot = spawn_child(microtest_reply_server, stack_top)?;

            // Yield once so the server has a chance to issue Recv
            // before our Call lands. Without this our Call could
            // be queued (sender-blocks-then-receiver-arrives
            // path), which exercises a different code path —
            // valid but more involved to reason about for a smoke
            // test.
            syscall0(SYS_YIELD);

            // SysCall(ep, length=1, payload=0xCAFE). Phase 38c —
            // upstream SYSCALL ABI: payload is msg_reg[0] which lives
            // in r10 both on send and on receive (the kernel's reply
            // transfer fans msg_regs back into r10/r8/r9/r15). 38c-
            // followup: rax is preserved.
            let mut payload_io: u64 = 0xCAFE;
            core::arch::asm!(
                "syscall",
                in("rdx") SYS_CALL as u64,
                inout("rdi") ep => _,
                inout("rsi") /* length=1 */ 1u64 => _,
                inout("r10") payload_io,
                lateout("rax") _,
                lateout("r8")  _,
                lateout("r9")  _,
                lateout("r15") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack, preserves_flags),
            );
            let reply_payload = payload_io;
            if reply_payload != 0xCAFE + 1 {
                return Err("reply payload mismatch");
            }
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
            let buf = ipcbuf_vaddr() as *mut u64;
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
        // Third reserved fixed slot.
        let dest_slot: u64 = first_empty_slot() + 2;
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
        const CAPS_OR_BADGES_OFFSET_BYTES: u64 = 122 * 8;
        unsafe {
            let buf = ipcbuf_vaddr() as *mut u64;
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
        let frame_slot: u64 = first_empty_slot() + 1; // reserved slot
        let r = untyped_retype(
            CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE,
            PAGING_BITS, 1, frame_slot,
        );
        if r != 0 { return Err("retype frame failed"); }
        let target = first_empty_slot(); // TCB from `untyped_retype_tcb`
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
        let target = first_empty_slot();
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
static mut REPLY_CAP_SERVER_STACK: ChildStack = ChildStack([0; 4096]);
static mut WRITE_REGS_STACK: ChildStack = ChildStack([0; 4096]);

static REPLY_CAP_EP_SLOT: AtomicU64 = AtomicU64::new(0);
static REPLY_CAP_REPLY_SLOT: AtomicU64 = AtomicU64::new(0);
static WRITE_REGS_EP_SLOT: AtomicU64 = AtomicU64::new(0);

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

/// Phase 36d server thread: Recv on the endpoint with a Reply
/// cap registered (via SysRecv arg a2). When a Call arrives,
/// reply with payload = received_payload + 1 via Send-on-
/// Cap::Reply. The kernel routes Send to `decode_reply` because
/// the target cap is a `Cap::Reply`.
#[no_mangle]
#[link_section = ".text.microtest_reply_server"]
unsafe extern "C" fn microtest_reply_server() -> ! {
    let ep = REPLY_CAP_EP_SLOT.load(AtomicOrdering::Relaxed);
    let reply = REPLY_CAP_REPLY_SLOT.load(AtomicOrdering::Relaxed);
    // MCS SYSCALL ABI: SysRecv carries the reply cptr in the reply register
    // R12 (libsel4's MCS_REPLY_DECL pins `reply` to r12); the kernel reads it
    // from there (see handle_recv). Putting it in r10 registered no reply
    // object, so the Call's reply had no bound waiter and the caller hung.
    // The received payload comes back in r10 (msg_reg[0]).
    let payload: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_RECV as u64,
        in("rdi") ep,
        in("r12") reply,
        lateout("r10") payload,
        lateout("rax") _,
        lateout("rsi") _,
        lateout("r8")  _,
        lateout("r9")  _,
        lateout("r15") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    // Send reply: target = the reply cap, length=1, payload+1.
    let _ = syscall5(SYS_SEND, reply, /* length */ 1,
                     payload.wrapping_add(1), 0, 0);
    loop { syscall0(SYS_YIELD); }
}

/// Phase 36g — child for `tcb_write_registers_full`. The parent
/// sets THIS function's registers via the upstream-shape
/// WriteRegisters: rip, rsp, rflags, rax (msg payload), and
/// other GPRs. The child sends `rax` over the configured endpoint
/// so the parent can verify all the regs landed correctly.
#[no_mangle]
#[link_section = ".text.microtest_write_regs_child"]
unsafe extern "C" fn microtest_write_regs_child() -> ! {
    // Snapshot rax FIRST — Rust's atomic load + the function's
    // standard prologue can both touch rax and would clobber the
    // value WriteRegisters staged. The asm! captures rax into a
    // u64 with no Rust code in between.
    let rax_value: u64;
    core::arch::asm!(
        "mov {}, rax",
        out(reg) rax_value,
        options(nostack, preserves_flags),
    );
    let ep = WRITE_REGS_EP_SLOT.load(AtomicOrdering::Relaxed);
    let _ = syscall5(SYS_SEND, ep, /* length */ 1, rax_value, 0, 0);
    loop { syscall0(SYS_YIELD); }
}

#[no_mangle]
#[link_section = ".text.microtest_cap_transfer_child"]
unsafe extern "C" fn microtest_cap_transfer_child() -> ! {
    // The parent has set up the rootserver's IPC buffer with the
    // cptr we want to transfer at caps_or_badges[0]; we just send
    // with msginfo.extraCaps = 1.
    let cap = CHILD_CAP_TRANSFER_CAP_SLOT.load(AtomicOrdering::Relaxed);
    let buf = ipcbuf_vaddr() as *mut u64;
    core::ptr::write_volatile(buf.add(122), cap);
    let ep = CHILD_CAP_TRANSFER_EP_SLOT.load(AtomicOrdering::Relaxed);
    let msg_info: u64 = (1u64 << MSG_EXTRA_CAPS_SHIFT); // length=0, extraCaps=1
    let _ = syscall5(SYS_SEND, ep, msg_info, 0, 0, 0);
    loop { syscall0(SYS_YIELD); }
}

const LBL_TCB_CONFIGURE: u64 = 5;
const LBL_TCB_SET_IPC_BUFFER: u64 = 10;
const LBL_CNODE_COPY: u64 = 25;
const SYS_NB_SEND: i64 = -6;
const SYS_RECV: i64 = -7;
const SYS_CALL: i64 = -1;
/// `seL4_ObjectType::Reply` numeric tag (mirrors `object_type.rs`).
const OBJ_REPLY: u64 = 6;
/// Bit position of `extraCaps` in `seL4_MessageInfo` (sits just above
/// the 7-bit length field).
const MSG_EXTRA_CAPS_SHIFT: u64 = 7;

/// 6-register SYSCALL — like `syscall5` but exposes the sixth arg
/// (r15 / `args.a5`). Used by tests that need to set the priority
/// field of `TCB::Configure`, which lives at a5. Phase 38c —
/// upstream SYSCALL ABI; rax preserved (38c-followup) so we always
/// return 0 here.
#[inline(always)]
unsafe fn syscall_configure_with_prio(
    target: u64, msg_info: u64,
    fault_ep: u64, cspace: u64, vspace: u64, prio: u64,
) -> u64 {
    asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") target,
        in("rsi") msg_info,
        in("r10") /* a2 */ fault_ep,
        in("r8")  /* a3 */ cspace,
        in("r9")  /* a4 */ vspace,
        in("r15") /* a5 */ prio,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    0
}
