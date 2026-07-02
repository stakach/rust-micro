//! SURT scenarios, driven through the **published `surt-sel4` crate**.
//!
//! A progression that culminates in the flagship: `single_thread` →
//! `two_thread_notify` → `multiprocess` → `connect` → `cap_transfer` (two
//! fully-isolated components, own CSpaces, ring frame + notification caps
//! transferred over IPC). The transport itself is `surt_sel4::surt_core`; the
//! seL4 glue is `surt_sel4::{Sel4Env, Sel4Notify, drain_blocking}`, with
//! `KernelEnv` implementing the two-syscall platform contract for this kernel.
//!
//! Everything below `KernelEnv` is ordinary seL4 root-task code (retype, map,
//! spawn, cap-transfer handshake) that a downstream project writes once — it is
//! deliberately verbatim from the proven kernel microtests so the demo is a
//! faithful reference.

use crate::*;
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use surt_sel4::surt_core;
use surt_sel4::{drain_adaptive, drain_blocking, CPtr, DrainExit, Sel4Env, Sel4Notify};

// ---------------------------------------------------------------------------
// The platform contract: SURT's fast-path wakeup needs exactly two seL4
// syscalls. `KernelEnv` implements them against this kernel's ABI; on upstream
// seL4 you'd implement the same trait over the `sel4` crate.
// ---------------------------------------------------------------------------
struct KernelEnv;

impl Sel4Env for KernelEnv {
    fn signal(&self, ntfn: CPtr) {
        // seL4_Signal — Send to a Notification cap, length 0, no IPC buffer.
        unsafe {
            syscall5(SYS_SEND, ntfn, 0, 0, 0, 0);
        }
    }
    fn wait(&self, ntfn: CPtr) {
        // seL4_Wait — Recv on the notification; the badge is discarded.
        unsafe {
            let _ = ep_recv(ntfn);
        }
    }
}

static ENV: KernelEnv = KernelEnv;

// ---------------------------------------------------------------------------
// Slot allocator + boot-cap plumbing (runtime values from BootInfo).
// ---------------------------------------------------------------------------
static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_START: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_COUNT: AtomicU64 = AtomicU64::new(0);

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, AtomicOrdering::Relaxed)
}

// Extra invocation labels / object types used by the SURT handshake.
const LBL_CNODE_COPY: u64 = 25;
const LBL_CNODE_MINT: u64 = 26;
const LBL_TCB_SET_IPC_BUFFER: u64 = 10;
const MSG_EXTRA_CAPS_SHIFT: u64 = 7;
const OBJ_CNODE: u64 = 4; // CapTable
const OBJ_UNTYPED: u64 = 0;

const SURT_N: u64 = 100;
const SURT_QLEN: u32 = 16;

// ---------------------------------------------------------------------------
// Shared spawn helpers.
// ---------------------------------------------------------------------------

/// Retype + configure + bind a round-robin SchedContext to `tcb_slot` so it is
/// independently schedulable under MCS (a no-SC TCB is Resume-able but never
/// dispatched).
unsafe fn attach_sched_context(tcb_slot: u64) -> Result<u64, &'static str> {
    let sc_slot = alloc_slot();
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc_slot);
    if r != 0 {
        return Err("retype SC");
    }
    let r = sched_control_configure(SLOT_SCHED_CONTROL, sc_slot, /* budget */ 10, /* period */ 10);
    if r != 0 {
        return Err("sched_control configure");
    }
    let r = sched_context_bind(sc_slot, tcb_slot);
    if r != 0 {
        return Err("sc bind");
    }
    Ok(sc_slot)
}

/// Spawn a child TCB sharing the rootserver's CSpace + VSpace at priority 100.
unsafe fn spawn_child(entry: unsafe extern "C" fn() -> !, stack_top: u64) -> Result<u64, &'static str> {
    let slot = alloc_slot();
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, slot);
    if r != 0 {
        return Err("retype TCB");
    }
    let r = tcb_set_space(slot, 0, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
    if r != 0 {
        return Err("setspace");
    }
    let r = tcb_write_registers(slot, entry as u64, stack_top, 0);
    if r != 0 {
        return Err("writeregs");
    }
    let r = tcb_set_priority(slot, 100);
    if r != 0 {
        return Err("setprio");
    }
    attach_sched_context(slot)?;
    let r = tcb_resume(slot);
    if r != 0 {
        return Err("resume");
    }
    Ok(slot)
}

/// Retype an Endpoint into a fresh slot.
unsafe fn make_endpoint() -> Result<u64, &'static str> {
    let slot = alloc_slot();
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_ENDPOINT, 0, 1, slot);
    if r != 0 {
        return Err("retype endpoint");
    }
    Ok(slot)
}

/// Retype a Notification into a fresh slot.
unsafe fn make_notification() -> Result<u64, &'static str> {
    let slot = alloc_slot();
    let r = untyped_retype(CAP_INIT_UNTYPED, OBJ_NOTIFICATION, 0, 1, slot);
    if r != 0 {
        return Err("retype notification");
    }
    Ok(slot)
}

// ---------------------------------------------------------------------------
// Scenario 2: two threads over one ring + a Notification (coalesced wakeup).
// ---------------------------------------------------------------------------
#[repr(C, align(64))]
struct SurtBuf([u8; 1536]); // ring_bytes::<SurtSqe>(16) = 1472 <= 1536
static mut SURT_RING: SurtBuf = SurtBuf([0; 1536]);
#[repr(C, align(16))]
struct SurtStack([u8; 16384]);
static mut SURT_CONS_STACK: SurtStack = SurtStack([0; 16384]);
static SURT_NTFN: AtomicU64 = AtomicU64::new(0);
static SURT_ACK: AtomicU64 = AtomicU64::new(0);
static SURT_DONE: AtomicU64 = AtomicU64::new(0);

/// Consumer child (same VSpace): drains the shared ring via the coalesced
/// blocking protocol, recording the outcome in `SURT_DONE`.
#[no_mangle]
unsafe extern "C" fn surt_consumer_child() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::{Consumer, WaitDecision};

    let ptr = core::ptr::addr_of_mut!(SURT_RING) as *mut u8;
    let len = 1536usize;
    let notify = Sel4Notify::new(&ENV, SURT_NTFN.load(AtomicOrdering::Relaxed));
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
                let _ = ep_send_one(ack, 0);
                if expect == SURT_N {
                    loop {
                        notify.wait();
                    }
                }
            }
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
// Scenario 3: multiprocess — consumer in a SEPARATE VSpace, shared ring frame.
// ---------------------------------------------------------------------------
const MP_IMAGE_BASE_VADDR: u64 = 0x0000_0100_0040_0000;
const MP_STACK_VADDR: u64 = 0x0000_0100_005F_E000;
const MP_RING_VADDR: u64 = 0x0000_0100_005F_F000;
const MP_RING_LEN: usize = 1536;
const MP_ARGS_OFF: usize = 2048;
const MP_MAGIC: u64 = 0x5355_5254_4D50_5F31; // "SURTMP_1"

/// Consumer entry, run in a SEPARATE VSpace. Touches only stack locals, the
/// shared ring frame, and const cptrs read from the frame — NO writable static.
#[no_mangle]
#[link_section = ".text.surt_multiproc_consumer"]
unsafe extern "C" fn surt_multiproc_consumer() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::{Consumer, WaitDecision};

    let args = (MP_RING_VADDR + MP_ARGS_OFF as u64) as *const u64;
    let magic = core::ptr::read_volatile(args);
    let ack = core::ptr::read_volatile(args.add(1));
    let notify = Sel4Notify::new(&ENV, core::ptr::read_volatile(args.add(2)));
    if magic != MP_MAGIC {
        loop {
            yield_now();
        }
    }

    let mut c = match Consumer::<SurtSqe>::attach(MP_RING_VADDR as *mut u8, MP_RING_LEN) {
        Ok(c) => c,
        Err(_) => {
            let _ = ep_send_one(ack, 0xBADA);
            loop {
                notify.wait();
            }
        }
    };
    let mut expect = 0u64;
    loop {
        match c.try_pop() {
            Ok(Some(e)) => {
                if e.request_id != expect || e.user_data != !expect {
                    let _ = ep_send_one(ack, 0xBAD0);
                    loop {
                        notify.wait();
                    }
                }
                let _ = ep_send_one(ack, expect);
                expect += 1;
                if expect == SURT_N {
                    loop {
                        notify.wait();
                    }
                }
            }
            Ok(None) => match c.prepare_wait() {
                Ok(WaitDecision::Block) => notify.wait(),
                Ok(WaitDecision::Ready) => {}
                Err(_) => {
                    let _ = ep_send_one(ack, 0xBAD2);
                    loop {
                        notify.wait();
                    }
                }
            },
            Err(_) => {
                let _ = ep_send_one(ack, 0xBAD3);
                loop {
                    notify.wait();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 4 + 5: dynamic connect + capability transfer between isolated
// components. Vaddr layout (all inside the one 2 MiB PT of each component).
// ---------------------------------------------------------------------------
const CONN_IMAGE_BASE: u64 = 0x0000_0100_0040_0000;
const CONN_SCRATCH_VADDR: u64 = 0x0000_0100_005F_C000;
const CONN_ARGS_VADDR: u64 = 0x0000_0100_005F_D000;
const CONN_STACK_VADDR: u64 = 0x0000_0100_005F_E000;
const CONN_RING_VADDR: u64 = 0x0000_0100_005F_F000;
const CONN_IPCBUF_VADDR: u64 = 0x0000_0100_005F_B000;
const CONN_RING_LEN: usize = 1536;
const CONN_MAGIC: u64 = 0x5355_5254_434E_5F31; // "SURTCN_1"

// Component's own CNode: radix 5 (32 slots), guard 59 so `guard_size+radix=64`
// and the component names slot k with cptr k.
const CN_RADIX: u32 = 5;
const CN_GUARD_BADGE: u64 = 59;

// Component-local cptrs (indices into each component's own CNode).
const CT_CTRL_EP: u64 = 1;
const CT_PML4: u64 = 2;
const CT_UT_OR_RESULT: u64 = 3;
const CT_RING: u64 = 4;
const CT_NTFN: u64 = 5;
const CT_RECV_FRAME: u64 = 8;
const CT_RECV_NTFN: u64 = 9;

/// Send a ≤3-word control message (no caps, fits in registers).
#[inline]
unsafe fn conn_send3(ep: u64, m0: u64, m1: u64, m2: u64) {
    let _ = syscall5(SYS_SEND, ep, 3, m0, m1, m2);
}

/// Receive a 3-word control message; returns (MR0, MR1, MR2).
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

/// Build a fresh isolated VSpace: new PML4 + one PDPT/PD/PT chain, image mapped
/// read-only, and a private stack. Returns the PML4 cptr.
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
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, CONN_IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    let stack_slot = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, stack_slot);
    let _ = page_map(stack_slot, CONN_STACK_VADDR, /* RW */ 3, pml4);
    pml4
}

/// Retype a fresh frame, fill it via a rootserver-side scratch mapping, then map
/// it into `pml4` at `vaddr` (the component reads its boot args from there).
unsafe fn make_args_frame(pml4: u64, vaddr: u64, words: &[u64]) {
    let frame = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, frame);
    let _ = page_map(frame, CONN_SCRATCH_VADDR, /* RW */ 3, CAP_INIT_THREAD_VSPACE);
    let dst = CONN_SCRATCH_VADDR as *mut u64;
    for (i, &w) in words.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), w);
    }
    let _ = page_unmap(frame);
    let _ = page_map(frame, vaddr, /* RW */ 3, pml4);
}

/// Spawn a component thread in `pml4` (shared CNode), priority 100, bound SC.
unsafe fn spawn_component(pml4: u64, entry: unsafe extern "C" fn() -> !) -> Result<u64, &'static str> {
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, 0, CAP_INIT_THREAD_CNODE, pml4);
    let stack_top = CONN_STACK_VADDR + 4096 - 8;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb)?;
    let _ = tcb_resume(tcb);
    Ok(tcb)
}

/// Producer component (shared CNode): maps the pre-created ring, announces
/// {ring frame cap, notification} to the peer, then produces.
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
        loop {
            yield_now();
        }
    }

    let cfg = RingConfig {
        queue_len: SURT_QLEN,
        ring_id: 4,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    if init_ring::<SurtSqe>(CONN_RING_VADDR as *mut u8, CONN_RING_LEN, &cfg).is_err() {
        loop {
            yield_now();
        }
    }
    let mut prod = match Producer::<SurtSqe>::attach(CONN_RING_VADDR as *mut u8, CONN_RING_LEN) {
        Ok(p) => p,
        Err(_) => loop {
            yield_now();
        },
    };

    conn_send3(control_ep, CONN_MAGIC, ring_cptr, data_ntfn);

    let notify = Sel4Notify::new(&ENV, data_ntfn);
    let mut i = 0u64;
    while i < SURT_N {
        let e = SurtSqe { request_id: i, user_data: !i, ..Default::default() };
        match prod.try_push(e) {
            Ok(()) => {
                let _ = prod.notify_consumer(&notify);
                i += 1;
            }
            Err(PushError::Full) => yield_now(),
            Err(PushError::Closed) => break,
        }
    }
    loop {
        yield_now();
    }
}

/// Consumer component (shared CNode): discovers the connection over the control
/// endpoint, maps the granted frame into its OWN VSpace, drains, reports.
#[no_mangle]
#[link_section = ".text.surt_connect_consumer"]
unsafe extern "C" fn surt_connect_consumer() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::{Consumer, WaitDecision};

    let args = CONN_ARGS_VADDR as *const u64;
    let control_ep = core::ptr::read_volatile(args.add(1));
    let result_ep = core::ptr::read_volatile(args.add(2));
    let my_pml4 = core::ptr::read_volatile(args.add(3));

    let (magic, ring_cptr, ntfn) = conn_recv3(control_ep);
    if magic != CONN_MAGIC {
        let _ = ep_send_one(result_ep, 0xBAD1);
        loop {
            yield_now();
        }
    }
    let _ = page_map(ring_cptr, CONN_RING_VADDR, /* RW */ 3, my_pml4);
    let mut c = match Consumer::<SurtSqe>::attach(CONN_RING_VADDR as *mut u8, CONN_RING_LEN) {
        Ok(c) => c,
        Err(_) => {
            let _ = ep_send_one(result_ep, 0xBAD2);
            loop {
                yield_now();
            }
        }
    };

    let notify = Sel4Notify::new(&ENV, ntfn);
    let mut expect = 0u64;
    while expect < SURT_N {
        match c.try_pop() {
            Ok(Some(e)) => {
                if e.request_id != expect || e.user_data != !expect {
                    let _ = ep_send_one(result_ep, 0xBAD3);
                    loop {
                        yield_now();
                    }
                }
                expect += 1;
            }
            Ok(None) => match c.prepare_wait() {
                Ok(WaitDecision::Block) => notify.wait(),
                Ok(WaitDecision::Ready) => {}
                Err(_) => {
                    let _ = ep_send_one(result_ep, 0xBAD4);
                    loop {
                        yield_now();
                    }
                }
            },
            Err(_) => {
                let _ = ep_send_one(result_ep, 0xBAD5);
                loop {
                    yield_now();
                }
            }
        }
    }
    let _ = ep_send_one(result_ep, 0);
    loop {
        yield_now();
    }
}

/// Consumer component (shared CNode) that drains with `drain_adaptive` — the
/// io_uring-SQPOLL-style path: busy-poll while entries flow, fall back to a
/// coalesced block only after a spin budget of consecutive empties. Same
/// handshake as `surt_connect_consumer`; only the drain loop differs.
#[no_mangle]
#[link_section = ".text.surt_adaptive_consumer"]
unsafe extern "C" fn surt_adaptive_consumer() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::Consumer;

    let args = CONN_ARGS_VADDR as *const u64;
    let control_ep = core::ptr::read_volatile(args.add(1));
    let result_ep = core::ptr::read_volatile(args.add(2));
    let my_pml4 = core::ptr::read_volatile(args.add(3));

    let (magic, ring_cptr, ntfn) = conn_recv3(control_ep);
    if magic != CONN_MAGIC {
        let _ = ep_send_one(result_ep, 0xBAD1);
        loop {
            yield_now();
        }
    }
    let _ = page_map(ring_cptr, CONN_RING_VADDR, /* RW */ 3, my_pml4);
    let mut c = match Consumer::<SurtSqe>::attach(CONN_RING_VADDR as *mut u8, CONN_RING_LEN) {
        Ok(c) => c,
        Err(_) => {
            let _ = ep_send_one(result_ep, 0xBAD2);
            loop {
                yield_now();
            }
        }
    };

    // Poll up to 64× before blocking (SQPOLL idle-timeout style). While entries
    // flow this drains with zero syscalls; it only blocks after a quiet spell,
    // woken by the producer's coalesced notify.
    let notify = Sel4Notify::new(&ENV, ntfn);
    let mut expect = 0u64;
    let mut ok = true;
    let exit = drain_adaptive(&mut c, &notify, 64, |e: &SurtSqe| {
        if e.request_id != expect || e.user_data != !expect {
            ok = false;
            return false;
        }
        expect += 1;
        expect < SURT_N
    });
    let verdict = if ok && expect == SURT_N && exit == DrainExit::Stopped { 0 } else { 0xBAD3 };
    let _ = ep_send_one(result_ep, verdict);
    loop {
        yield_now();
    }
}

/// Retype a radix-5 CNode and `CNode_Mint` a guard-59 view (so the component
/// names slot k with cptr k). Returns the guarded CNode cptr.
unsafe fn build_component_cnode() -> u64 {
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let guarded = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, guarded, raw, CN_GUARD_BADGE);
    guarded
}

/// `CNode_Copy` `src_cptr` into slot `dest_slot` of the guarded component CNode.
unsafe fn seed_cnode(cnode_guarded: u64, dest_slot: u64, src_cptr: u64) {
    let _ = syscall5(SYS_SEND, cnode_guarded, LBL_CNODE_COPY << 12, dest_slot, src_cptr, 0);
}

/// Producer with its OWN CSpace: retypes ring + notification from its own
/// Untyped, maps the ring, then TRANSFERS both caps to the peer over IPC.
#[no_mangle]
#[link_section = ".text.surt_ct_producer"]
unsafe extern "C" fn surt_ct_producer() -> ! {
    use surt_core::surt_abi::{feature, role, SurtSqe};
    use surt_core::{init_ring, Producer, PushError, RingConfig};

    let _ = untyped_retype(CT_UT_OR_RESULT, OBJ_X86_4K_PAGE, PAGING_BITS, 1, CT_RING);
    let _ = untyped_retype(CT_UT_OR_RESULT, OBJ_NOTIFICATION, 0, 1, CT_NTFN);
    let _ = page_map(CT_RING, CONN_RING_VADDR, /* RW */ 3, CT_PML4);

    let cfg = RingConfig {
        queue_len: SURT_QLEN,
        ring_id: 5,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    if init_ring::<SurtSqe>(CONN_RING_VADDR as *mut u8, CONN_RING_LEN, &cfg).is_err() {
        loop {
            yield_now();
        }
    }
    let mut prod = match Producer::<SurtSqe>::attach(CONN_RING_VADDR as *mut u8, CONN_RING_LEN) {
        Ok(p) => p,
        Err(_) => loop {
            yield_now();
        },
    };

    // Transfer {ring frame, notification} over the control endpoint (extraCaps).
    let buf = CONN_IPCBUF_VADDR as *mut u64;
    core::ptr::write_volatile(buf.add(122), CT_RING);
    core::ptr::write_volatile(buf.add(123), CT_NTFN);
    let msg_info: u64 = 1 | (2 << MSG_EXTRA_CAPS_SHIFT); // length 1 (magic) + 2 caps
    let _ = syscall5(SYS_SEND, CT_CTRL_EP, msg_info, CONN_MAGIC, 0, 0);

    let notify = Sel4Notify::new(&ENV, CT_NTFN);
    let mut i = 0u64;
    while i < SURT_N {
        let e = SurtSqe { request_id: i, user_data: !i, ..Default::default() };
        match prod.try_push(e) {
            Ok(()) => {
                let _ = prod.notify_consumer(&notify);
                i += 1;
            }
            Err(PushError::Full) => yield_now(),
            Err(PushError::Closed) => break,
        }
    }
    loop {
        yield_now();
    }
}

/// Consumer with its OWN CSpace: sets a receive path, RECEIVES the transferred
/// caps into its own CNode, maps the frame, and drains via `drain_blocking`
/// (the surt-sel4 coalesced consumer loop) — the binding's headline helper.
#[no_mangle]
#[link_section = ".text.surt_ct_consumer"]
unsafe extern "C" fn surt_ct_consumer() -> ! {
    use surt_core::surt_abi::SurtSqe;
    use surt_core::Consumer;

    let buf = CONN_IPCBUF_VADDR as *mut u64;
    core::ptr::write_volatile(buf.add(125), 0); // receiveCNode = our cspace_root
    core::ptr::write_volatile(buf.add(126), CT_RECV_FRAME); // receiveIndex
    core::ptr::write_volatile(buf.add(127), 64); // receiveDepth

    let (magic, _, _) = conn_recv3(CT_CTRL_EP);
    if magic != CONN_MAGIC {
        let _ = ep_send_one(CT_UT_OR_RESULT, 0xBAD1);
        loop {
            yield_now();
        }
    }
    let _ = page_map(CT_RECV_FRAME, CONN_RING_VADDR, /* RW */ 3, CT_PML4);
    let mut c = match Consumer::<SurtSqe>::attach(CONN_RING_VADDR as *mut u8, CONN_RING_LEN) {
        Ok(c) => c,
        Err(_) => {
            let _ = ep_send_one(CT_UT_OR_RESULT, 0xBAD2);
            loop {
                yield_now();
            }
        }
    };

    // Coalesced blocking drain via surt-sel4. The handler verifies each entry
    // and returns false once all `SURT_N` have arrived (or on a mismatch).
    let notify = Sel4Notify::new(&ENV, CT_RECV_NTFN);
    let mut expect = 0u64;
    let mut ok = true;
    let exit = drain_blocking(&mut c, &notify, |e: &SurtSqe| {
        if e.request_id != expect || e.user_data != !expect {
            ok = false;
            return false;
        }
        expect += 1;
        expect < SURT_N
    });
    let verdict = if ok && expect == SURT_N && exit == DrainExit::Stopped { 0 } else { 0xBAD3 };
    let _ = ep_send_one(CT_UT_OR_RESULT, verdict);
    loop {
        yield_now();
    }
}

/// Build an isolated component: own VSpace + own CNode (seeded per `seeds`) +
/// own IPC buffer, then spawn its TCB with that CNode as cspace_root.
unsafe fn spawn_isolated_component(
    entry: unsafe extern "C" fn() -> !,
    seeds: &[(u64, u64)],
) -> Result<u64, &'static str> {
    let pml4 = build_component_vspace();
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, CONN_IPCBUF_VADDR, /* RW */ 3, pml4);
    let cnode = build_component_cnode();
    seed_cnode(cnode, CT_PML4, pml4);
    for &(slot, src) in seeds {
        seed_cnode(cnode, slot, src);
    }
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, 0, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, CONN_IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = CONN_STACK_VADDR + 4096 - 8;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb)?;
    let _ = tcb_resume(tcb);
    Ok(tcb)
}

// ===========================================================================
// Scenarios
// ===========================================================================

type DemoResult = Result<(), &'static str>;

/// Single-thread: init a ring, push/pop 20 entries through an 8-slot ring
/// (wraparound), verify — the transport runs unchanged on the kernel ABI.
fn single_thread() -> DemoResult {
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
    unsafe { init_ring::<SurtSqe>(ptr, len, &cfg).map_err(|_| "init_ring")? };
    let mut p = unsafe { Producer::<SurtSqe>::attach(ptr, len).map_err(|_| "attach p")? };
    let mut c = unsafe { Consumer::<SurtSqe>::attach(ptr, len).map_err(|_| "attach c")? };

    for i in 0..20u64 {
        let e = SurtSqe { request_id: i, user_data: !i, ..Default::default() };
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

/// Two threads over one ring + a Notification + ack endpoint, coalesced wakeup.
fn two_thread_notify() -> DemoResult {
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
    unsafe { init_ring::<SurtSqe>(ptr, len, &cfg).map_err(|_| "init_ring")? };

    let data_ntfn = unsafe { make_notification()? };
    let ack_ep = unsafe { make_endpoint()? };
    SURT_NTFN.store(data_ntfn, AtomicOrdering::Relaxed);
    SURT_ACK.store(ack_ep, AtomicOrdering::Relaxed);
    SURT_DONE.store(0, AtomicOrdering::Relaxed);
    let notify = Sel4Notify::new(&ENV, data_ntfn);

    let mut prod = unsafe { Producer::<SurtSqe>::attach(ptr, len).map_err(|_| "attach")? };

    // `- 8`: SysV wants rsp % 16 == 8 at entry (large-model SSE else #GP).
    let stack_top = core::ptr::addr_of_mut!(SURT_CONS_STACK) as u64 + 16384 - 8;
    let _child = unsafe { spawn_child(surt_consumer_child, stack_top)? };

    for i in 0..SURT_N {
        let e = SurtSqe { request_id: i, user_data: !i, ..Default::default() };
        loop {
            match prod.try_push(e) {
                Ok(()) => break,
                Err(PushError::Full) => yield_now(),
                Err(PushError::Closed) => return Err("ring closed"),
            }
        }
        let _ = prod.notify_consumer(&notify);
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

/// Multiprocess: producer (this thread) + consumer in a SEPARATE VSpace sharing
/// one ring frame (granted by CNode_Copy + double-map).
fn multiprocess() -> DemoResult {
    use surt_core::surt_abi::{feature, role, SurtSqe};
    use surt_core::{init_ring, Producer, PushError, RingConfig};

    unsafe {
        let img_start = IMAGE_FRAMES_START.load(AtomicOrdering::Relaxed);
        let img_count = IMAGE_FRAMES_COUNT.load(AtomicOrdering::Relaxed);
        if img_count == 0 {
            return Err("no image frames");
        }

        let data_ntfn = make_notification()?;
        let ack_ep = make_endpoint()?;

        let ring_slot = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ring_slot);
        let _ = page_map(ring_slot, MP_RING_VADDR, /* RW */ 3, CAP_INIT_THREAD_VSPACE);

        let cfg = RingConfig {
            queue_len: SURT_QLEN,
            ring_id: 3,
            feature_flags: feature::REQUIRED_V0_1,
            role: role::PRODUCER,
        };
        init_ring::<SurtSqe>(MP_RING_VADDR as *mut u8, MP_RING_LEN, &cfg).map_err(|_| "init_ring")?;
        let mut prod = Producer::<SurtSqe>::attach(MP_RING_VADDR as *mut u8, MP_RING_LEN).map_err(|_| "attach producer")?;

        let args = (MP_RING_VADDR + MP_ARGS_OFF as u64) as *mut u64;
        core::ptr::write_volatile(args.add(1), ack_ep);
        core::ptr::write_volatile(args.add(2), data_ntfn);
        core::ptr::write_volatile(args, MP_MAGIC);

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

        for i in 0..img_count {
            let cp = alloc_slot();
            let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
            let _ = page_map(cp, MP_IMAGE_BASE_VADDR + i * 0x1000, /* RO */ 2, pml4);
        }

        let stack_slot = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, stack_slot);
        let _ = page_map(stack_slot, MP_STACK_VADDR, /* RW */ 3, pml4);

        let ring_copy = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, ring_copy, ring_slot, 0);
        let _ = page_map(ring_copy, MP_RING_VADDR, /* RW */ 3, pml4);

        let tcb = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
        let _ = tcb_set_space(tcb, 0, CAP_INIT_THREAD_CNODE, pml4);
        let stack_top = MP_STACK_VADDR + 4096 - 8;
        let entry: unsafe extern "C" fn() -> ! = surt_multiproc_consumer;
        let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
        let _ = tcb_set_priority(tcb, 100);
        attach_sched_context(tcb)?;
        let _ = tcb_resume(tcb);

        let notify = Sel4Notify::new(&ENV, data_ntfn);
        for i in 0..SURT_N {
            let e = SurtSqe { request_id: i, user_data: !i, ..Default::default() };
            loop {
                match prod.try_push(e) {
                    Ok(()) => break,
                    Err(PushError::Full) => yield_now(),
                    Err(PushError::Closed) => return Err("ring closed"),
                }
            }
            let _ = prod.notify_consumer(&notify);
            let (_rax, _badge, _info, payload) = ep_recv(ack_ep);
            if payload != i {
                return Err("consumer verdict mismatch");
            }
        }
        Ok(())
    }
}

/// Dynamic connect: two components, each in its own VSpace, discover + connect
/// at runtime over a control endpoint (shared CNode; cptr handoff + peer map).
fn connect() -> DemoResult {
    unsafe {
        if IMAGE_FRAMES_COUNT.load(AtomicOrdering::Relaxed) == 0 {
            return Err("no image frames");
        }
        let control_ep = make_endpoint()?;
        let result_ep = make_endpoint()?;
        let data_ntfn = make_notification()?;

        let prod_pml4 = build_component_vspace();
        let ring_slot = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ring_slot);
        let _ = page_map(ring_slot, CONN_RING_VADDR, /* RW */ 3, prod_pml4);
        let ring_copy = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, ring_copy, ring_slot, 0);
        make_args_frame(prod_pml4, CONN_ARGS_VADDR, &[CONN_MAGIC, control_ep, data_ntfn, ring_copy]);

        let cons_pml4 = build_component_vspace();
        make_args_frame(cons_pml4, CONN_ARGS_VADDR, &[CONN_MAGIC, control_ep, result_ep, cons_pml4]);

        spawn_component(prod_pml4, surt_connect_producer)?;
        spawn_component(cons_pml4, surt_connect_consumer)?;

        let (_rax, _badge, _info, verdict) = ep_recv(result_ep);
        if verdict != 0 {
            return Err("consumer reported failure");
        }
        Ok(())
    }
}

/// Full isolation + real capability transfer: two components, each with its own
/// CSpace + VSpace + IPC buffer; ring frame + notification caps move between the
/// two distinct CSpaces over IPC (extraCaps).
fn cap_transfer() -> DemoResult {
    unsafe {
        if IMAGE_FRAMES_COUNT.load(AtomicOrdering::Relaxed) == 0 {
            return Err("no image frames");
        }
        let control_ep = make_endpoint()?;
        let result_ep = make_endpoint()?;
        let prod_ut = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_UNTYPED, /* 64 KiB */ 16, 1, prod_ut);

        spawn_isolated_component(surt_ct_producer, &[(CT_CTRL_EP, control_ep), (CT_UT_OR_RESULT, prod_ut)])?;
        spawn_isolated_component(surt_ct_consumer, &[(CT_CTRL_EP, control_ep), (CT_UT_OR_RESULT, result_ep)])?;

        let (_rax, _badge, _info, verdict) = ep_recv(result_ep);
        if verdict != 0 {
            return Err("consumer reported failure");
        }
        Ok(())
    }
}

/// Adaptive (SQPOLL-style) path: the same two-isolated-component setup as
/// `connect`, but the consumer drains with `drain_adaptive` — polling while busy
/// (zero syscalls) and blocking only after an idle spin budget. Reuses
/// `surt_connect_producer`; both components run round-robin at the same priority.
fn adaptive() -> DemoResult {
    unsafe {
        if IMAGE_FRAMES_COUNT.load(AtomicOrdering::Relaxed) == 0 {
            return Err("no image frames");
        }
        let control_ep = make_endpoint()?;
        let result_ep = make_endpoint()?;
        let data_ntfn = make_notification()?;

        let prod_pml4 = build_component_vspace();
        let ring_slot = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ring_slot);
        let _ = page_map(ring_slot, CONN_RING_VADDR, /* RW */ 3, prod_pml4);
        let ring_copy = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, ring_copy, ring_slot, 0);
        make_args_frame(prod_pml4, CONN_ARGS_VADDR, &[CONN_MAGIC, control_ep, data_ntfn, ring_copy]);

        let cons_pml4 = build_component_vspace();
        make_args_frame(cons_pml4, CONN_ARGS_VADDR, &[CONN_MAGIC, control_ep, result_ep, cons_pml4]);

        spawn_component(prod_pml4, surt_connect_producer)?;
        spawn_component(cons_pml4, surt_adaptive_consumer)?;

        let (_rax, _badge, _info, verdict) = ep_recv(result_ep);
        if verdict != 0 {
            return Err("consumer reported failure");
        }
        Ok(())
    }
}

// ===========================================================================
// Harness
// ===========================================================================

struct Scenario {
    name: &'static str,
    body: fn() -> DemoResult,
}

const SCENARIOS: &[Scenario] = &[
    Scenario { name: "single_thread", body: single_thread },
    Scenario { name: "two_thread_notify", body: two_thread_notify },
    Scenario { name: "multiprocess", body: multiprocess },
    Scenario { name: "connect", body: connect },
    Scenario { name: "cap_transfer", body: cap_transfer },
    Scenario { name: "adaptive", body: adaptive },
];

/// Run every scenario, print a summary, then the kernel-exit sentinel.
pub unsafe fn run(empty_start: u64, image_frames_start: u64, image_frames_count: u64) {
    NEXT_SLOT.store(empty_start, AtomicOrdering::Relaxed);
    IMAGE_FRAMES_START.store(image_frames_start, AtomicOrdering::Relaxed);
    IMAGE_FRAMES_COUNT.store(image_frames_count, AtomicOrdering::Relaxed);

    print_str(b"[surt-demo] SURT ring transport on rust-micro via the published surt-sel4 crate\n");
    let mut passed = 0usize;
    let mut failed = 0usize;
    for s in SCENARIOS.iter() {
        match (s.body)() {
            Ok(()) => {
                print_str(b"  PASS ");
                print_str(s.name.as_bytes());
                print_str(b"\n");
                passed += 1;
            }
            Err(why) => {
                print_str(b"  FAIL ");
                print_str(s.name.as_bytes());
                print_str(b": ");
                print_str(why.as_bytes());
                print_str(b"\n");
                failed += 1;
            }
        }
    }
    print_str(b"[surt-demo summary: ");
    print_u64(passed as u64);
    print_str(b" passed, ");
    print_u64(failed as u64);
    print_str(b" failed]\n");
    // The kernel's serial exit hook watches for this exact sentinel to qemu_exit.
    print_str(b"[microtest done]\n");
}
