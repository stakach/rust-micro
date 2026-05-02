//! Endpoint state machine + slowpath IPC transfer.
//!
//! Mirrors `seL4/src/object/endpoint.c` (sendIPC / receiveIPC /
//! cancelIPC) for the non-MCS, non-fastpath case. An endpoint is
//! always in one of three states:
//!
//!   * `Idle` — no waiters
//!   * `Send` — one or more senders queued, waiting for a receiver
//!   * `Recv` — one or more receivers queued, waiting for a sender
//!
//! The state and queue are stored in an `Endpoint` kernel object;
//! the queue is a FIFO of TCBs linked through the `ep_next`/
//! `ep_prev` fields on `Tcb`.
//!
//! The transfer itself is the slowpath: copy the sender's
//! `msg_regs[0..ipc_length]` into the receiver's, stamp the badge,
//! and unblock the receiver. Fastpath optimisation is deferred.

use crate::scheduler::Scheduler;
use crate::tcb::{TcbId, ThreadStateType};
use crate::types::seL4_Word as Word;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum EpState {
    #[default]
    Idle,
    Send,
    Recv,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Endpoint {
    pub state: EpState,
    pub head: Option<TcbId>,
    pub tail: Option<TcbId>,
}

impl Endpoint {
    pub const fn new() -> Self {
        Self { state: EpState::Idle, head: None, tail: None }
    }
}

// ---------------------------------------------------------------------------
// Internal queue helpers — push to tail, pop from head, remove
// arbitrary node. All operate on `tcb.ep_next` / `tcb.ep_prev`.
// ---------------------------------------------------------------------------

fn queue_push(ep: &mut Endpoint, sched: &mut Scheduler, t: TcbId) {
    let prev_tail = ep.tail;
    {
        let tcb = sched.slab.get_mut(t);
        tcb.ep_prev = prev_tail;
        tcb.ep_next = None;
    }
    match prev_tail {
        Some(p) => sched.slab.get_mut(p).ep_next = Some(t),
        None => ep.head = Some(t),
    }
    ep.tail = Some(t);
}

fn queue_pop_head(ep: &mut Endpoint, sched: &mut Scheduler) -> Option<TcbId> {
    let head = ep.head?;
    let next = sched.slab.get(head).ep_next;
    ep.head = next;
    match next {
        Some(n) => sched.slab.get_mut(n).ep_prev = None,
        None => ep.tail = None,
    }
    let tcb = sched.slab.get_mut(head);
    tcb.ep_next = None;
    tcb.ep_prev = None;
    Some(head)
}

fn queue_remove(ep: &mut Endpoint, sched: &mut Scheduler, t: TcbId) {
    let (prev, next) = {
        let tcb = sched.slab.get(t);
        (tcb.ep_prev, tcb.ep_next)
    };
    match prev {
        Some(p) => sched.slab.get_mut(p).ep_next = next,
        None => ep.head = next,
    }
    match next {
        Some(n) => sched.slab.get_mut(n).ep_prev = prev,
        None => ep.tail = prev,
    }
    let tcb = sched.slab.get_mut(t);
    tcb.ep_next = None;
    tcb.ep_prev = None;
}

fn queue_is_empty(ep: &Endpoint) -> bool {
    ep.head.is_none()
}

// ---------------------------------------------------------------------------
// Public IPC primitives.
// ---------------------------------------------------------------------------

/// Options for `send_ipc`. Mirrors the `bool blocking, bool do_call,
/// word_t badge` triple in seL4's `sendIPC`.
#[derive(Copy, Clone, Debug)]
pub struct SendOptions {
    pub blocking: bool,
    pub do_call: bool,
    pub badge: Word,
}

impl SendOptions {
    pub const fn blocking(badge: Word) -> Self {
        Self { blocking: true, do_call: false, badge }
    }
}

/// Options for `receive_ipc`.
#[derive(Copy, Clone, Debug, Default)]
pub struct RecvOptions {
    pub blocking: bool,
}

impl RecvOptions {
    pub const fn blocking() -> Self { Self { blocking: true } }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpcOutcome {
    /// Message transferred to a waiting peer. `peer` is the TCB now
    /// holding the message.
    Transferred { peer: TcbId },
    /// Caller blocked; no peer was waiting.
    Blocked,
    /// Non-blocking call had no peer; nothing happened.
    Skipped,
}

pub fn send_ipc(
    ep: &mut Endpoint,
    sched: &mut Scheduler,
    sender: TcbId,
    opts: SendOptions,
) -> IpcOutcome {
    match ep.state {
        // No receivers waiting — caller blocks if blocking.
        EpState::Idle | EpState::Send => {
            if !opts.blocking {
                return IpcOutcome::Skipped;
            }
            // Call vs Send: a Call waits for the matched receiver
            // to issue Reply, so the sender goes straight to
            // BlockedOnReply once the message is delivered.
            // Without a receiver waiting it still queues on Send;
            // the call-vs-send distinction is observed when the
            // pair-up actually happens.
            sched.block(sender, ThreadStateType::BlockedOnSend);
            queue_push(ep, sched, sender);
            ep.state = EpState::Send;
            IpcOutcome::Blocked
        }
        // A receiver is queued — wake the head and transfer.
        EpState::Recv => {
            let receiver = queue_pop_head(ep, sched)
                .expect("Recv state must have at least one waiter");
            transfer(sched, sender, receiver, opts.badge);
            transfer_extra_caps(sched, sender, receiver);
            if opts.do_call {
                // Call: block sender BlockedOnReply, set the
                // receiver's reply_to to the caller.
                sched.block(sender, ThreadStateType::BlockedOnReply);
                sched.slab.get_mut(receiver).reply_to = Some(sender);
                // Phase 33c — donate the caller's SchedContext to
                // the callee for the duration of the call. The
                // callee runs on the caller's budget; the receiver
                // restores its own SC on `seL4_Reply`.
                let donated = sched.slab.get(sender).sc;
                if donated.is_some() {
                    sched.slab.get_mut(receiver).active_sc = donated;
                }
                // Phase 36d — if the receiver registered a Reply
                // slot via `Recv(ep, reply=cptr)`, bind that Reply
                // object to the caller. Send-on-Cap::Reply later
                // looks up `bound_tcb` to wake the caller. The
                // legacy `reply_to` path stays in place for
                // backward compat with kernel specs that don't
                // wire a Reply cap.
                if let Some(reply_idx) =
                    sched.slab.get_mut(receiver).pending_reply.take()
                {
                    unsafe {
                        let s = crate::kernel::KERNEL.get();
                        s.replies[reply_idx as usize].bound_tcb = Some(sender);
                    }
                }
            }
            sched.make_runnable(receiver);
            if queue_is_empty(ep) {
                ep.state = EpState::Idle;
            }
            IpcOutcome::Transferred { peer: receiver }
        }
    }
}

pub fn receive_ipc(
    ep: &mut Endpoint,
    sched: &mut Scheduler,
    receiver: TcbId,
    opts: RecvOptions,
) -> IpcOutcome {
    match ep.state {
        // No senders queued — block (or skip if NB).
        EpState::Idle | EpState::Recv => {
            if !opts.blocking {
                return IpcOutcome::Skipped;
            }
            sched.block(receiver, ThreadStateType::BlockedOnReceive);
            queue_push(ep, sched, receiver);
            ep.state = EpState::Recv;
            IpcOutcome::Blocked
        }
        // Sender queued — pair them off.
        EpState::Send => {
            let sender = queue_pop_head(ep, sched)
                .expect("Send state must have at least one waiter");
            // The sender's `ipc_badge` field was set on the original
            // send call — re-use it instead of consulting the cap.
            let badge = sched.slab.get(sender).ipc_badge;
            transfer(sched, sender, receiver, badge);
            transfer_extra_caps(sched, sender, receiver);
            sched.make_runnable(sender);
            if queue_is_empty(ep) {
                ep.state = EpState::Idle;
            }
            IpcOutcome::Transferred { peer: sender }
        }
    }
}

/// Cancel an in-flight IPC: remove the thread from whichever
/// endpoint queue it's parked on, mark it Restart so the caller can
/// retry. Mirrors `cancelIPC` in seL4 for the endpoint case only.
pub fn cancel_ipc(ep: &mut Endpoint, sched: &mut Scheduler, thread: TcbId) {
    let state = sched.slab.get(thread).state;
    if !matches!(
        state,
        ThreadStateType::BlockedOnSend | ThreadStateType::BlockedOnReceive,
    ) {
        return;
    }
    queue_remove(ep, sched, thread);
    sched.slab.get_mut(thread).state = ThreadStateType::Restart;
    if queue_is_empty(ep) {
        ep.state = EpState::Idle;
    }
}

// ---------------------------------------------------------------------------
// Message transfer. seL4's `doIPCTransfer` does considerably more
// (cap transfer, fault payload), but for the bytewise message-
// register copy this is the whole story.
// ---------------------------------------------------------------------------

fn transfer(sched: &mut Scheduler, sender: TcbId, receiver: TcbId, badge: Word) {
    // We need both TCBs mutable simultaneously. Borrow each entry
    // separately by index — the Slab guarantees they're distinct
    // memory because TcbIds are unique.
    let (label, length, regs) = {
        let s = sched.slab.get(sender);
        (s.ipc_label, s.ipc_length, s.msg_regs)
    };
    let r = sched.slab.get_mut(receiver);
    r.ipc_label = label;
    r.ipc_length = length;
    r.ipc_badge = badge;
    let n = (length as usize).min(r.msg_regs.len());
    r.msg_regs[..n].copy_from_slice(&regs[..n]);

    // Phase 34c — fan words 4..length out to the receiver's IPC
    // buffer page so userspace can read them. Words 0..3 ride in
    // registers (rdx/r10/r8/r9 below) and don't need the buffer.
    if length > 4 && r.ipc_buffer_paddr != 0 {
        let buf = (r.ipc_buffer_paddr as *mut u64).wrapping_add(1); // skip tag word
        let max = (length as usize).min(regs.len());
        for i in 4..max {
            unsafe { core::ptr::write_volatile(buf.add(i), regs[i]); }
        }
    }

    // Phase 29h — fan the IPC payload into the receiver's
    // user-visible registers immediately. The dispatcher's existing
    // tail only fans-in when the in-flight syscall is the receiver's
    // SysRecv, which doesn't cover the "receiver-blocked-first,
    // sender-arrives-later" path. We do it here so the receiver's
    // saved user_context has the right values whenever it next runs.
    #[cfg(target_arch = "x86_64")]
    {
        let mi = (label << 12) | (length as Word & 0x7F);
        // Phase 38c-followup — rax is preserved across SYSCALL.
        // Upstream seL4 signals success/error via the IPC label in
        // msginfo and faults via the parent's fault EP, not via a
        // rax sentinel.
        r.user_context.rsi = mi;
        r.user_context.rdi = badge;
        // Upstream seL4 x86_64 IPC return ABI: msg_regs[0..3] map to
        // r10/r8/r9/r15 (matches `x64_sys_recv` in libsel4).
        r.user_context.r10 = r.msg_regs[0];
        r.user_context.r8  = r.msg_regs[1];
        r.user_context.r9  = r.msg_regs[2];
        r.user_context.r15 = r.msg_regs[3];
    }
}

/// Phase 34d — copy any caps the sender staged on
/// `pending_extra_caps` into the receiver's CSpace at the slots the
/// receiver named in its IPC buffer (`receiveCNode` / `receiveIndex`).
/// `receiveCNode == 0` means "use the receiver's own cspace_root".
///
/// `receiveDepth` is read but currently ignored — our flat-radix
/// CNodes don't traverse hierarchies on the receive side.
pub fn transfer_extra_caps(
    sched: &mut crate::scheduler::Scheduler,
    sender: TcbId,
    receiver: TcbId,
) {
    let count = sched.slab.get(sender).pending_extra_caps_count as usize;
    if count == 0 { return; }
    let recv_buf_paddr = sched.slab.get(receiver).ipc_buffer_paddr;
    if recv_buf_paddr == 0 {
        // No buffer to consult — drop the staged caps.
        sched.slab.get_mut(sender).pending_extra_caps_count = 0;
        return;
    }

    // Read receive descriptor from receiver's IPC buffer.
    let (recv_cnode_cptr, recv_index) = unsafe {
        let buf = recv_buf_paddr as *const u64;
        (
            core::ptr::read_volatile(buf.add(crate::ipc_buffer::RECEIVE_CNODE_OFFSET)),
            core::ptr::read_volatile(buf.add(crate::ipc_buffer::RECEIVE_INDEX_OFFSET))
                as usize,
        )
    };

    let recv_cspace = sched.slab.get(receiver).cspace_root;
    let target_cnode_cap = if recv_cnode_cptr == 0 {
        recv_cspace
    } else {
        match unsafe {
            crate::cspace::lookup_cap(crate::kernel::KERNEL.get(),
                &recv_cspace, recv_cnode_cptr)
        } {
            Ok(c) => c,
            Err(_) => {
                sched.slab.get_mut(sender).pending_extra_caps_count = 0;
                return;
            }
        }
    };
    let cnode_ptr = match target_cnode_cap {
        crate::cap::Cap::CNode { ptr, .. } => ptr,
        _ => {
            sched.slab.get_mut(sender).pending_extra_caps_count = 0;
            return;
        }
    };
    let cnode_idx = unsafe {
        crate::kernel::KernelState::cnode_index(cnode_ptr)
    };

    unsafe {
        let s = crate::kernel::KERNEL.get();
        let staged = s.scheduler.slab.get(sender).pending_extra_caps;
        let slots = &mut s.cnodes[cnode_idx].0;
        for i in 0..count {
            let dest_idx = recv_index + i;
            if dest_idx >= slots.len() { break; }
            // Don't clobber an existing cap.
            if !slots[dest_idx].cap().is_null() { continue; }
            slots[dest_idx].set_cap(&staged[i]);
            // MDB: the new cap is derived from… we have no source
            // CTE id (the cap was looked up by cptr through the
            // sender's CSpace, not retyped). For now record None;
            // proper provenance tracking is a follow-up.
            slots[dest_idx].set_parent(None);
        }
    }
    sched.slab.get_mut(sender).pending_extra_caps_count = 0;
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::tcb::{Tcb, ThreadStateType};

    fn runnable(prio: u8) -> Tcb {
        let mut t = Tcb::default();
        t.priority = prio;
        t.state = ThreadStateType::Running;
        t
    }

    pub fn test_endpoint() {
        arch::log("Running endpoint IPC tests...\n");

        send_meets_waiting_receiver();
        recv_meets_waiting_sender();
        sender_blocks_then_receiver_arrives();
        non_blocking_send_with_no_receiver();
        cancel_ipc_unblocks_thread();
        multiple_senders_queue_in_order();
        long_message_via_ipc_buffer();
        extra_cap_transfer_via_ipc();

        arch::log("Endpoint IPC tests completed\n");
    }

    /// Phase 34d — staging an Endpoint cap on the sender and
    /// arranging for a receive slot via the receiver's IPC buffer
    /// should land the cap in the receiver's CSpace at the named
    /// slot after the IPC transfer.
    ///
    /// Uses `KERNEL.get().scheduler` rather than a local
    /// `Scheduler::new()` — `transfer_extra_caps` reaches into
    /// `KERNEL.get().cnodes[]` via raw pointer to write the cap,
    /// so the sender/receiver TCBs need to live in the same slab
    /// that production code consults.
    #[inline(never)]
    fn extra_cap_transfer_via_ipc() {
        use crate::cap::{Cap, Badge, EndpointObj, EndpointRights, PPtr};

        #[repr(C, align(4096))]
        struct IpcPage([u64; 512]);
        static mut SENDER_BUF: IpcPage = IpcPage([0; 512]);
        static mut RECEIVER_BUF: IpcPage = IpcPage([0; 512]);

        let s = unsafe { crate::kernel::KERNEL.get() };
        s.scheduler.reset_queues();
        s.scheduler.set_current(None);

        let mut ep = Endpoint::new();
        let sender = s.scheduler.admit(runnable(50));
        let receiver = s.scheduler.admit(runnable(50));

        unsafe {
            s.scheduler.slab.get_mut(sender).ipc_buffer_paddr =
                (&raw mut SENDER_BUF) as u64;
            s.scheduler.slab.get_mut(receiver).ipc_buffer_paddr =
                (&raw mut RECEIVER_BUF) as u64;
        }

        // Receiver names slot 5 of its own CSpace as the receive
        // target. `receiveCNode = 0` ⇒ "use cspace_root".
        unsafe {
            let buf = (&raw mut RECEIVER_BUF) as *mut u64;
            core::ptr::write_volatile(
                buf.add(crate::ipc_buffer::RECEIVE_CNODE_OFFSET), 0);
            core::ptr::write_volatile(
                buf.add(crate::ipc_buffer::RECEIVE_INDEX_OFFSET), 5);
        }

        // Sender stages a fake Endpoint cap. We don't go through
        // CSpace lookup here — `transfer_extra_caps` reads from
        // `pending_extra_caps[]` directly.
        let to_transfer = Cap::Endpoint {
            ptr: PPtr::<EndpointObj>::new(0x4000).unwrap(),
            badge: Badge(0xBEEF),
            rights: EndpointRights {
                can_send: true, can_receive: true,
                can_grant: false, can_grant_reply: false,
            },
        };
        s.scheduler.slab.get_mut(sender).pending_extra_caps[0] = to_transfer;
        s.scheduler.slab.get_mut(sender).pending_extra_caps_count = 1;

        // Plant the receiver's cspace_root pointing at CNode 0 so
        // `transfer_extra_caps` can resolve the receive CNode.
        let cspace = Cap::CNode {
            ptr: crate::kernel::KernelState::cnode_ptr(0),
            radix: 5, guard_size: 59, guard: 0,
        };
        s.scheduler.slab.get_mut(receiver).cspace_root = cspace;
        // Make sure slot 5 starts empty.
        s.cnodes[0].0[5].set_cap(&Cap::Null);

        receive_ipc(&mut ep, &mut s.scheduler, receiver, RecvOptions::blocking());
        send_ipc(&mut ep, &mut s.scheduler, sender, SendOptions::blocking(0));

        let landed = s.cnodes[0].0[5].cap();
        match landed {
            Cap::Endpoint { ptr, badge, .. } => {
                assert_eq!(ptr.addr(), 0x4000);
                assert_eq!(badge.0, 0xBEEF);
            }
            other => panic!(
                "expected Endpoint at slot 5, got {:?}", other),
        }
        s.cnodes[0].0[5].set_cap(&Cap::Null);
        assert_eq!(
            s.scheduler.slab.get(sender).pending_extra_caps_count, 0,
            "transfer should drain the staged caps");

        // Cleanup.
        s.scheduler.slab.free(sender);
        s.scheduler.slab.free(receiver);
        s.scheduler.reset_queues();
        s.scheduler.set_current(None);
        arch::log("  ✓ extra cap transfers through IPC into receiver's CNode\n");
    }

    /// Phase 34c — long-message IPC. With both TCBs sporting an
    /// `ipc_buffer_paddr`, words 4..length should round-trip
    /// through the buffer. Words 0..3 ride in `msg_regs[0..4]`.
    #[inline(never)]
    fn long_message_via_ipc_buffer() {
        // Two backing pages — one per TCB. They sit in BSS so
        // `&raw mut` doubles as a kernel-virt address; for the
        // kernel-side spec that's all we need (we don't go
        // through the BOOTBOOT identity map here, we just want
        // any writable u64 storage shared between sender and
        // receiver via a known address).
        #[repr(C, align(4096))]
        struct IpcPage([u64; 512]);
        static mut SENDER_BUF: IpcPage = IpcPage([0; 512]);
        static mut RECEIVER_BUF: IpcPage = IpcPage([0; 512]);

        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();

        let sender = sched.admit(runnable(50));
        let receiver = sched.admit(runnable(50));
        unsafe {
            sched.slab.get_mut(sender).ipc_buffer_paddr =
                (&raw mut SENDER_BUF) as u64;
            sched.slab.get_mut(receiver).ipc_buffer_paddr =
                (&raw mut RECEIVER_BUF) as u64;
        }

        // Stage an 8-word message. Words 0..3 in msg_regs (the
        // syscall-stage path normally fills these from a2..a5);
        // words 4..7 in the sender's IPC buffer at offset
        // `tag_word + i = 1 + i` (we mirror seL4's layout).
        {
            let s = sched.slab.get_mut(sender);
            s.ipc_label = 0xABCD;
            s.ipc_length = 8;
            s.msg_regs[0] = 0x1000;
            s.msg_regs[1] = 0x1001;
            s.msg_regs[2] = 0x1002;
            s.msg_regs[3] = 0x1003;
            s.msg_regs[4] = 0x1004;
            s.msg_regs[5] = 0x1005;
            s.msg_regs[6] = 0x1006;
            s.msg_regs[7] = 0x1007;
        }
        // Receiver waits.
        receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking());
        // Sender sends.
        send_ipc(&mut ep, &mut sched, sender, SendOptions::blocking(0));

        // Receiver's msg_regs should mirror the sender for words
        // 0..7, AND the receiver's ipc_buffer should hold words
        // 4..7 at offsets 5..8 (after the 1-word tag).
        unsafe {
            let r = sched.slab.get(receiver);
            for (i, &expect) in [
                0x1000u64, 0x1001, 0x1002, 0x1003,
                0x1004, 0x1005, 0x1006, 0x1007,
            ].iter().enumerate() {
                assert_eq!(r.msg_regs[i], expect,
                    "msg_regs[{}] was {:#x} expected {:#x}",
                    i, r.msg_regs[i], expect);
            }
            assert_eq!(r.ipc_length, 8);
            for i in 4..8 {
                let buf = (&raw mut RECEIVER_BUF) as *mut u64;
                let got = core::ptr::read_volatile(buf.add(1 + i));
                let expect = 0x1000u64 + i as u64;
                assert_eq!(got, expect,
                    "RECEIVER_BUF[{}] was {:#x} expected {:#x}",
                    i, got, expect);
            }
        }
        arch::log("  ✓ 8-word IPC routes 4..length through ipc_buffer\n");
    }

    #[inline(never)]
    fn send_meets_waiting_receiver() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();

        let receiver = sched.admit(runnable(50));
        let sender = sched.admit(runnable(50));

        // Receiver arrives first and blocks.
        let r = receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking());
        assert_eq!(r, IpcOutcome::Blocked);
        assert_eq!(ep.state, EpState::Recv);
        assert_eq!(sched.slab.get(receiver).state, ThreadStateType::BlockedOnReceive);

        // Sender stamps a message and sends.
        {
            let s = sched.slab.get_mut(sender);
            s.ipc_label = 0xCAFE;
            s.ipc_length = 3;
            s.msg_regs[0] = 0xAA;
            s.msg_regs[1] = 0xBB;
            s.msg_regs[2] = 0xCC;
        }
        let s = send_ipc(&mut ep, &mut sched, sender, SendOptions::blocking(0x1234));
        assert_eq!(s, IpcOutcome::Transferred { peer: receiver });
        assert_eq!(ep.state, EpState::Idle);

        // Receiver got the message.
        let r = sched.slab.get(receiver);
        assert_eq!(r.ipc_label, 0xCAFE);
        assert_eq!(r.ipc_length, 3);
        assert_eq!(r.msg_regs[0], 0xAA);
        assert_eq!(r.msg_regs[1], 0xBB);
        assert_eq!(r.msg_regs[2], 0xCC);
        assert_eq!(r.ipc_badge, 0x1234);
        assert_eq!(r.state, ThreadStateType::Running);
        arch::log("  ✓ send → waiting receiver transfers msg + badge\n");
    }

    #[inline(never)]
    fn recv_meets_waiting_sender() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();

        let sender = sched.admit(runnable(50));
        let receiver = sched.admit(runnable(50));

        // Sender arrives first; we stamp the message + badge on the
        // sender so receive_ipc can pick it up.
        {
            let s = sched.slab.get_mut(sender);
            s.ipc_label = 0xBEEF;
            s.ipc_length = 1;
            s.msg_regs[0] = 0x11;
            s.ipc_badge = 0xABCD;
        }
        let r = send_ipc(&mut ep, &mut sched, sender, SendOptions {
            blocking: true, do_call: false, badge: 0xABCD,
        });
        assert_eq!(r, IpcOutcome::Blocked);
        assert_eq!(ep.state, EpState::Send);

        // Receiver shows up and pairs off.
        let r = receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking());
        assert_eq!(r, IpcOutcome::Transferred { peer: sender });
        assert_eq!(ep.state, EpState::Idle);
        let dst = sched.slab.get(receiver);
        assert_eq!(dst.ipc_label, 0xBEEF);
        assert_eq!(dst.msg_regs[0], 0x11);
        assert_eq!(dst.ipc_badge, 0xABCD);
        arch::log("  ✓ recv finds queued sender, transfers, unblocks both\n");
    }

    #[inline(never)]
    fn sender_blocks_then_receiver_arrives() {
        // Same as recv_meets_waiting_sender but exercise the
        // make_runnable path on the sender so the scheduler queues
        // get touched.
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let sender = sched.admit(runnable(50));
        let receiver = sched.admit(runnable(50));
        send_ipc(&mut ep, &mut sched, sender, SendOptions::blocking(0));
        // The sender should be blocked and out of the run queue.
        assert_eq!(sched.slab.get(sender).state, ThreadStateType::BlockedOnSend);
        receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking());
        // Both are runnable again; the scheduler queue at prio 50
        // contains both.
        assert_eq!(sched.slab.get(sender).state, ThreadStateType::Running);
        assert_eq!(sched.slab.get(receiver).state, ThreadStateType::Running);
        arch::log("  ✓ blocked sender re-enters scheduler on transfer\n");
    }

    #[inline(never)]
    fn non_blocking_send_with_no_receiver() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let sender = sched.admit(runnable(50));
        let r = send_ipc(&mut ep, &mut sched, sender, SendOptions {
            blocking: false, do_call: false, badge: 0,
        });
        assert_eq!(r, IpcOutcome::Skipped);
        assert_eq!(ep.state, EpState::Idle);
        // Sender stays runnable.
        assert_eq!(sched.slab.get(sender).state, ThreadStateType::Running);
        arch::log("  ✓ non-blocking send with no receiver skips silently\n");
    }

    #[inline(never)]
    fn cancel_ipc_unblocks_thread() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let sender = sched.admit(runnable(50));
        send_ipc(&mut ep, &mut sched, sender, SendOptions::blocking(0));
        assert_eq!(sched.slab.get(sender).state, ThreadStateType::BlockedOnSend);

        cancel_ipc(&mut ep, &mut sched, sender);
        assert_eq!(sched.slab.get(sender).state, ThreadStateType::Restart);
        assert_eq!(ep.state, EpState::Idle);
        // Sender's ep links are cleared.
        assert!(sched.slab.get(sender).ep_next.is_none());
        assert!(sched.slab.get(sender).ep_prev.is_none());
        arch::log("  ✓ cancel_ipc removes thread from queue, sets Restart\n");
    }

    #[inline(never)]
    fn multiple_senders_queue_in_order() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let s1 = sched.admit(runnable(50));
        let s2 = sched.admit(runnable(50));
        let s3 = sched.admit(runnable(50));
        for s in &[s1, s2, s3] {
            sched.slab.get_mut(*s).msg_regs[0] = s.0 as u64;
            send_ipc(&mut ep, &mut sched, *s, SendOptions::blocking(0));
        }
        let r = sched.admit(runnable(50));
        // First receive picks up s1.
        let out = receive_ipc(&mut ep, &mut sched, r, RecvOptions::blocking());
        assert_eq!(out, IpcOutcome::Transferred { peer: s1 });
        // Second, s2.
        let out = receive_ipc(&mut ep, &mut sched, r, RecvOptions::blocking());
        assert_eq!(out, IpcOutcome::Transferred { peer: s2 });
        // Third, s3.
        let out = receive_ipc(&mut ep, &mut sched, r, RecvOptions::blocking());
        assert_eq!(out, IpcOutcome::Transferred { peer: s3 });
        arch::log("  ✓ multiple senders dequeued in FIFO order\n");
    }
}
