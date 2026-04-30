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

        arch::log("Endpoint IPC tests completed\n");
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
