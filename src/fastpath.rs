//! Phase 10c — IPC fastpath.
//!
//! Mirrors seL4/src/fastpath/fastpath.c. The fastpath skips most of
//! the slowpath's bookkeeping for the common case: an endpoint with
//! exactly one waiter, both threads at the same priority, message
//! payload short enough to live in registers. When the preconditions
//! don't hold, control falls through to the slowpath in
//! `endpoint.rs`.
//!
//! Gated behind `fastpath`. Combines with the slowpath: callers
//! should `try_fastpath_*` first, then fall back to `send_ipc` /
//! `receive_ipc` on `Reject`.

#![cfg(feature = "fastpath")]

use crate::endpoint::{Endpoint, EpState};
use crate::scheduler::Scheduler;
use crate::tcb::{TcbId, ThreadStateType, SCRATCH_MSG_LEN};
use crate::types::seL4_Word as Word;

/// Maximum message length that the fastpath handles. Anything
/// longer falls through to the slowpath, which can spill into the
/// IPC buffer page.
pub const FASTPATH_MAX_MSG_LEN: u32 = 4;

/// Outcome of a fastpath attempt.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FastpathOutcome {
    /// Fastpath succeeded and the transfer completed. `peer` is the
    /// other thread now runnable with the message.
    Took { peer: TcbId },
    /// One of the preconditions failed; caller should retry on the
    /// slowpath.
    Reject(RejectReason),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RejectReason {
    /// Endpoint isn't in the matching state for the requested op.
    EpStateMismatch,
    /// Message wouldn't fit in registers.
    MessageTooLong,
    /// Sender and receiver have different priorities — the fastpath
    /// only handles the equal-priority case to avoid touching the
    /// scheduler bitmap.
    PriorityMismatch,
    /// Receiver's TCB isn't in the expected `BlockedOnReceive` state.
    ReceiverNotBlocked,
}

/// Try the send-fastpath. Mirrors `fastpath_call` in seL4 for the
/// part that does the transfer (we omit the cap-grant + reply-cap
/// installation, which depend on an MDB layer not yet ported).
pub fn try_fastpath_send(
    ep: &mut Endpoint,
    sched: &mut Scheduler,
    sender: TcbId,
    badge: Word,
) -> FastpathOutcome {
    // Precondition: endpoint must have a waiting receiver.
    if ep.state != EpState::Recv {
        return FastpathOutcome::Reject(RejectReason::EpStateMismatch);
    }
    let receiver = match ep.head {
        Some(t) => t,
        None => return FastpathOutcome::Reject(RejectReason::EpStateMismatch),
    };
    // Receiver must actually be blocked-on-receive.
    if sched.slab.get(receiver).state != ThreadStateType::BlockedOnReceive {
        return FastpathOutcome::Reject(RejectReason::ReceiverNotBlocked);
    }
    // Same priority (so we don't have to peek at the scheduler bitmap).
    let s_prio = sched.slab.get(sender).priority;
    let r_prio = sched.slab.get(receiver).priority;
    if s_prio != r_prio {
        return FastpathOutcome::Reject(RejectReason::PriorityMismatch);
    }
    // Message must be short enough to live in regs.
    let length = sched.slab.get(sender).ipc_length;
    if length > FASTPATH_MAX_MSG_LEN {
        return FastpathOutcome::Reject(RejectReason::MessageTooLong);
    }

    // All preconditions hold — pop the receiver, copy the message
    // inline, mark both runnable. This is the inlined transfer.
    pop_head(ep, sched);
    let (label, regs) = {
        let s = sched.slab.get(sender);
        (s.ipc_label, s.msg_regs)
    };
    let r = sched.slab.get_mut(receiver);
    r.ipc_label = label;
    r.ipc_length = length;
    r.ipc_badge = badge;
    let n = (length as usize).min(SCRATCH_MSG_LEN);
    r.msg_regs[..n].copy_from_slice(&regs[..n]);
    drop(r);

    sched.make_runnable(receiver);
    if ep.head.is_none() {
        ep.state = EpState::Idle;
    }
    FastpathOutcome::Took { peer: receiver }
}

/// Try the receive-fastpath. Symmetric to send.
pub fn try_fastpath_recv(
    ep: &mut Endpoint,
    sched: &mut Scheduler,
    receiver: TcbId,
) -> FastpathOutcome {
    if ep.state != EpState::Send {
        return FastpathOutcome::Reject(RejectReason::EpStateMismatch);
    }
    let sender = match ep.head {
        Some(t) => t,
        None => return FastpathOutcome::Reject(RejectReason::EpStateMismatch),
    };
    let s_prio = sched.slab.get(sender).priority;
    let r_prio = sched.slab.get(receiver).priority;
    if s_prio != r_prio {
        return FastpathOutcome::Reject(RejectReason::PriorityMismatch);
    }
    let length = sched.slab.get(sender).ipc_length;
    if length > FASTPATH_MAX_MSG_LEN {
        return FastpathOutcome::Reject(RejectReason::MessageTooLong);
    }

    pop_head(ep, sched);
    let (label, regs, badge) = {
        let s = sched.slab.get(sender);
        (s.ipc_label, s.msg_regs, s.ipc_badge)
    };
    let r = sched.slab.get_mut(receiver);
    r.ipc_label = label;
    r.ipc_length = length;
    r.ipc_badge = badge;
    let n = (length as usize).min(SCRATCH_MSG_LEN);
    r.msg_regs[..n].copy_from_slice(&regs[..n]);

    sched.make_runnable(sender);
    if ep.head.is_none() {
        ep.state = EpState::Idle;
    }
    FastpathOutcome::Took { peer: sender }
}

// Local copy of the queue-pop helper (the slowpath's lives in
// endpoint.rs and is non-pub). Keeps fastpath.rs decoupled and
// emphasises the inlined nature of the operation.
fn pop_head(ep: &mut Endpoint, sched: &mut Scheduler) -> Option<TcbId> {
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

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::endpoint::{receive_ipc, RecvOptions};
    use crate::tcb::Tcb;

    fn running(prio: u8) -> Tcb {
        let mut t = Tcb::default();
        t.priority = prio;
        t.state = ThreadStateType::Running;
        t
    }

    pub fn test_fastpath() {
        arch::log("Running fastpath tests...\n");
        send_fastpath_happy_path();
        send_fastpath_rejects_idle_ep();
        send_fastpath_rejects_long_msg();
        send_fastpath_rejects_priority_mismatch();
        recv_fastpath_happy_path();
        arch::log("Fastpath tests completed\n");
    }

    #[inline(never)]
    fn send_fastpath_happy_path() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let receiver = sched.admit(running(50));
        let sender = sched.admit(running(50));

        // Receiver blocks on the endpoint first.
        receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking());
        assert_eq!(ep.state, EpState::Recv);

        // Sender stamps a 2-word message.
        sched.slab.get_mut(sender).ipc_label = 0xABCD;
        sched.slab.get_mut(sender).ipc_length = 2;
        sched.slab.get_mut(sender).msg_regs[0] = 0x11;
        sched.slab.get_mut(sender).msg_regs[1] = 0x22;

        let r = try_fastpath_send(&mut ep, &mut sched, sender, 0xBADu64);
        assert_eq!(r, FastpathOutcome::Took { peer: receiver });
        assert_eq!(ep.state, EpState::Idle);

        let recv = sched.slab.get(receiver);
        assert_eq!(recv.ipc_label, 0xABCD);
        assert_eq!(recv.msg_regs[0], 0x11);
        assert_eq!(recv.msg_regs[1], 0x22);
        assert_eq!(recv.ipc_badge, 0xBAD);
        assert_eq!(recv.state, ThreadStateType::Running);
        arch::log("  ✓ send-fastpath transfers msg + badge inline\n");
    }

    #[inline(never)]
    fn send_fastpath_rejects_idle_ep() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let sender = sched.admit(running(50));
        // Endpoint has no receiver — fastpath rejects.
        let r = try_fastpath_send(&mut ep, &mut sched, sender, 0);
        assert_eq!(r, FastpathOutcome::Reject(RejectReason::EpStateMismatch));
        arch::log("  ✓ send-fastpath rejects empty endpoint\n");
    }

    #[inline(never)]
    fn send_fastpath_rejects_long_msg() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let receiver = sched.admit(running(50));
        let sender = sched.admit(running(50));
        receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking());
        sched.slab.get_mut(sender).ipc_length = FASTPATH_MAX_MSG_LEN + 1;
        let r = try_fastpath_send(&mut ep, &mut sched, sender, 0);
        assert_eq!(r, FastpathOutcome::Reject(RejectReason::MessageTooLong));
        arch::log("  ✓ send-fastpath rejects oversized message\n");
    }

    #[inline(never)]
    fn send_fastpath_rejects_priority_mismatch() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let receiver = sched.admit(running(50));
        let sender = sched.admit(running(60));
        receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking());
        let r = try_fastpath_send(&mut ep, &mut sched, sender, 0);
        assert_eq!(r, FastpathOutcome::Reject(RejectReason::PriorityMismatch));
        arch::log("  ✓ send-fastpath rejects priority mismatch\n");
    }

    #[inline(never)]
    fn recv_fastpath_happy_path() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let sender = sched.admit(running(50));
        let receiver = sched.admit(running(50));

        // Sender blocks first (Send state).
        sched.slab.get_mut(sender).ipc_label = 0x1234;
        sched.slab.get_mut(sender).ipc_length = 1;
        sched.slab.get_mut(sender).msg_regs[0] = 0x99;
        sched.slab.get_mut(sender).ipc_badge = 0xFE;
        crate::endpoint::send_ipc(
            &mut ep, &mut sched, sender,
            crate::endpoint::SendOptions::blocking(0xFE),
        );
        assert_eq!(ep.state, EpState::Send);

        let r = try_fastpath_recv(&mut ep, &mut sched, receiver);
        assert_eq!(r, FastpathOutcome::Took { peer: sender });
        let recv = sched.slab.get(receiver);
        assert_eq!(recv.ipc_label, 0x1234);
        assert_eq!(recv.msg_regs[0], 0x99);
        assert_eq!(recv.ipc_badge, 0xFE);
        arch::log("  ✓ recv-fastpath pulls queued sender's message\n");
    }
}
