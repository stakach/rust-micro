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
        Self {
            state: EpState::Idle,
            head: None,
            tail: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal queue helpers — push to tail, pop from head, remove
// arbitrary node. All operate on `tcb.ep_next` / `tcb.ep_prev`.
// ---------------------------------------------------------------------------

fn queue_push(ep: &mut Endpoint, sched: &mut Scheduler, t: TcbId) {
    // Priority-ordered insertion under MCS (mirrors upstream
    // `tcbEPAppend` in include/object/tcb.h). Walk back from the
    // tail while the inserted TCB outranks the cursor — so highest
    // priority ends up at head, equal priorities preserve FIFO.
    // SCHED0007 expects the receiver to service callers in priority
    // order regardless of arrival order.
    let new_prio = sched.slab.get(t).priority;
    let mut before = ep.tail;
    let mut after: Option<TcbId> = None;
    while let Some(b) = before {
        if new_prio > sched.slab.get(b).priority {
            after = Some(b);
            before = sched.slab.get(b).ep_prev;
        } else {
            break;
        }
    }
    {
        let tcb = sched.slab.get_mut(t);
        tcb.ep_prev = before;
        tcb.ep_next = after;
    }
    match before {
        Some(b) => sched.slab.get_mut(b).ep_next = Some(t),
        None => ep.head = Some(t),
    }
    match after {
        Some(a) => sched.slab.get_mut(a).ep_prev = Some(t),
        None => ep.tail = Some(t),
    }
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

fn queue_unlink_id(ep: &mut Endpoint, sched: &mut Scheduler, target: TcbId) -> bool {
    let mut prev = None;
    let mut cur = ep.head;
    let mut guard = 0usize;
    while let Some(id) = cur {
        guard += 1;
        if guard > crate::tcb::MAX_TCBS {
            break;
        }
        let next = sched.slab.try_get(id).and_then(|t| t.ep_next);
        if id != target {
            prev = cur;
            cur = next;
            continue;
        }

        match prev {
            Some(prev_id) => {
                if let Some(prev_tcb) = sched.slab.entries[prev_id.0 as usize].as_mut() {
                    prev_tcb.ep_next = next;
                } else {
                    ep.head = next;
                }
            }
            None => ep.head = next,
        }
        match next {
            Some(next_id) => {
                if let Some(next_tcb) = sched.slab.entries[next_id.0 as usize].as_mut() {
                    next_tcb.ep_prev = prev;
                } else {
                    ep.tail = prev;
                }
            }
            None => ep.tail = prev,
        }
        if let Some(tcb) = sched.slab.entries[target.0 as usize].as_mut() {
            tcb.ep_next = None;
            tcb.ep_prev = None;
        }
        return true;
    }
    false
}

fn queue_is_empty(ep: &Endpoint) -> bool {
    ep.head.is_none()
}

fn normalize_queue_state(ep: &mut Endpoint, sched: &mut Scheduler) {
    loop {
        let Some(head) = ep.head else {
            ep.tail = None;
            ep.state = EpState::Idle;
            return;
        };
        match sched.slab.try_get(head).map(|t| t.state) {
            Some(ThreadStateType::BlockedOnSend) => {
                ep.state = EpState::Send;
                ep.tail = queue_tail_from(head, sched);
                return;
            }
            Some(ThreadStateType::BlockedOnReceive) => {
                ep.state = EpState::Recv;
                ep.tail = queue_tail_from(head, sched);
                return;
            }
            _ => {
                let _ = queue_pop_head(ep, sched);
            }
        }
    }
}

fn queue_tail_from(head: TcbId, sched: &Scheduler) -> Option<TcbId> {
    let mut tail = head;
    let mut cur = Some(head);
    let mut guard = 0usize;
    while let Some(id) = cur {
        guard += 1;
        if guard > crate::tcb::MAX_TCBS {
            break;
        }
        tail = id;
        cur = sched.slab.try_get(id).and_then(|t| t.ep_next);
    }
    Some(tail)
}

fn waiter_kind(sched: &Scheduler, id: TcbId) -> Option<EpState> {
    match sched.slab.try_get(id).map(|t| t.state) {
        Some(ThreadStateType::BlockedOnSend) => Some(EpState::Send),
        Some(ThreadStateType::BlockedOnReceive) => Some(EpState::Recv),
        _ => None,
    }
}

fn opposite_waiter(kind: EpState) -> Option<EpState> {
    match kind {
        EpState::Send => Some(EpState::Recv),
        EpState::Recv => Some(EpState::Send),
        EpState::Idle => None,
    }
}

fn complete_queued_transfer(
    ep: &Endpoint,
    sched: &mut Scheduler,
    sender: TcbId,
    receiver: TcbId,
    sender_can_donate: bool,
) {
    let (badge, sender_can_grant, was_call) = {
        let s = sched.slab.get_mut(sender);
        let badge = s.ipc_badge;
        let sender_can_grant = core::mem::replace(&mut s.blocked_can_grant, false);
        let was_call = core::mem::replace(&mut s.blocked_is_call, false);
        (badge, sender_can_grant, was_call)
    };
    deliver_message(sched, sender, receiver, badge);
    if sender_can_grant {
        transfer_extra_caps(sched, ep, sender, receiver);
    } else {
        sched.slab.get_mut(sender).pending_extra_caps_count = 0;
    }
    if was_call {
        finish_call(sched, sender, receiver);
    } else {
        release_receive_offer(sched, receiver);
        sched.make_runnable(sender);
        if sender_can_donate {
            maybe_donate_on_send(sched, sender, receiver);
        }
    }
    sched.make_runnable(receiver);
}

fn repair_mixed_queue(
    ep: &mut Endpoint,
    sched: &mut Scheduler,
    focus_sender: Option<(TcbId, bool)>,
    focus: Option<TcbId>,
) -> Option<TcbId> {
    let mut focus_peer = None;
    loop {
        normalize_queue_state(ep, sched);
        let Some(head) = ep.head else {
            return focus_peer;
        };
        let Some(head_kind) = waiter_kind(sched, head) else {
            return focus_peer;
        };
        let Some(opposite) = opposite_waiter(head_kind) else {
            return focus_peer;
        };

        let mut cur = sched.slab.get(head).ep_next;
        let mut other = None;
        let mut guard = 0usize;
        while let Some(id) = cur {
            guard += 1;
            if guard > crate::tcb::MAX_TCBS {
                break;
            }
            let next = sched.slab.try_get(id).and_then(|t| t.ep_next);
            if waiter_kind(sched, id) == Some(opposite) {
                other = Some(id);
                break;
            }
            cur = next;
        }

        let Some(other) = other else {
            return focus_peer;
        };
        let (sender, receiver) = match head_kind {
            EpState::Recv => {
                queue_remove(ep, sched, other);
                let popped = queue_pop_head(ep, sched);
                debug_assert_eq!(popped, Some(head));
                (other, head)
            }
            EpState::Send => {
                queue_remove(ep, sched, other);
                let popped = queue_pop_head(ep, sched);
                debug_assert_eq!(popped, Some(head));
                (head, other)
            }
            EpState::Idle => unreachable!(),
        };
        let sender_can_donate = focus_sender
            .map(|(id, can_donate)| id == sender && can_donate)
            .unwrap_or(false);
        complete_queued_transfer(ep, sched, sender, receiver, sender_can_donate);
        if focus == Some(sender) {
            focus_peer = Some(receiver);
        } else if focus == Some(receiver) {
            focus_peer = Some(sender);
        }
    }
}

// ---------------------------------------------------------------------------
// Public IPC primitives.
// ---------------------------------------------------------------------------

/// Options for `send_ipc`. Mirrors the `bool blocking, bool do_call,
/// word_t badge` triple in seL4's `sendIPC`, plus a `can_grant`
/// gate sourced from the cap's rights — the receive side only
/// accepts cap-transfer when the sender's cap had grant rights.
#[derive(Copy, Clone, Debug)]
pub struct SendOptions {
    pub blocking: bool,
    pub do_call: bool,
    pub badge: Word,
    pub can_grant: bool,
    /// Mirrors upstream `sendIPC`'s `canDonate`. True for Call,
    /// NBSendRecv, NBSendWait (and reply); false for plain Send /
    /// NBSend. When true and a plain (non-Call) send pairs with a
    /// PASSIVE receiver (no SC), the sender's SC is donated so the
    /// receiver can run — the stack-spawning handoff in IPC0022.
    /// Plain Send keeps it false so IPC0017 (Send to a no-SC server)
    /// correctly blocks the sender instead of donating.
    pub can_donate: bool,
}

impl SendOptions {
    pub const fn blocking(badge: Word) -> Self {
        Self {
            blocking: true,
            do_call: false,
            badge,
            can_grant: true,
            can_donate: false,
        }
    }
}

/// Options for `receive_ipc`.
#[derive(Copy, Clone, Debug, Default)]
pub struct RecvOptions {
    pub blocking: bool,
}

impl RecvOptions {
    pub const fn blocking() -> Self {
        Self { blocking: true }
    }
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

/// Common tail when a Call pairs with its receiver: park the caller
/// `BlockedOnReply`, point the receiver's reply at it, bind the reply
/// object, and — if the receiver is a PASSIVE server (no SC of its
/// own) — donate the caller's scheduling context so the server can
/// run (upstream `reply_push` -> `schedContext_donate`). The exact
/// reply chain owns SC return authority. Non-passive receivers stay
/// on their own SC; carrying the
/// caller's SC on an already-schedulable receiver leaks helper budget
/// across unrelated receives in sel4test's helper-completion path.
fn finish_call(sched: &mut Scheduler, sender: TcbId, receiver: TcbId) {
    // Bind the reply object (if the receiver registered one via
    // Recv(ep, reply=cptr)) so Send-on-Cap::Reply can find the caller.
    let reply_idx = sched.slab.get(receiver).pending_reply;
    unsafe {
        let s = crate::kernel::KERNEL.get();
        crate::reply::bind_call(s, sender, receiver, reply_idx);
    }
}

fn release_receive_offer(sched: &mut Scheduler, receiver: TcbId) {
    if !sched.slab.try_get(receiver).is_some_and(|tcb| tcb.pending_reply.is_some()) {
        return;
    }
    // A real offer belongs to the kernel's object registry. Queue-only operations
    // with no offer need no object access and can use an independent scheduler.
    unsafe {
        let state: *mut crate::kernel::KernelState = crate::kernel::KERNEL.get();
        assert!(core::ptr::eq(sched as *const Scheduler,
            core::ptr::addr_of!((*state).scheduler)));
        crate::reply::release_offer(&mut *state, receiver);
    }
}

pub fn send_ipc(
    ep: &mut Endpoint,
    sched: &mut Scheduler,
    sender: TcbId,
    opts: SendOptions,
) -> IpcOutcome {
    if queue_unlink_id(ep, sched, sender) {
        normalize_queue_state(ep, sched);
    } else if ep.head.is_none() || ep.tail.is_none() {
        normalize_queue_state(ep, sched);
    }
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
            // pair-up actually happens — record it on the TCB so
            // the receive-pop path can act on it.
            sched.block(sender, ThreadStateType::BlockedOnSend);
            sched.slab.get_mut(sender).blocked_is_call = opts.do_call;
            sched.slab.get_mut(sender).blocked_can_grant = opts.can_grant;
            // Stamp the badge for the deferred pair-up: receive_ipc
            // reads `sender.ipc_badge` when it pops us. The syscall
            // send path pre-stages it, but kernel-synthesized sends
            // (fault delivery) only pass it via `opts` — without
            // this, a queued fault to a BADGED fault EP arrives with
            // a stale badge (PAGEFAULT badged rounds, faulter prio >
            // handler so the fault queues before the handler's
            // recv).
            sched.slab.get_mut(sender).ipc_badge = opts.badge;
            queue_push(ep, sched, sender);
            ep.state = EpState::Send;
            if let Some(receiver) =
                repair_mixed_queue(ep, sched, Some((sender, opts.can_donate)), Some(sender))
            {
                IpcOutcome::Transferred { peer: receiver }
            } else {
                IpcOutcome::Blocked
            }
        }
        // A receiver is queued — wake the head and transfer.
        EpState::Recv => {
            let receiver =
                queue_pop_head(ep, sched).expect("Recv state must have at least one waiter");
            deliver_message(sched, sender, receiver, opts.badge);
            // Cap transfer requires the sender's cap to carry grant
            // rights (or grant-reply for Reply paths). Without this
            // gate, sel4test IPCRIGHTS0003 sees a cap arrive at the
            // receiver even though the sending EP cap was minted
            // without grant.
            if opts.can_grant {
                transfer_extra_caps(sched, ep, sender, receiver);
            } else {
                // Drop staged caps so the next IPC doesn't accidentally
                // smuggle them.
                sched.slab.get_mut(sender).pending_extra_caps_count = 0;
            }
            if opts.do_call {
                finish_call(sched, sender, receiver);
            } else {
                release_receive_offer(sched, receiver);
                // Plain (non-Call) send to a PASSIVE receiver donates
                // the sender's SC so it can run (upstream sendIPC's
                // `canDonate && dest->tcbSchedContext == NULL` arm).
                // NBSendRecv/NBSendWait set can_donate; this is the
                // stack-spawning handoff (IPC0022) where the spawner
                // hands its (donated) SC to the worker it just woke.
                if opts.can_donate { maybe_donate_on_send(sched, sender, receiver); }
            }
            sched.make_runnable(receiver);
            if queue_is_empty(ep) {
                ep.state = EpState::Idle;
            } else {
                repair_mixed_queue(ep, sched, None, None);
            }
            IpcOutcome::Transferred { peer: receiver }
        }
    }
}

/// Upstream sendIPC's passive-receiver donation for a plain (non-Call)
/// send: if `receiver` has no SC of its own but `sender` does, MOVE
/// the sender's SC to the receiver (the sender becomes passive). Used
/// only when the send carries `can_donate` (NBSendRecv/NBSendWait).
fn maybe_donate_on_send(sched: &mut Scheduler, sender: TcbId, receiver: TcbId) {
    let sender_sc = sched.slab.get(sender).sc;
    let receiver_passive = sched.slab.get(receiver).sc.is_none();
    if let (Some(sc), true) = (sender_sc, receiver_passive) {
        unsafe {
            let s = crate::kernel::KERNEL.get();
            crate::sched_context::sc_donate(s, sc as usize, receiver);
        }
    }
}

pub fn receive_ipc(
    ep: &mut Endpoint,
    sched: &mut Scheduler,
    receiver: TcbId,
    opts: RecvOptions,
) -> IpcOutcome {
    if let Some(index) = sched.slab.get(receiver).pending_reply {
        unsafe { crate::reply::offer(crate::kernel::KERNEL.get(), receiver, index); }
    }
    if queue_unlink_id(ep, sched, receiver) {
        normalize_queue_state(ep, sched);
    } else if ep.head.is_none() || ep.tail.is_none() {
        normalize_queue_state(ep, sched);
    }
    match ep.state {
        // No senders queued — block (or skip if NB).
        EpState::Idle | EpState::Recv => {
            if !opts.blocking {
                release_receive_offer(sched, receiver);
                return IpcOutcome::Skipped;
            }
            sched.block(receiver, ThreadStateType::BlockedOnReceive);
            queue_push(ep, sched, receiver);
            ep.state = EpState::Recv;
            if let Some(sender) = repair_mixed_queue(ep, sched, None, Some(receiver)) {
                IpcOutcome::Transferred { peer: sender }
            } else {
                IpcOutcome::Blocked
            }
        }
        // Sender queued — pair them off.
        EpState::Send => {
            let sender =
                queue_pop_head(ep, sched).expect("Send state must have at least one waiter");
            // The sender's `ipc_badge` field was set on the original
            // send call — re-use it instead of consulting the cap.
            let badge = sched.slab.get(sender).ipc_badge;
            // Capture and clear the queued can_grant flag so re-queue
            // doesn't smuggle stale state.
            let sender_can_grant =
                core::mem::replace(&mut sched.slab.get_mut(sender).blocked_can_grant, false);
            deliver_message(sched, sender, receiver, badge);
            if sender_can_grant {
                transfer_extra_caps(sched, ep, sender, receiver);
            } else {
                sched.slab.get_mut(sender).pending_extra_caps_count = 0;
            }
            // Phase 43 — if the sender was blocked on a Call (not a
            // plain Send), it must wait for an actual Reply: park it
            // in BlockedOnReply, donate its SC, and bind the
            // receiver's reply slot to it. Without this the sender
            // resumes from `seL4_Call` reading stale `user_context`
            // and the test sees garbage in MR(0).
            let was_call =
                core::mem::replace(&mut sched.slab.get_mut(sender).blocked_is_call, false);
            if was_call {
                finish_call(sched, sender, receiver);
            } else {
                release_receive_offer(sched, receiver);
                sched.make_runnable(sender);
            }
            if queue_is_empty(ep) {
                ep.state = EpState::Idle;
            } else {
                repair_mixed_queue(ep, sched, None, None);
            }
            IpcOutcome::Transferred { peer: sender }
        }
    }
}

/// Walk all in-kernel endpoints, find the one currently holding
/// `thread` in its sender or receiver queue, and dequeue. Used by
/// `notification::signal` for the bound-TCB short-circuit, where
/// we need to lift a `BlockedOnReceive` TCB out of an unknown
/// endpoint queue and immediately re-wake it via `make_runnable`.
///
/// Leaves the thread in `Inactive` state so the caller's
/// `make_runnable` sees `was_runnable == false` and actually
/// enqueues onto the ready queue. (Setting it to `Restart` here
/// would short-circuit `make_runnable`'s enqueue, since `Restart`
/// is "runnable" but the thread is not yet on the ready queue.)
pub fn cancel_ipc_anywhere(sched: &mut Scheduler, thread: TcbId) {
    use crate::kernel::{KernelState, KERNEL};
    let s_ptr: *mut KernelState = unsafe { KERNEL.get() };
    release_receive_offer(sched, thread);
    for i in 0..crate::kernel::MAX_ENDPOINTS {
        let ep = unsafe { &mut (*s_ptr).endpoints[i] };
        loop {
            if !queue_unlink_id(ep, sched, thread) {
                break;
            }
            if queue_is_empty(ep) {
                ep.state = EpState::Idle;
            } else {
                repair_mixed_queue(ep, sched, None, None);
            }
            if let Some(tcb) = sched.slab.entries[thread.0 as usize].as_mut() {
                tcb.state = ThreadStateType::Inactive;
            }
        }
    }
    // Phase 43 — also clear notification queues. cnode_delete on a
    // TCB cap calls this to flush IPC references before freeing the
    // slab entry; without the notification sweep, a sender blocked on
    // a notification leaves a stale id in `ntfn.head/tail` and any
    // later signal_or_wait dereferences a freed slot.
    crate::notification::cancel_wait_anywhere(sched, thread);
}

/// SCHED0008 — reposition `thread` within whatever endpoint or
/// notification wait-queue currently holds it, using the new
/// priority. seL4's `tcbEPAppend` is priority-ordered (head =
/// highest), so a thread whose priority changes while parked must
/// be moved to a new slot to preserve the invariant. SetPriority
/// calls this AFTER it's written the new `tcb.priority`.
pub fn reposition_in_wait_queue(sched: &mut Scheduler, thread: TcbId) {
    use crate::kernel::{KernelState, KERNEL};
    let s_ptr: *mut KernelState = unsafe { KERNEL.get() };
    for i in 0..crate::kernel::MAX_ENDPOINTS {
        let ep = unsafe { &mut (*s_ptr).endpoints[i] };
        if !ep_queue_contains(ep, sched, thread) {
            continue;
        }
        queue_remove(ep, sched, thread);
        queue_push(ep, sched, thread);
        repair_mixed_queue(ep, sched, None, None);
        return;
    }
    crate::notification::reposition_in_wait_queue(sched, thread);
}

fn ep_queue_contains(ep: &Endpoint, sched: &Scheduler, thread: TcbId) -> bool {
    let mut cur = ep.head;
    while let Some(c) = cur {
        if c == thread {
            return true;
        }
        cur = sched.slab.try_get(c).and_then(|t| t.ep_next);
    }
    false
}

/// Read-only proof that an exact receiver belongs to a consistent endpoint receive queue.
/// Inspect the whole bounded chain: a corrupt neighbor or stale tail cannot authenticate a
/// worker that happens to appear earlier in the queue. This does not reserve the endpoint.
pub(crate) fn receive_queue_contains_exact(
    ep: &Endpoint,
    sched: &Scheduler,
    receiver: TcbId,
) -> bool {
    if ep.state != EpState::Recv || ep.head.is_none() || ep.tail.is_none() {
        return false;
    }
    let mut current = ep.head;
    let mut previous = None;
    let mut found = false;
    let mut visited = 0;
    while let Some(id) = current {
        if visited == crate::tcb::MAX_TCBS {
            return false;
        }
        visited += 1;
        let Some(tcb) = sched.slab.try_get(id) else {
            return false;
        };
        if tcb.state != ThreadStateType::BlockedOnReceive
            || tcb.enqueued
            || tcb.ep_prev != previous
        {
            return false;
        }
        found |= id == receiver;
        previous = Some(id);
        current = tcb.ep_next;
    }
    found && ep.tail == previous
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
    release_receive_offer(sched, thread);
    queue_remove(ep, sched, thread);
    {
        let tcb = sched.slab.get_mut(thread);
        tcb.state = ThreadStateType::Restart;
    }
    if queue_is_empty(ep) {
        ep.state = EpState::Idle;
    } else {
        repair_mixed_queue(ep, sched, None, None);
    }
}

// ---------------------------------------------------------------------------
// Message transfer. seL4's `doIPCTransfer` does considerably more
// (cap transfer, fault payload), but for the bytewise message-
// register copy this is the whole story.
// ---------------------------------------------------------------------------

/// Copy a fully-staged message from `sender` to `receiver`: the
/// first 4 words ride in registers (already in `sender.msg_regs[0..4]`),
/// words 4..min(length, SCRATCH) come from `sender.msg_regs`, and the
/// tail (SCRATCH..length) is copied buffer-to-buffer. Also fans the
/// payload into `receiver`'s saved user_context per the IPC return
/// ABI. `sender.msg_regs[4..]` must already be loaded from its IPC
/// buffer by the caller (handle_send / the reply paths do this).
///
/// Shared by endpoint IPC and the Reply-cap / ReplyRecv paths so
/// long messages (>SCRATCH words) round-trip in BOTH directions —
/// IPC0002 / IPC0003 reply with up to seL4_MsgMaxLength words.
pub(crate) fn deliver_message(sched: &mut Scheduler, sender: TcbId, receiver: TcbId, badge: Word) {
    // We need both TCBs mutable simultaneously. Borrow each entry
    // separately by index — the Slab guarantees they're distinct
    // memory because TcbIds are unique.
    let (label, length, regs, snd_buf_paddr, kernel_fault) = {
        let s = sched.slab.get(sender);
        (s.ipc_label, s.ipc_length, s.msg_regs, s.ipc_buffer_send_paddr(), s.pending_fault != 0)
    };
    let r = sched.slab.get_mut(receiver);
    let recv_buf_paddr = r.ipc_buffer_receive_paddr();
    // Fault payloads are kernel-staged, whereas ordinary words beyond the registers require
    // sender frame authority. The receiver must independently authorize every buffer write.
    let sender_words = if kernel_fault { regs.len() } else if snd_buf_paddr != 0 {
        crate::types::seL4_MsgMaxLength
    } else { 4 };
    let receiver_words = if recv_buf_paddr != 0 { crate::types::seL4_MsgMaxLength } else { 4 };
    let length = (length as usize).min(sender_words).min(receiver_words) as u32;
    r.ipc_label = label;
    r.ipc_length = length;
    r.ipc_badge = badge;
    r.composite_reply_handoff = None;
    let n = (length as usize).min(r.msg_regs.len());
    r.msg_regs[..n].copy_from_slice(&regs[..n]);

    // Phase 34c — fan words 4..length out to the receiver's IPC
    // buffer page so userspace can read them. Words 0..3 ride in
    // registers (rdx/r10/r8/r9 below) and don't need the buffer.
    if length > 4 && recv_buf_paddr != 0 {
        let buf = (crate::arch::phys_to_virt(recv_buf_paddr) as *mut u64).wrapping_add(1); // skip tag word
        let staged_max = (length as usize).min(regs.len());
        for i in 4..staged_max {
            unsafe {
                core::ptr::write_volatile(buf.add(i), regs[i]);
            }
        }
        // Long-message tail: words SCRATCH_MSG_LEN..length live in
        // the sender's IPC buffer page and bypass the on-TCB
        // staging entirely (which is bounded at SCRATCH_MSG_LEN to
        // keep TCBs small). Copy buffer → buffer directly via the
        // kernel's linear map. Both pages are present because they
        // were allocated as user Frames whose phys range is in our
        // mapped low-mem region.
        if length as usize > regs.len() && snd_buf_paddr != 0 {
            let snd_buf = (crate::arch::phys_to_virt(snd_buf_paddr) as *const u64).wrapping_add(1);
            for i in regs.len()..(length as usize).min(crate::types::seL4_MsgMaxLength) {
                let w = unsafe { core::ptr::read_volatile(snd_buf.add(i)) };
                unsafe {
                    core::ptr::write_volatile(buf.add(i), w);
                }
            }
        }
    }

    // Phase 29h — fan the IPC payload into the receiver's
    // user-visible registers immediately. The dispatcher's existing
    // tail only fans-in when the in-flight syscall is the receiver's
    // SysRecv, which doesn't cover the "receiver-blocked-first,
    // sender-arrives-later" path. We do it here so the receiver's
    // saved user_context has the right values whenever it next runs.
    let mi = (label << 12) | (length as Word & 0x7F);
    // Upstream signals success/error through MessageInfo and faults through
    // the configured fault endpoint, not a separate integer result.
    let msg_regs = r.msg_regs;
    crate::arch::set_ipc_return(&mut r.user_context, badge, mi, &msg_regs[..4]);
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
    ep: &Endpoint,
    sender: TcbId,
    receiver: TcbId,
) {
    let count = sched.slab.get(sender).pending_extra_caps_count as usize;
    if count == 0 {
        return;
    }
    let recv_buf_paddr = sched.slab.get(receiver).ipc_buffer_receive_paddr();
    if recv_buf_paddr == 0 {
        // seL4 transferCaps: without a receive buffer no cap or badge is delivered.
        sched.slab.get_mut(sender).pending_extra_caps_count = 0;
        return;
    }
    let destination = receive_slot(sched, receiver, recv_buf_paddr);
    unsafe {
        let s = crate::kernel::KERNEL.get();
        // An endpoint in the kernel pool is named by its pool index.
        let ep_index = {
            let base = s.endpoints.as_ptr() as usize;
            let at = ep as *const Endpoint as usize;
            let size = core::mem::size_of::<Endpoint>();
            (at >= base && at < base + size * s.endpoints.len()).then(|| (at - base) / size)
        };
        let staged = s.scheduler.slab.get(sender).pending_extra_caps;
        let sources = s.scheduler.slab.get(sender).pending_extra_cap_sources;
        let buffer = crate::arch::phys_to_virt(recv_buf_paddr) as *mut u64;
        let mut processed = 0u8;
        let mut unwrapped = 0u8;
        for i in 0..count {
            // seL4 transferCaps looks each cap up when the message is transferred and stops at
            // the first one it cannot deliver. A blocked sender's source slot may have changed
            // since staging: transfer only while that exact CTE still holds the staged cap.
            let Some(source) = sources[i] else { break };
            let Some(source_cte) = s.cte(source).copied() else { break };
            if source_cte.cap() != staged[i] {
                break;
            }
            // A cap to the endpoint the message travels on is not transferred: the receiver gets
            // its badge in caps_or_badges[i] and capsUnwrapped bit i.
            if let crate::cap::Cap::Endpoint { ptr, badge, .. } = staged[i] {
                if ep_index == Some(crate::kernel::KernelState::endpoint_index(ptr)) {
                    core::ptr::write_volatile(
                        buffer.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET + i), badge.0);
                    unwrapped |= 1 << i;
                    processed = i as u8 + 1;
                    continue;
                }
            }
            let Some((cnode, base_slot)) = destination else { break };
            let Ok(cap) = crate::invocation::derive_cap(&source_cte) else { break };
            if cap.is_null() {
                break;
            }
            // Dispatch across all three CNode pools — the receiver's
            // cspace root may be an XL page (test processes), not a
            // big-pool entry.
            let Some(slots) = s.cnode_slots_at_mut(cnode) else { break };
            // Consecutive receive slots, one per transferred cap; an occupied slot ends the
            // transfer as seL4's getReceiveSlots refusal does.
            let Some(slot) = slots.get_mut(base_slot + i) else { break };
            if !slot.cap().is_null() {
                break;
            }
            // cteInsert: the receiver's copy is a derived child of the sender's CTE, so a
            // revoke of the source (or of any ancestor) reaches it.
            slot.set_cap(&cap);
            slot.set_parent(Some(source));
            slot.set_child_count(0);
            slot.set_revoke_epoch(0);
            crate::invocation::child_count_inc(source, 1);
            processed = i as u8 + 1;
        }
        // Surface extraCaps (caps processed) and capsUnwrapped in the receiver's message info.
        let r = s.scheduler.slab.get_mut(receiver);
        r.received_extra_caps = processed;
        r.received_caps_unwrapped = unwrapped;
        // deliver_message already wrote the receiver's return msginfo
        // into rsi (label|length) BEFORE we ran, so fold the counts in
        // now — covers the receiver-blocked-first path, where the
        // dispatcher's recv-return tail doesn't re-pack rsi.
        let info = (crate::arch::ipc_message_info(&r.user_context) & !(0x1f << 7))
            | (((processed as u64) & 0x3) << 7)
            | (((unwrapped as u64) & 0x7) << 9);
        let badge = crate::arch::ipc_badge(&r.user_context);
        let msg_regs = r.msg_regs;
        crate::arch::set_ipc_return(&mut r.user_context, badge, info, &msg_regs[..4]);
    }
    sched.slab.get_mut(sender).pending_extra_caps_count = 0;
}

/// seL4 getReceiveSlots: the CNode and first slot the receiver's IPC buffer names, resolved
/// through its receive path, or None when it names none.
fn receive_slot(
    sched: &crate::scheduler::Scheduler,
    receiver: TcbId,
    recv_buf_paddr: u64,
) -> Option<(usize, usize)> {
    let (recv_cnode_cptr, recv_index, recv_depth) = unsafe {
        let buf = crate::arch::phys_to_virt(recv_buf_paddr) as *const u64;
        (
            core::ptr::read_volatile(buf.add(crate::ipc_buffer::RECEIVE_CNODE_OFFSET)),
            core::ptr::read_volatile(buf.add(crate::ipc_buffer::RECEIVE_INDEX_OFFSET)),
            core::ptr::read_volatile(buf.add(crate::ipc_buffer::RECEIVE_DEPTH_OFFSET)) as u32,
        )
    };
    let recv_cspace = sched.slab.get(receiver).cspace_root();
    let s = unsafe { crate::kernel::KERNEL.get() };
    let target_cnode_cap = if recv_cnode_cptr == 0 {
        recv_cspace
    } else {
        crate::cspace::lookup_cap(s, &recv_cspace, recv_cnode_cptr).ok()?
    };
    // Resolve the actual receive slot through the receive path (CNode cap + index at
    // `recv_depth`), mirroring lookupTargetSlot: the index is resolved, never indexed raw.
    match crate::cspace::resolve_address_bits(s, &target_cnode_cap, recv_index, recv_depth) {
        Ok(res) if res.bits_remaining == 0 => Some((
            crate::kernel::KernelState::cnode_index(res.slot_ptr),
            res.slot_index,
        )),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::cap::Cap;
    use crate::tcb::{Tcb, ThreadStateType};

    fn runnable(prio: u8) -> Tcb {
        let mut t = Tcb::default();
        t.priority = prio;
        t.state = ThreadStateType::Running;
        // MCS is_schedulable needs an SC; placeholder index (never
        // dereferenced) so these IPC specs' threads stay enqueued.
        t.sc = Some(0);
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
        send_repairs_current_sender_stale_queue_link();
        send_pairs_receiver_head_when_state_is_stale_send();
        long_message_via_ipc_buffer();
        extra_cap_transfer_via_ipc();
        revoking_the_source_revokes_transferred_copies();
        a_stale_staged_cap_is_not_transferred();
        a_cap_to_the_sending_endpoint_is_unwrapped_to_its_badge();
        an_untyped_with_children_is_not_derived();
        transfer_into_a_dynamic_cnode_is_revoked_with_its_source();

        arch::log("Endpoint IPC tests completed\n");
    }

    /// A sender/receiver pair whose receiver names slot `RECEIVE_SLOT` of CNode 0 as its receive
    /// slot, and a Frame source CTE the sender can transfer. Frames keep finalization benign: a
    /// deleted derived Frame names no kernel object.
    struct TransferFixture {
        owners: crate::asid::spec::RootOwners,
        ep: Endpoint,
        sender: TcbId,
        receiver: TcbId,
        source: crate::cte::MdbId,
        /// The CNode the receiver's CSpace (and so its receive slots) lives in.
        receive_cnode: usize,
    }

    const RECEIVE_SLOT: usize = 5;

    impl TransferFixture {
        unsafe fn new() -> Self {
            Self::new_receiving_in(0, 5)
        }

        /// A receiver whose CSpace root is CNode `receive_cnode` of `radix` (any pool).
        unsafe fn new_receiving_in(receive_cnode: usize, radix: u8) -> Self {
            #[repr(C, align(4096))]
            struct IpcPage([u64; 512]);
            static mut SENDER_BUF: IpcPage = IpcPage([0; 512]);
            static mut RECEIVER_BUF: IpcPage = IpcPage([0; 512]);
            static mut TRANSFERRED: IpcPage = IpcPage([0; 512]);

            let mut owners = crate::asid::spec::RootOwners::new();
            let s = crate::kernel::KERNEL.get();
            s.scheduler.reset_queues();
            s.scheduler.set_current(None);
            let sender = s.scheduler.admit(runnable(50));
            let receiver = s.scheduler.admit(runnable(50));
            bind_ipc_buffer(s, &mut owners, sender, (&raw mut SENDER_BUF) as u64,
                crate::cap::FrameRights::ReadOnly);
            bind_ipc_buffer(s, &mut owners, receiver, (&raw mut RECEIVER_BUF) as u64,
                crate::cap::FrameRights::ReadWrite);
            let cspace = Cap::CNode {
                ptr: crate::kernel::KernelState::cnode_ptr(receive_cnode),
                radix,
                guard_size: 64 - radix,
                guard: 0,
            };
            let cspace_source = owners.cap_source_in(s, cspace);
            crate::invocation::derive_tcb_cap(s, receiver, crate::cte::TcbSlot::CSpace,
                Some(cspace_source), 0).unwrap();
            let source = owners.frame_source(
                crate::arch::virt_to_phys((&raw mut TRANSFERRED) as u64),
                crate::cap::FrameSize::Small,
                crate::cap::FrameRights::ReadWrite,
            );
            let fixture = Self { owners, ep: Endpoint::new(), sender, receiver, source, receive_cnode };
            for slot in [RECEIVE_SLOT, RECEIVE_SLOT + 1] {
                assert!(fixture.received(slot).cap().is_null(), "receive slot {slot} starts empty");
            }
            fixture.receive_into(RECEIVE_SLOT);
            fixture
        }

        /// The receiver's IPC buffer names `slot` of its own CSpace (receiveCNode = 0).
        unsafe fn receive_into(&self, slot: usize) {
            let s = crate::kernel::KERNEL.get();
            let buffer = crate::arch::phys_to_virt(
                s.scheduler.slab.get(self.receiver).ipc_buffer_send_paddr()) as *mut u64;
            core::ptr::write_volatile(buffer.add(crate::ipc_buffer::RECEIVE_CNODE_OFFSET), 0);
            core::ptr::write_volatile(buffer.add(crate::ipc_buffer::RECEIVE_INDEX_OFFSET), slot as u64);
            core::ptr::write_volatile(buffer.add(crate::ipc_buffer::RECEIVE_DEPTH_OFFSET), 64);
        }

        unsafe fn received(&self, slot: usize) -> &'static mut crate::cte::Cte {
            crate::kernel::KERNEL.get().cnode_slot_mut(self.receive_cnode, slot).unwrap()
        }

        unsafe fn receive_buffer(&self) -> *mut u64 {
            let s = crate::kernel::KERNEL.get();
            crate::arch::phys_to_virt(s.scheduler.slab.get(self.receiver).ipc_buffer_send_paddr())
                as *mut u64
        }

        /// Stage the source cap as the sender's syscall path does: by value and source CTE.
        unsafe fn stage(&self) {
            self.stage_from(self.source);
        }

        unsafe fn stage_from(&self, source: crate::cte::MdbId) {
            let s = crate::kernel::KERNEL.get();
            let cap = s.cte(source).unwrap().cap();
            let sender = s.scheduler.slab.get_mut(self.sender);
            sender.pending_extra_caps[0] = cap;
            sender.pending_extra_cap_sources[0] = Some(source);
            sender.pending_extra_caps_count = 1;
        }

        unsafe fn transfer(&mut self) -> u8 {
            let ep: *mut Endpoint = &mut self.ep;
            self.transfer_through(ep)
        }

        /// Rendezvous on `ep`, which may be a kernel-pool endpoint.
        unsafe fn transfer_through(&mut self, ep: *mut Endpoint) -> u8 {
            let s = crate::kernel::KERNEL.get();
            receive_ipc(&mut *ep, &mut s.scheduler, self.receiver, RecvOptions::blocking());
            send_ipc(&mut *ep, &mut s.scheduler, self.sender, SendOptions::blocking(0));
            assert_eq!(s.scheduler.slab.get(self.sender).pending_extra_caps_count, 0,
                "transfer drains the staged caps");
            s.scheduler.slab.get(self.receiver).received_extra_caps
        }

        unsafe fn retire(self) {
            let s = crate::kernel::KERNEL.get();
            for slot in [RECEIVE_SLOT, RECEIVE_SLOT + 1] {
                crate::invocation::delete_cap_slot(
                    s, crate::cte::MdbId::pack(self.receive_cnode as u32, slot as u32)).unwrap();
            }
            assert_eq!(s.cte(self.source).unwrap().child_count(), 0,
                "deleting every received copy releases its derivation edge");
            crate::invocation::retire_tcb(s, self.sender);
            crate::invocation::retire_tcb(s, self.receiver);
            s.scheduler.reset_queues();
            s.scheduler.set_current(None);
            drop(self.owners);
        }
    }

    /// seL4 transferCaps: the received cap is a derived child of the sender's CTE.
    #[inline(never)]
    fn extra_cap_transfer_via_ipc() {
        unsafe {
            let mut fixture = TransferFixture::new();
            let s = crate::kernel::KERNEL.get();
            let children = s.cte(fixture.source).unwrap().child_count();
            fixture.stage();
            assert_eq!(fixture.transfer(), 1);
            let landed = fixture.received(RECEIVE_SLOT);
            assert!(matches!(landed.cap(), Cap::Frame { mapped: None, .. }),
                "a transferred Frame is an unmapped derived copy");
            assert_eq!(landed.parent(), Some(fixture.source));
            assert_eq!(s.cte(fixture.source).unwrap().child_count(), children + 1);
            fixture.retire();
        }
        arch::log("  ✓ extra cap transfers as a derived child of the sender's CTE\n");
    }

    /// Revoking the sender's source reaches every receiver's copy (#286).
    #[inline(never)]
    fn revoking_the_source_revokes_transferred_copies() {
        unsafe {
            let mut fixture = TransferFixture::new();
            let s = crate::kernel::KERNEL.get();
            fixture.stage();
            assert_eq!(fixture.transfer(), 1);
            fixture.receive_into(RECEIVE_SLOT + 1);
            fixture.stage();
            assert_eq!(fixture.transfer(), 1);
            assert_eq!(s.cte(fixture.source).unwrap().child_count(), 2);
            let cnode = Cap::CNode {
                ptr: crate::kernel::KernelState::cnode_ptr(fixture.source.cnode_idx() as usize),
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            let revoke = crate::syscall_handler::SyscallArgs {
                a1: (crate::syscalls::InvocationLabel::CNodeRevoke as u64) << 12,
                a2: fixture.source.slot() as u64,
                ..Default::default()
            };
            crate::invocation::decode_invocation(cnode, &revoke, fixture.sender).expect("revoke");
            for slot in [RECEIVE_SLOT, RECEIVE_SLOT + 1] {
                assert!(fixture.received(slot).cap().is_null(), "received copy in slot {slot} revoked");
            }
            assert!(matches!(s.cte(fixture.source).unwrap().cap(), Cap::Frame { .. }),
                "revoke keeps the source itself");
            assert_eq!(s.cte(fixture.source).unwrap().child_count(), 0);
            fixture.retire();
        }
        arch::log("  ✓ revoking a source revokes the caps it sent over IPC\n");
    }

    /// A blocked sender's staged cap is not transferred once its source CTE no longer holds it:
    /// the copy would otherwise escape a revoke that ran while the sender waited.
    #[inline(never)]
    fn a_stale_staged_cap_is_not_transferred() {
        unsafe {
            let mut fixture = TransferFixture::new();
            let s = crate::kernel::KERNEL.get();
            fixture.stage();
            let staged = s.cte(fixture.source).unwrap().cap();
            s.cte_mut(fixture.source).unwrap().set_cap(&Cap::Null);
            assert_eq!(fixture.transfer(), 0);
            assert!(fixture.received(RECEIVE_SLOT).cap().is_null());
            assert_eq!(s.cte(fixture.source).unwrap().child_count(), 0);
            s.cte_mut(fixture.source).unwrap().set_cap(&staged);
            fixture.retire();
        }
        arch::log("  ✓ a staged cap whose source changed is not transferred\n");
    }

    /// seL4 transferCaps: a cap to the endpoint the message travels on is not transferred; the
    /// receiver gets its badge and capsUnwrapped. A cap to another endpoint transfers.
    #[inline(never)]
    fn a_cap_to_the_sending_endpoint_is_unwrapped_to_its_badge() {
        use crate::cap::{Badge, EndpointRights};
        unsafe {
            let mut fixture = TransferFixture::new();
            let s = crate::kernel::KERNEL.get();
            let via = s.alloc_endpoint().unwrap();
            let other = s.alloc_endpoint().unwrap();
            let rights = EndpointRights {
                can_send: true, can_receive: true, can_grant: true, can_grant_reply: true,
            };
            let endpoint_cap = |index, badge| Cap::Endpoint {
                ptr: crate::kernel::KernelState::endpoint_ptr(index), badge: Badge(badge), rights,
            };
            let same = fixture.owners.cap_source_in(s, endpoint_cap(via, 0x55));
            fixture.stage_from(same);
            let ep: *mut Endpoint = &mut s.endpoints[via];
            assert_eq!(fixture.transfer_through(ep), 1, "an unwrapped cap counts in extraCaps");
            assert_eq!(s.scheduler.slab.get(fixture.receiver).received_caps_unwrapped, 1);
            assert_eq!(core::ptr::read_volatile(
                fixture.receive_buffer().add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET)), 0x55);
            assert!(fixture.received(RECEIVE_SLOT).cap().is_null(), "no cap is transferred");
            assert_eq!(s.cte(same).unwrap().child_count(), 0);
            let info = crate::arch::ipc_message_info(
                &s.scheduler.slab.get(fixture.receiver).user_context);
            assert_eq!(((info >> 7) & 0x3, (info >> 9) & 0x7), (1, 1));

            let different = fixture.owners.cap_source_in(s, endpoint_cap(other, 0x66));
            fixture.stage_from(different);
            assert_eq!(fixture.transfer_through(ep), 1);
            assert_eq!(s.scheduler.slab.get(fixture.receiver).received_caps_unwrapped, 0);
            assert!(matches!(fixture.received(RECEIVE_SLOT).cap(), Cap::Endpoint { .. }));
            assert_eq!(fixture.received(RECEIVE_SLOT).parent(), Some(different));
            fixture.retire();
        }
        arch::log("  \u{2713} a cap to the sending endpoint is unwrapped to its badge\n");
    }

    /// seL4 deriveCap: an Untyped with children cannot be derived (ensureNoChildren), so it is
    /// neither transferred nor copied.
    #[inline(never)]
    fn an_untyped_with_children_is_not_derived() {
        unsafe {
            let mut fixture = TransferFixture::new();
            let s = crate::kernel::KERNEL.get();
            let untyped = fixture.owners.cap_source_in(s, Cap::Untyped {
                ptr: crate::cap::PAddr::new(0x0090_0000), block_bits: 14, free_index: 0,
                is_device: false,
            });
            s.cte_mut(untyped).unwrap().set_child_count(1);
            assert!(crate::invocation::derive_cap(s.cte(untyped).unwrap()).is_err(),
                "CNode Copy of an Untyped with children fails with seL4_RevokeFirst");
            fixture.stage_from(untyped);
            assert_eq!(fixture.transfer(), 0);
            assert!(fixture.received(RECEIVE_SLOT).cap().is_null());
            s.cte_mut(untyped).unwrap().set_child_count(0);
            fixture.stage_from(untyped);
            assert_eq!(fixture.transfer(), 1, "an Untyped without children transfers");
            assert_eq!(fixture.received(RECEIVE_SLOT).parent(), Some(untyped));
            crate::invocation::delete_cap_slot(
                s, crate::cte::MdbId::pack(0, RECEIVE_SLOT as u32)).unwrap();
            assert_eq!(s.cte(untyped).unwrap().child_count(), 0);
            fixture.retire();
        }
        arch::log("  \u{2713} an Untyped with children is not derived\n");
    }

    /// A receiver whose CSpace is a dynamic (Untyped-backed) CNode: its copy is a child across CNode
    /// pools, and revoking the source reaches it there.
    #[inline(never)]
    fn transfer_into_a_dynamic_cnode_is_revoked_with_its_source() {
        use crate::kernel::{SMALL_CNODE_RADIX, SMALL_CNODE_SLOTS};
        #[repr(C, align(2048))]
        struct Backing([crate::cte::Cte; SMALL_CNODE_SLOTS]);
        static mut BACKING: Backing = Backing([crate::cte::Cte::null(); SMALL_CNODE_SLOTS]);
        unsafe {
            let s = crate::kernel::KERNEL.get();
            let vi = s
                .alloc_dynamic_cnode(crate::arch::virt_to_phys((&raw mut BACKING) as u64),
                    SMALL_CNODE_RADIX)
                .expect("dynamic CNode descriptor");
            let mut fixture = TransferFixture::new_receiving_in(vi, SMALL_CNODE_RADIX);
            fixture.stage();
            assert_eq!(fixture.transfer(), 1);
            assert!(matches!(BACKING.0[RECEIVE_SLOT].cap(), Cap::Frame { .. }),
                "the copy lands in the dynamic CNode's own storage");
            assert_eq!(fixture.received(RECEIVE_SLOT).parent(), Some(fixture.source));
            let cnode = Cap::CNode {
                ptr: crate::kernel::KernelState::cnode_ptr(fixture.source.cnode_idx() as usize),
                radix: 5, guard_size: 59, guard: 0,
            };
            let revoke = crate::syscall_handler::SyscallArgs {
                a1: (crate::syscalls::InvocationLabel::CNodeRevoke as u64) << 12,
                a2: fixture.source.slot() as u64,
                ..Default::default()
            };
            crate::invocation::decode_invocation(cnode, &revoke, fixture.sender).expect("revoke");
            assert!(BACKING.0[RECEIVE_SLOT].cap().is_null(), "revoke reaches the dynamic CNode");
            assert_eq!(s.cte(fixture.source).unwrap().child_count(), 0);
            fixture.retire();
            s.free_dynamic_cnode(vi);
        }
        arch::log("  \u{2713} a copy in a dynamic CNode is revoked with its source\n");
    }

    unsafe fn bind_ipc_buffer(
        state: &mut crate::kernel::KernelState,
        owners: &mut crate::asid::spec::RootOwners,
        id: TcbId,
        address: u64,
        rights: crate::cap::FrameRights,
    ) {
        let source = owners.cap_source_in(state, crate::cap::Cap::Frame {
            ptr: crate::cap::PAddr::new(crate::arch::virt_to_phys(address)),
            size: crate::cap::FrameSize::Small, rights, mapped: None, asid: 0,
            is_device: false, map_type: crate::cap::FrameMapType::None,
        });
        crate::invocation::derive_tcb_cap(state, id, crate::cte::TcbSlot::IpcBuffer,
            Some(source), 0x1000).unwrap();
    }

    /// Long messages require readable sender and writable receiver Frame authority.
    #[inline(never)]
    fn long_message_via_ipc_buffer() {
        // Two backing pages — one per TCB. They sit in BSS so
        // `&raw mut` doubles as a kernel-virt address; for the
        // kernel-side spec that's all we need: writable u64
        // storage shared between sender and receiver via a known
        // address.
        #[repr(C, align(4096))]
        struct IpcPage([u64; 512]);
        static mut SENDER_BUF: IpcPage = IpcPage([0; 512]);
        static mut RECEIVER_BUF: IpcPage = IpcPage([0; 512]);

        let mut owners = crate::asid::spec::RootOwners::new();
        let state = unsafe { crate::kernel::KERNEL.get() };
        state.scheduler.reset_queues();
        state.scheduler.set_current(None);
        let mut ep = Endpoint::new();
        let sender = state.scheduler.admit(runnable(50));
        let receiver = state.scheduler.admit(runnable(50));
        unsafe {
            bind_ipc_buffer(state, &mut owners, sender, (&raw mut SENDER_BUF) as u64,
                crate::cap::FrameRights::ReadOnly);
            bind_ipc_buffer(state, &mut owners, receiver, (&raw mut RECEIVER_BUF) as u64,
                crate::cap::FrameRights::ReadWrite);
        }
        let sched = &mut state.scheduler;

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
        receive_ipc(&mut ep, sched, receiver, RecvOptions::blocking());
        // Sender sends.
        send_ipc(&mut ep, sched, sender, SendOptions::blocking(0));

        // Receiver's msg_regs should mirror the sender for words
        // 0..7, AND the receiver's ipc_buffer should hold words
        // 4..7 at offsets 5..8 (after the 1-word tag).
        unsafe {
            let r = sched.slab.get(receiver);
            for (i, &expect) in [
                0x1000u64, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007,
            ]
            .iter()
            .enumerate()
            {
                assert_eq!(
                    r.msg_regs[i], expect,
                    "msg_regs[{}] was {:#x} expected {:#x}",
                    i, r.msg_regs[i], expect
                );
            }
            assert_eq!(r.ipc_length, 8);
            for i in 4..8 {
                let buf = (&raw mut RECEIVER_BUF) as *mut u64;
                let got = core::ptr::read_volatile(buf.add(1 + i));
                let expect = 0x1000u64 + i as u64;
                assert_eq!(
                    got, expect,
                    "RECEIVER_BUF[{}] was {:#x} expected {:#x}",
                    i, got, expect
                );
            }
        }
        // A read-only receive buffer cannot accept the long-message tail.
        unsafe {
            bind_ipc_buffer(state, &mut owners, receiver, (&raw mut RECEIVER_BUF) as u64,
                crate::cap::FrameRights::ReadOnly);
        }
        state.scheduler.slab.get_mut(sender).ipc_length = 8;
        receive_ipc(&mut ep, &mut state.scheduler, receiver, RecvOptions::blocking());
        send_ipc(&mut ep, &mut state.scheduler, sender, SendOptions::blocking(0));
        assert_eq!(state.scheduler.slab.get(receiver).ipc_length, 4);
        unsafe {
            crate::invocation::retire_tcb(state, sender);
            crate::invocation::retire_tcb(state, receiver);
        }
        state.scheduler.reset_queues();
        state.scheduler.set_current(None);
        arch::log("  ✓ long IPC respects directional Frame authority\n");
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
        assert_eq!(
            sched.slab.get(receiver).state,
            ThreadStateType::BlockedOnReceive
        );

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
        let r = send_ipc(
            &mut ep,
            &mut sched,
            sender,
            SendOptions {
                blocking: true,
                do_call: false,
                badge: 0xABCD,
                can_grant: true,
                can_donate: false,
            },
        );
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
        let r = send_ipc(
            &mut ep,
            &mut sched,
            sender,
            SendOptions {
                blocking: false,
                do_call: false,
                badge: 0,
                can_grant: true,
                can_donate: false,
            },
        );
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

    #[inline(never)]
    fn send_repairs_current_sender_stale_queue_link() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let receiver = sched.admit(runnable(100));
        let sender = sched.admit(runnable(90));

        assert_eq!(
            receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking()),
            IpcOutcome::Blocked
        );
        sched.slab.get_mut(receiver).ep_next = Some(sender);
        {
            let sender_tcb = sched.slab.get_mut(sender);
            sender_tcb.ep_prev = Some(receiver);
            sender_tcb.ep_next = None;
        }
        ep.tail = Some(sender);
        ep.state = EpState::Send;

        assert_eq!(
            send_ipc(&mut ep, &mut sched, sender, SendOptions::blocking(0)),
            IpcOutcome::Transferred { peer: receiver }
        );
        assert_eq!(ep.state, EpState::Idle);
        assert_eq!(ep.head, None);
        assert_eq!(ep.tail, None);
        assert_eq!(sched.slab.get(receiver).state, ThreadStateType::Running);
        assert_eq!(sched.slab.get(sender).state, ThreadStateType::Running);
        assert_eq!(sched.slab.get(receiver).ep_next, None);
        assert_eq!(sched.slab.get(receiver).ep_prev, None);
        assert_eq!(sched.slab.get(sender).ep_next, None);
        assert_eq!(sched.slab.get(sender).ep_prev, None);
        arch::log("  ✓ current sender stale endpoint link is repaired before send\n");
    }

    #[inline(never)]
    fn send_pairs_receiver_head_when_state_is_stale_send() {
        let mut sched = Scheduler::new();
        let mut ep = Endpoint::new();
        let receiver = sched.admit(runnable(100));
        let sender = sched.admit(runnable(90));

        assert_eq!(
            receive_ipc(&mut ep, &mut sched, receiver, RecvOptions::blocking()),
            IpcOutcome::Blocked
        );
        ep.state = EpState::Send;
        {
            let s = sched.slab.get_mut(sender);
            s.ipc_label = 0xAB;
            s.ipc_length = 1;
            s.msg_regs[0] = 0xCD;
        }

        assert_eq!(
            send_ipc(&mut ep, &mut sched, sender, SendOptions::blocking(0x1234)),
            IpcOutcome::Transferred { peer: receiver }
        );
        assert_eq!(ep.state, EpState::Idle);
        assert_eq!(ep.head, None);
        assert_eq!(ep.tail, None);
        assert_eq!(sched.slab.get(receiver).state, ThreadStateType::Running);
        assert_eq!(sched.slab.get(sender).state, ThreadStateType::Running);
        assert_eq!(sched.slab.get(receiver).ipc_label, 0xAB);
        assert_eq!(sched.slab.get(receiver).msg_regs[0], 0xCD);
        assert_eq!(sched.slab.get(receiver).ipc_badge, 0x1234);
        assert_eq!(sched.slab.get(receiver).ep_next, None);
        assert_eq!(sched.slab.get(receiver).ep_prev, None);
        assert_eq!(sched.slab.get(sender).ep_next, None);
        assert_eq!(sched.slab.get(sender).ep_prev, None);
        arch::log("  ✓ stale Send state pairs an existing receiver instead of mixing queues\n");
    }
}
