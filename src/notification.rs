//! Notification state machine. Mirrors `seL4/src/object/notification.c`
//! (the non-MCS slowpath).
//!
//! A Notification is a coarse synchronisation primitive — one badge
//! word that accumulates across signals via bitwise OR, plus a queue
//! of threads waiting for it to become non-zero.
//!
//! Three states:
//!   - `Idle` — no signal, no waiters
//!   - `Waiting` — one or more threads queued, no signal yet
//!   - `Active` — signal arrived but nobody had been waiting; the
//!     accumulated badge is parked in `pending_badge`.
//!
//! Transitions:
//!   signal(badge):
//!     Idle    -> Active, pending_badge = badge
//!     Waiting -> dequeue head, transfer badge, return to Idle if empty
//!     Active  -> pending_badge |= badge (badge merge)
//!
//!   wait():
//!     Idle    -> queue + block (state becomes Waiting)
//!     Waiting -> queue + block
//!     Active  -> consume pending_badge, return to Idle, caller stays
//!                runnable

use crate::scheduler::Scheduler;
use crate::tcb::{TcbId, ThreadStateType};
use crate::types::seL4_Word as Word;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum NtfnState {
    #[default]
    Idle,
    Waiting,
    Active,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Notification {
    pub state: NtfnState,
    /// Accumulated badge. When `state == Active`, this is the value
    /// the next `wait()` will consume.
    pub pending_badge: Word,
    /// Queue of waiting threads — same intrusive structure as
    /// endpoints, keyed off `tcb.ep_next` / `tcb.ep_prev`.
    pub head: Option<TcbId>,
    pub tail: Option<TcbId>,
    /// Optional bound TCB. When set, a signal that arrives while
    /// nobody is waiting on this notification *and* the bound thread
    /// is blocked on receive on this notification gets delivered to
    /// it directly. We track the cap but don't yet implement the
    /// shortcut — the slowpath subsumes it.
    pub bound_tcb: Option<TcbId>,
    /// Phase 43 — passive-server SchedContext binding. When a TCB is
    /// bound to this notification AND its SC has been unbound (sc =
    /// None), signalling the notification donates this SC's budget
    /// so the bound TCB can run. sel4test's BIND005/006 exercise this.
    pub bound_sc: Option<u16>,
}

impl Notification {
    pub const fn new() -> Self {
        Self {
            state: NtfnState::Idle,
            pending_badge: 0,
            head: None,
            tail: None,
            bound_tcb: None,
            bound_sc: None,
        }
    }
}

// Reuse the same intrusive helpers — but we replicate locally for
// clarity rather than coupling notification.rs to endpoint.rs.

fn queue_push(ntfn: &mut Notification, sched: &mut Scheduler, t: TcbId) {
    // Priority-ordered insertion (matches endpoint queue under MCS;
    // mirrors upstream tcbEPAppend).
    let new_prio = sched.slab.get(t).priority;
    let mut before = ntfn.tail;
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
        None => ntfn.head = Some(t),
    }
    match after {
        Some(a) => sched.slab.get_mut(a).ep_prev = Some(t),
        None => ntfn.tail = Some(t),
    }
}

fn queue_pop_head(ntfn: &mut Notification, sched: &mut Scheduler) -> Option<TcbId> {
    let head = ntfn.head?;
    let next = sched.slab.get(head).ep_next;
    ntfn.head = next;
    match next {
        Some(n) => sched.slab.get_mut(n).ep_prev = None,
        None => ntfn.tail = None,
    }
    let tcb = sched.slab.get_mut(head);
    tcb.ep_next = None;
    tcb.ep_prev = None;
    Some(head)
}

fn queue_remove(ntfn: &mut Notification, sched: &mut Scheduler, t: TcbId) {
    let (prev, next) = {
        let tcb = sched.slab.get(t);
        (tcb.ep_prev, tcb.ep_next)
    };
    match prev {
        Some(p) => sched.slab.get_mut(p).ep_next = next,
        None => ntfn.head = next,
    }
    match next {
        Some(n) => sched.slab.get_mut(n).ep_prev = prev,
        None => ntfn.tail = prev,
    }
    let tcb = sched.slab.get_mut(t);
    tcb.ep_next = None;
    tcb.ep_prev = None;
}

// ---------------------------------------------------------------------------
// Public operations.
// ---------------------------------------------------------------------------

/// Signal the notification with `badge`. Mirrors `sendSignal` in
/// seL4. Returns `Some(thread)` if a thread was woken (so the
/// caller can stash it in the scheduler), or `None` if the badge
/// was simply parked / merged.
pub fn signal(
    ntfn: &mut Notification,
    sched: &mut Scheduler,
    badge: Word,
) -> Option<TcbId> {
    match ntfn.state {
        NtfnState::Idle => {
            // Bound-TCB short-circuit: if a TCB is bound to this
            // notification AND that TCB is currently BlockedOnReceive
            // on some endpoint, upstream `sendSignal` cancels the
            // IPC and wakes the TCB with the badge in the badge
            // register. sel4test's test_notification_binding relies
            // on this — it Wait's on a sync endpoint and expects
            // bound-notification signals to wake it through that
            // wait. Without this short-circuit, the bound TCB
            // never wakes for a notification while it's blocked
            // on an endpoint.
            if let Some(bt) = ntfn.bound_tcb {
                // Defensive: if bound_tcb points at a freed slab slot
                // (a code path freed the TCB without clearing this
                // back-reference), repair the link and fall through
                // to the normal queue path instead of panicking.
                if sched.slab.try_get(bt).is_none() {
                    ntfn.bound_tcb = None;
                } else {
                // Phase 43 — passive-server SC donation. If the
                // bound TCB has no SC of its own (it was unbound) but
                // the notification carries a bound_sc, donate it so
                // the wake actually schedules. BIND006 needs this.
                if sched.slab.get(bt).sc.is_none() {
                    if let Some(sc_idx) = ntfn.bound_sc {
                        sched.slab.get_mut(bt).sc = Some(sc_idx);
                    }
                }
                // Phase 43 — BIND005 enforcement: a TCB with no SC
                // (no own + no donation) MUST NOT run. Fall through
                // to leaving the notification Active so the badge is
                // parked until SC is later bound (SchedContextBind on
                // the TCB will pick it up).
                if sched.slab.get(bt).sc.is_none() {
                    ntfn.state = NtfnState::Active;
                    ntfn.pending_badge |= badge;
                    return None;
                }
                let state = sched.slab.get(bt).state;
                if matches!(state, ThreadStateType::BlockedOnReceive) {
                    // Walk all endpoints to find which queue holds
                    // `bt` and dequeue from there. We don't track
                    // the endpoint id on the TCB, so a linear scan
                    // is the simplest way to keep the queue links
                    // consistent.
                    crate::endpoint::cancel_ipc_anywhere(sched, bt);
                    {
                        let tcb = sched.slab.get_mut(bt);
                        tcb.ipc_badge = badge;
                        #[cfg(target_arch = "x86_64")]
                        {
                            tcb.user_context.rdi = badge;
                            tcb.user_context.rsi = 0;
                        }
                    }
                    sched.make_runnable(bt);
                    return Some(bt);
                }
                } // end of else branch (bt slab slot was Some)
            }
            ntfn.state = NtfnState::Active;
            ntfn.pending_badge = badge;
            None
        }
        NtfnState::Active => {
            ntfn.pending_badge |= badge;
            None
        }
        NtfnState::Waiting => {
            let t = queue_pop_head(ntfn, sched)
                .expect("Waiting state must have at least one waiter");
            // Hand the badge directly to the woken thread. Write it
            // into both `ipc_badge` (for the syscall_entry tail's
            // was_recv_path fan-out, when the wake happens during
            // the same SYSCALL that called Wait) AND directly into
            // `user_context.rdi` (the upstream Wait/Recv ABI return
            // register) so dispatch paths that bypass the fan-out —
            // notably the syscall HLT loop's `enter_user_via_sysret`
            // when the Wait blocked, the kernel HLT'd, and an IRQ
            // ISR signalled the wake — still deliver the badge to
            // userspace. Without this rdi update, sel4test's Wait
            // returns with rdi == the original `src` cptr (preserved
            // from the SYSCALL entry args), userspace treats it as
            // the badge, runs `CTZL(cptr)` to index its per-IRQ
            // callback table, and calls a NULL function pointer.
            {
                let tcb = sched.slab.get_mut(t);
                tcb.ipc_badge = badge;
                #[cfg(target_arch = "x86_64")]
                {
                    tcb.user_context.rdi = badge;
                    // rsi (msginfo) — Wait returns an empty msginfo
                    // (no message words from notifications).
                    tcb.user_context.rsi = 0;
                }
            }
            sched.make_runnable(t);
            if ntfn.head.is_none() {
                ntfn.state = NtfnState::Idle;
            }
            Some(t)
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    /// Pending signal consumed; caller stays runnable. Returns the
    /// badge.
    Got { badge: Word },
    /// No signal — caller blocked on the queue.
    Blocked,
}

pub fn wait(
    ntfn: &mut Notification,
    sched: &mut Scheduler,
    thread: TcbId,
) -> WaitOutcome {
    match ntfn.state {
        NtfnState::Active => {
            let badge = ntfn.pending_badge;
            ntfn.pending_badge = 0;
            ntfn.state = NtfnState::Idle;
            // Stash the badge on the TCB so `wait`'s return convention
            // matches the receive side of an IPC transfer.
            sched.slab.get_mut(thread).ipc_badge = badge;
            WaitOutcome::Got { badge }
        }
        NtfnState::Idle | NtfnState::Waiting => {
            sched.block(thread, ThreadStateType::BlockedOnNotification);
            queue_push(ntfn, sched, thread);
            ntfn.state = NtfnState::Waiting;
            WaitOutcome::Blocked
        }
    }
}

/// Cancel a pending wait — used when a thread is destroyed or a
/// notification cap revoked.
pub fn cancel_wait(ntfn: &mut Notification, sched: &mut Scheduler, thread: TcbId) {
    if !matches!(
        sched.slab.get(thread).state,
        ThreadStateType::BlockedOnNotification,
    ) {
        return;
    }
    queue_remove(ntfn, sched, thread);
    sched.slab.get_mut(thread).state = ThreadStateType::Restart;
    if ntfn.head.is_none() {
        ntfn.state = NtfnState::Idle;
    }
}

/// SCHED0008 — reposition `thread` within whatever notification
/// wait-queue currently holds it, using the new priority. Mirrors
/// `endpoint::reposition_in_wait_queue` for notifications.
pub fn reposition_in_wait_queue(sched: &mut Scheduler, thread: TcbId) {
    use crate::kernel::{KERNEL, KernelState};
    let s_ptr: *mut KernelState = unsafe { KERNEL.get() };
    for i in 0..crate::kernel::MAX_NTFNS {
        let ntfn = unsafe { &mut (*s_ptr).notifications[i] };
        let mut found = false;
        let mut cur = ntfn.head;
        while let Some(c) = cur {
            if c == thread { found = true; break; }
            cur = sched.slab.try_get(c).and_then(|t| t.ep_next);
        }
        if !found { continue; }
        queue_remove(ntfn, sched, thread);
        queue_push(ntfn, sched, thread);
        return;
    }
}

/// Phase 43 — walk every kernel notification queue, removing `thread`
/// if found. Mirrors `endpoint::cancel_ipc_anywhere` for notifications;
/// used by TCB destruction to flush stale ids before the slab slot
/// is reclaimed.
pub fn cancel_wait_anywhere(sched: &mut Scheduler, thread: TcbId) {
    use crate::kernel::{KERNEL, KernelState};
    let s_ptr: *mut KernelState = unsafe { KERNEL.get() };
    for i in 0..crate::kernel::MAX_NTFNS {
        let ntfn = unsafe { &mut (*s_ptr).notifications[i] };
        let mut found = false;
        let mut cur = ntfn.head;
        while let Some(c) = cur {
            if c == thread { found = true; break; }
            cur = sched.slab.try_get(c).and_then(|t| t.ep_next);
        }
        if !found { continue; }
        queue_remove(ntfn, sched, thread);
        if ntfn.head.is_none() {
            ntfn.state = NtfnState::Idle;
        }
        if sched.slab.try_get(thread).is_some() {
            sched.slab.get_mut(thread).state = ThreadStateType::Inactive;
        }
        return;
    }
}

/// Bind a TCB to this notification. Mirrors
/// `bindNotification(tcb, ntfn)` in seL4. Returns `Err` if either
/// side is already bound.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BindError {
    AlreadyBound,
}

pub fn bind(ntfn: &mut Notification, tcb: TcbId) -> Result<(), BindError> {
    if ntfn.bound_tcb.is_some() {
        return Err(BindError::AlreadyBound);
    }
    ntfn.bound_tcb = Some(tcb);
    Ok(())
}

pub fn unbind(ntfn: &mut Notification) {
    ntfn.bound_tcb = None;
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

    pub fn test_notification() {
        arch::log("Running notification tests...\n");
        signal_then_wait();
        wait_then_signal();
        badge_merging_on_double_signal();
        cancel_wait_unblocks();
        bind_rejects_double();
        arch::log("Notification tests completed\n");
    }

    #[inline(never)]
    fn signal_then_wait() {
        let mut sched = Scheduler::new();
        let mut ntfn = Notification::new();
        let t = sched.admit(runnable(50));
        // Signal first — state goes Active, no thread woken.
        let woken = signal(&mut ntfn, &mut sched, 0xCAFE);
        assert_eq!(woken, None);
        assert_eq!(ntfn.state, NtfnState::Active);
        // Wait consumes it without blocking.
        let r = wait(&mut ntfn, &mut sched, t);
        assert_eq!(r, WaitOutcome::Got { badge: 0xCAFE });
        assert_eq!(ntfn.state, NtfnState::Idle);
        assert_eq!(sched.slab.get(t).state, ThreadStateType::Running);
        arch::log("  ✓ signal-then-wait consumes the parked badge\n");
    }

    #[inline(never)]
    fn wait_then_signal() {
        let mut sched = Scheduler::new();
        let mut ntfn = Notification::new();
        let t = sched.admit(runnable(50));
        let r = wait(&mut ntfn, &mut sched, t);
        assert_eq!(r, WaitOutcome::Blocked);
        assert_eq!(ntfn.state, NtfnState::Waiting);
        assert_eq!(sched.slab.get(t).state, ThreadStateType::BlockedOnNotification);
        // Now signal — head waiter wakes with the badge.
        let woken = signal(&mut ntfn, &mut sched, 0x42);
        assert_eq!(woken, Some(t));
        assert_eq!(ntfn.state, NtfnState::Idle);
        assert_eq!(sched.slab.get(t).ipc_badge, 0x42);
        assert_eq!(sched.slab.get(t).state, ThreadStateType::Running);
        arch::log("  ✓ wait-then-signal wakes the waiter with the badge\n");
    }

    #[inline(never)]
    fn badge_merging_on_double_signal() {
        let mut sched = Scheduler::new();
        let mut ntfn = Notification::new();
        let t = sched.admit(runnable(50));
        signal(&mut ntfn, &mut sched, 0b0001);
        signal(&mut ntfn, &mut sched, 0b0010);
        signal(&mut ntfn, &mut sched, 0b1000);
        assert_eq!(ntfn.state, NtfnState::Active);
        assert_eq!(ntfn.pending_badge, 0b1011);
        // wait() collects the merged value.
        match wait(&mut ntfn, &mut sched, t) {
            WaitOutcome::Got { badge: 0b1011 } => {}
            other => panic!("expected merged badge, got {:?}", other),
        }
        arch::log("  ✓ multiple signals OR their badges together\n");
    }

    #[inline(never)]
    fn cancel_wait_unblocks() {
        let mut sched = Scheduler::new();
        let mut ntfn = Notification::new();
        let t = sched.admit(runnable(50));
        wait(&mut ntfn, &mut sched, t);
        assert_eq!(sched.slab.get(t).state, ThreadStateType::BlockedOnNotification);
        cancel_wait(&mut ntfn, &mut sched, t);
        assert_eq!(sched.slab.get(t).state, ThreadStateType::Restart);
        assert_eq!(ntfn.state, NtfnState::Idle);
        arch::log("  ✓ cancel_wait removes thread + sets Restart\n");
    }

    #[inline(never)]
    fn bind_rejects_double() {
        let mut ntfn = Notification::new();
        bind(&mut ntfn, TcbId(0)).unwrap();
        assert_eq!(bind(&mut ntfn, TcbId(1)), Err(BindError::AlreadyBound));
        unbind(&mut ntfn);
        bind(&mut ntfn, TcbId(2)).unwrap();
        arch::log("  ✓ bind rejects double-bind, unbind allows re-bind\n");
    }
}
