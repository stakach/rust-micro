//! Exact MCS reply-call chains. Capability aliases name one object-backed node;
//! the explicit legacy IPC ABI uses an allocation-free node embedded in its caller.

use crate::kernel::KernelState;
use crate::tcb::{TcbId, ThreadStateType};

#[cfg(feature = "spec")]
pub mod specs;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReplyNode { Object(u16), Legacy(TcbId) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Next { Reply(ReplyNode), Head(u16) }

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Reply {
    pub bound_tcb: Option<TcbId>,
    pub offered_tcb: Option<TcbId>,
    pub prev: Option<ReplyNode>,
    pub next: Option<Next>,
}

impl Reply {
    pub const fn new() -> Self {
        Self { bound_tcb: None, offered_tcb: None, prev: None, next: None }
    }
}

fn get(s: &KernelState, node: ReplyNode) -> Reply {
    match node {
        ReplyNode::Object(i) => s.replies[i as usize],
        ReplyNode::Legacy(id) => s.scheduler.slab.get(id).legacy_reply,
    }
}

fn get_mut(s: &mut KernelState, node: ReplyNode) -> &mut Reply {
    match node {
        ReplyNode::Object(i) => &mut s.replies[i as usize],
        ReplyNode::Legacy(id) => &mut s.scheduler.slab.get_mut(id).legacy_reply,
    }
}

pub fn caller(s: &KernelState, node: ReplyNode) -> Option<TcbId> {
    // Keep exact-but-Inactive callers compatible until NT has a wait-preserving
    // execution hold and TCBSuspend can atomically adopt upstream cancellation.
    let id = get(s, node).bound_tcb?;
    (s.scheduler.slab.try_get(id)?.call_reply == Some(node)).then_some(id)
}

pub fn release_offer(s: &mut KernelState, receiver: TcbId) {
    if let Some(index) = s.scheduler.slab.get_mut(receiver).pending_reply.take() {
        let reply = &mut s.replies[index as usize];
        if reply.offered_tcb == Some(receiver) {
            assert!(reply.bound_tcb.is_none());
            *reply = Reply::new();
        }
    }
}

/// Reusing a Reply cancels its previous owner without returning its donation.
pub fn offer(s: &mut KernelState, receiver: TcbId, index: u16) {
    let node = ReplyNode::Object(index);
    if let Some(previous) = s.scheduler.slab.get(receiver).pending_reply {
        assert_eq!(s.replies[previous as usize].offered_tcb, Some(receiver));
        if previous == index { return; }
        release_offer(s, receiver);
    }
    let old = get(s, node);
    if let Some(previous) = old.offered_tcb {
        assert_ne!(previous, receiver, "receive offer lost its reciprocal TCB owner");
        release_offer(s, previous);
        crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, previous);
        s.scheduler.block(previous, ThreadStateType::Inactive);
    } else if old.bound_tcb.is_some() {
        unlink(s, node);
    }
    assert_eq!(get(s, node), Reply::new());
    get_mut(s, node).offered_tcb = Some(receiver);
    s.scheduler.slab.get_mut(receiver).pending_reply = Some(index);
}

/// Bind an admitted Call. `None` is only the explicit legacy no-Reply-cap ABI.
pub fn bind_call(s: &mut KernelState, sender: TcbId, receiver: TcbId, object: Option<u16>) {
    let node = object.map(ReplyNode::Object).unwrap_or(ReplyNode::Legacy(sender));
    if object.is_some() {
        assert_eq!(get(s, node).offered_tcb, Some(receiver));
        assert_eq!(s.scheduler.slab.get(receiver).pending_reply, object);
        s.scheduler.slab.get_mut(receiver).pending_reply = None;
        get_mut(s, node).offered_tcb = None;
    }
    assert_eq!(get(s, node), Reply::new());
    assert!(s.scheduler.slab.get(sender).call_reply.is_none());
    get_mut(s, node).bound_tcb = Some(sender);
    s.scheduler.slab.get_mut(sender).call_reply = Some(node);
    s.scheduler.block(sender, ThreadStateType::BlockedOnReply);
    s.scheduler.slab.get_mut(receiver).reply_to = Some(sender);
    let sc = s.scheduler.slab.get(sender).sc;
    if let (Some(sc), true) = (sc, s.scheduler.slab.get(receiver).sc.is_none()) {
        let prev = s.sched_contexts[sc as usize].reply_head;
        if let Some(prev) = prev {
            assert_eq!(get(s, prev).next, Some(Next::Head(sc)));
            get_mut(s, prev).next = Some(Next::Reply(node));
        }
        get_mut(s, node).prev = prev;
        get_mut(s, node).next = Some(Next::Head(sc));
        s.sched_contexts[sc as usize].reply_head = Some(node);
        crate::sched_context::sc_donate(s, sc as usize, receiver);
        s.scheduler.slab.get_mut(sender).donated_sc = Some(sc);
    }
}

fn clear_binding(s: &mut KernelState, node: ReplyNode, caller: TcbId) {
    assert_eq!(s.scheduler.slab.get(caller).call_reply, Some(node));
    let t = s.scheduler.slab.get_mut(caller);
    t.call_reply = None;
    t.donated_sc = None;
    *get_mut(s, node) = Reply::new();
    for t in s.scheduler.slab.entries.iter_mut().flatten() {
        if t.reply_to == Some(caller) {
            t.reply_to = None;
            t.active_sc = None;
        }
        if t.composite_reply_handoff == Some(caller) {
            t.composite_reply_handoff = None;
        }
    }
    s.scheduler.block(caller, ThreadStateType::Inactive);
}

/// Sever both chain segments without returning an SC (upstream reply_remove_tcb).
pub fn unlink(s: &mut KernelState, node: ReplyNode) {
    let reply = get(s, node);
    let Some(caller) = reply.bound_tcb else {
        assert_eq!(reply, Reply::new());
        return;
    };
    match reply.next {
        Some(Next::Head(sc)) => {
            assert_eq!(s.sched_contexts[sc as usize].reply_head, Some(node));
            s.sched_contexts[sc as usize].reply_head = None;
        }
        Some(Next::Reply(next)) => {
            assert_eq!(get(s, next).prev, Some(node));
            get_mut(s, next).prev = None;
        }
        None => {}
    }
    if let Some(prev) = reply.prev {
        assert_eq!(get(s, prev).next, Some(Next::Reply(node)));
        get_mut(s, prev).next = None;
    }
    clear_binding(s, node, caller);
}

/// Only the exact head can pop the SC. Removing an interior node breaks the
/// chain and leaves the live descendant holding its SC (upstream reply_remove).
pub fn remove(s: &mut KernelState, node: ReplyNode) {
    let reply = get(s, node);
    if let Some(receiver) = reply.offered_tcb {
        release_offer(s, receiver);
        crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, receiver);
        s.scheduler.block(receiver, ThreadStateType::Inactive);
        return;
    }
    let Some(caller) = reply.bound_tcb else {
        assert_eq!(reply, Reply::new());
        return;
    };
    if let Some(Next::Head(sc)) = reply.next {
        assert_eq!(s.sched_contexts[sc as usize].reply_head, Some(node));
        s.sched_contexts[sc as usize].reply_head = reply.prev;
        if let Some(prev) = reply.prev {
            assert_eq!(get(s, prev).next, Some(Next::Reply(node)));
            get_mut(s, prev).next = Some(Next::Head(sc));
        }
        if s.scheduler.slab.get(caller).sc.is_none() {
            if let Some(holder) = s.sched_contexts[sc as usize].bound_tcb {
                assert_eq!(s.scheduler.slab.get(holder).sc, Some(sc));
                unsafe { crate::smp::remote_tcb_stall(s, holder); }
            }
            crate::sched_context::sc_donate(s, sc as usize, caller);
        }
        clear_binding(s, node, caller);
    } else {
        unlink(s, node);
    }
}

pub fn retire_tcb(s: &mut KernelState, caller: TcbId) {
    release_offer(s, caller);
    if let Some(node) = s.scheduler.slab.get(caller).call_reply { unlink(s, node); }
    assert_eq!(s.scheduler.slab.get(caller).legacy_reply, Reply::new());
}

pub fn detach_sc(s: &mut KernelState, sc: usize) {
    if let Some(head) = s.sched_contexts[sc].reply_head.take() {
        assert_eq!(get(s, head).next, Some(Next::Head(sc as u16)));
        get_mut(s, head).next = None;
    }
    for t in s.scheduler.slab.entries.iter_mut().flatten() {
        if t.donated_sc == Some(sc as u16) { t.donated_sc = None; }
    }
}
