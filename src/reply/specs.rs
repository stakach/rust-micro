use super::*;
use crate::kernel::KERNEL;
use crate::tcb::Tcb;

struct Chain {
    threads: [TcbId; 3],
    objects: [usize; 2],
    sc: usize,
}

impl Chain {
    fn new(s: &mut KernelState, legacy: bool) -> Self {
        s.scheduler.reset_queues();
        s.scheduler.set_current(None);
        let threads = core::array::from_fn(|_| s.scheduler.admit(Tcb::default()));
        let objects = core::array::from_fn(|_| s.alloc_reply().expect("reply spec object"));
        let sc = s.alloc_sched_context().expect("reply spec SC");
        crate::sched_context::sc_donate(s, sc, threads[0]);
        for i in 0..2 {
            let object = if legacy { None } else { Some(objects[i] as u16) };
            if let Some(object) = object { offer(s, threads[i + 1], object); }
            bind_call(s, threads[i], threads[i + 1], object);
        }
        Self { threads, objects, sc }
    }

    fn node(&self, s: &KernelState, index: usize) -> ReplyNode {
        s.scheduler.slab.get(self.threads[index]).call_reply.expect("exact call node")
    }

    fn finish(self, s: &mut KernelState) {
        for &thread in &self.threads { retire_tcb(s, thread); }
        for object in self.objects { s.free_reply(object); }
        s.free_sched_context(self.sc);
        for thread in self.threads {
            s.scheduler.block(thread, ThreadStateType::Inactive);
            s.scheduler.slab.free(thread);
        }
        s.scheduler.reset_queues();
    }
}

fn nested_pop(s: &mut KernelState, legacy: bool) {
    let chain = Chain::new(s, legacy);
    let [a, b, c] = chain.threads;
    let outer = chain.node(s, 0);
    let inner = chain.node(s, 1);
    assert_eq!(get(s, outer).next, Some(Next::Reply(inner)));
    assert_eq!(get(s, inner).prev, Some(outer));
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(c));
    remove(s, inner);
    assert_eq!(s.sched_contexts[chain.sc].reply_head, Some(outer));
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(b));
    assert_eq!(get(s, outer).next, Some(Next::Head(chain.sc as u16)));
    assert_eq!(s.scheduler.slab.get(c).sc, None);
    assert_eq!(s.scheduler.slab.get(b).call_reply, None);
    remove(s, outer);
    assert_eq!(s.sched_contexts[chain.sc].reply_head, None);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(a));
    assert_eq!(s.scheduler.slab.get(a).call_reply, None);
    remove(s, outer);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(a));
    chain.finish(s);
}

fn interior_removal(s: &mut KernelState) {
    let chain = Chain::new(s, false);
    let [a, b, c] = chain.threads;
    let inner = chain.node(s, 1);
    s.free_reply(chain.objects[0]);
    assert_eq!(s.scheduler.slab.get(a).state, ThreadStateType::Inactive);
    assert_eq!(s.scheduler.slab.get(a).call_reply, None);
    assert_eq!(s.scheduler.slab.get(a).sc, None);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(c));
    assert_eq!(s.sched_contexts[chain.sc].reply_head, Some(inner));
    assert_eq!(get(s, inner).prev, None);
    let reused = s.alloc_reply().expect("reuse outer Reply slot");
    assert_eq!(reused, chain.objects[0]);
    assert_eq!(s.replies[reused], Reply::new());
    remove(s, inner);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(b));
    assert_eq!(s.sched_contexts[chain.sc].reply_head, None);
    assert_eq!(s.scheduler.slab.get(a).sc, None);
    chain.finish(s);
}

fn cancellation_does_not_reclaim(s: &mut KernelState) {
    let chain = Chain::new(s, false);
    let [a, b, c] = chain.threads;
    let outer = chain.node(s, 0);
    let inner = chain.node(s, 1);
    unlink(s, inner);
    assert_eq!(s.sched_contexts[chain.sc].reply_head, None);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(c));
    assert_eq!(get(s, outer).next, None);
    assert_eq!(s.scheduler.slab.get(b).state, ThreadStateType::Inactive);
    // This old diagnostic value must not authorize an SC return.
    s.scheduler.slab.get_mut(a).donated_sc = Some(chain.sc as u16);
    remove(s, outer);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(c));
    assert_eq!(s.scheduler.slab.get(a).sc, None);
    chain.finish(s);
}

fn bound_reply_reuse_cancels_without_return(s: &mut KernelState) {
    let chain = Chain::new(s, false);
    let [a, b, c] = chain.threads;
    let outer = chain.node(s, 0);
    let replacement = s.scheduler.admit(Tcb::default());
    offer(s, replacement, chain.objects[1] as u16);
    assert_eq!(s.scheduler.slab.get(b).call_reply, None);
    assert_eq!(s.scheduler.slab.get(b).state, ThreadStateType::Inactive);
    assert_eq!(s.sched_contexts[chain.sc].reply_head, None);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(c));
    assert_eq!(get(s, outer).next, None);
    remove(s, outer);
    assert_eq!(s.scheduler.slab.get(a).sc, None);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(c));
    release_offer(s, replacement);
    s.scheduler.block(replacement, ThreadStateType::Inactive);
    s.scheduler.slab.free(replacement);
    chain.finish(s);
}

fn caller_with_independent_sc(s: &mut KernelState) {
    let chain = Chain::new(s, false);
    let [a, b, c] = chain.threads;
    let outer = chain.node(s, 0);
    let inner = chain.node(s, 1);
    let independent = s.alloc_sched_context().expect("independent SC");
    crate::sched_context::sc_donate(s, independent, b);
    remove(s, inner);
    assert_eq!(s.scheduler.slab.get(b).sc, Some(independent as u16));
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(c));
    assert_eq!(s.sched_contexts[chain.sc].reply_head, Some(outer));
    remove(s, outer);
    assert_eq!(s.sched_contexts[chain.sc].bound_tcb, Some(a));
    assert_eq!(s.sched_contexts[independent].bound_tcb, Some(b));
    s.free_sched_context(independent);
    chain.finish(s);
}

fn sc_slot_reuse(s: &mut KernelState) {
    let chain = Chain::new(s, false);
    let outer = chain.node(s, 0);
    let inner = chain.node(s, 1);
    s.free_sched_context(chain.sc);
    assert_eq!(get(s, inner).next, None);
    let reused = s.alloc_sched_context().expect("reuse SC slot");
    assert_eq!(reused, chain.sc);
    let stranger = s.scheduler.admit(Tcb::default());
    crate::sched_context::sc_donate(s, reused, stranger);
    remove(s, inner);
    remove(s, outer);
    assert_eq!(s.sched_contexts[reused].bound_tcb, Some(stranger));
    chain.finish(s);
    s.scheduler.block(stranger, ThreadStateType::Inactive);
    s.scheduler.slab.free(stranger);
}

fn offered_reply_reuse(s: &mut KernelState) {
    use crate::endpoint::{IpcOutcome, RecvOptions};
    let receiver = s.scheduler.admit(Tcb::default());
    let endpoint = s.alloc_endpoint().expect("offer endpoint");
    let reply = s.alloc_reply().expect("offered Reply");
    offer(s, receiver, reply as u16);
    assert_eq!(crate::endpoint::receive_ipc(
        &mut s.endpoints[endpoint], &mut s.scheduler, receiver, RecvOptions::blocking(),
    ), IpcOutcome::Blocked);
    assert_eq!(s.replies[reply].offered_tcb, Some(receiver));
    s.free_reply(reply);
    assert_eq!(s.scheduler.slab.get(receiver).pending_reply, None);
    assert_eq!(s.scheduler.slab.get(receiver).state, ThreadStateType::Inactive);
    assert_eq!(s.endpoints[endpoint].head, None);
    assert_eq!(s.endpoints[endpoint].tail, None);
    let reused = s.alloc_reply().expect("reuse offered Reply slot");
    assert_eq!(reused, reply);
    let caller = s.scheduler.admit(Tcb::default());
    let other_receiver = s.scheduler.admit(Tcb::default());
    offer(s, other_receiver, reused as u16);
    bind_call(s, caller, other_receiver, Some(reused as u16));
    assert_eq!(self::caller(s, ReplyNode::Object(reused as u16)), Some(caller));
    assert_eq!(s.scheduler.slab.get(receiver).pending_reply, None);
    s.free_reply(reused);
    s.free_endpoint(endpoint);
    for thread in [receiver, caller, other_receiver] {
        retire_tcb(s, thread);
        s.scheduler.block(thread, ThreadStateType::Inactive);
        s.scheduler.slab.free(thread);
    }
}

fn receiver_offer_replacement(s: &mut KernelState) {
    let receiver = s.scheduler.admit(Tcb::default());
    let old = s.alloc_reply().expect("old offer");
    let new = s.alloc_reply().expect("new offer");
    offer(s, receiver, old as u16);
    offer(s, receiver, new as u16);
    assert_eq!(s.replies[old], Reply::new());
    assert_eq!(s.replies[new].offered_tcb, Some(receiver));
    assert_eq!(s.scheduler.slab.get(receiver).pending_reply, Some(new as u16));
    offer(s, receiver, new as u16);
    assert_eq!(s.replies[new].offered_tcb, Some(receiver));
    s.free_reply(old);
    assert_eq!(s.scheduler.slab.get(receiver).pending_reply, Some(new as u16));
    s.free_reply(new);
    assert_eq!(s.scheduler.slab.get(receiver).pending_reply, None);
    s.scheduler.block(receiver, ThreadStateType::Inactive);
    s.scheduler.slab.free(receiver);
}

pub fn test_reply_chains() {
    crate::arch::log("Running exact MCS Reply-chain tests...\n");
    unsafe {
        let s = KERNEL.get();
        nested_pop(s, false);
        nested_pop(s, true);
        interior_removal(s);
        cancellation_does_not_reclaim(s);
        bound_reply_reuse_cancels_without_return(s);
        caller_with_independent_sc(s);
        sc_slot_reuse(s);
        offered_reply_reuse(s);
        receiver_offer_replacement(s);
    }
    crate::arch::log("Exact MCS Reply-chain tests completed (9 cases)\n");
}
