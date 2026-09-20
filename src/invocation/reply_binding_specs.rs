mod reply_binding_specs {
    use super::*;

    fn target(id: TcbId) -> Cap {
        Cap::Thread {
            tcb: PPtr::new(id.0 as u64).unwrap(),
        }
    }

    fn request(cptr: u64) -> SyscallArgs {
        SyscallArgs {
            a1: ((InvocationLabel::TCBQueryReplyBinding as u64) << 12) | 1,
            a2: cptr,
            ..Default::default()
        }
    }

    unsafe fn query(invoker: TcbId, caller: TcbId, cptr: u64) -> u64 {
        decode_invocation(target(caller), &request(cptr), invoker).unwrap();
        let tcb = KERNEL.get().scheduler.slab.get(invoker);
        assert_eq!((tcb.ipc_label, tcb.ipc_length), (0, 1));
        tcb.msg_regs[0]
    }

    unsafe fn thread_snapshot(id: TcbId) -> impl core::fmt::Debug + PartialEq {
        let t = KERNEL.get().scheduler.slab.get(id);
        (
            t.state,
            t.pending_reply,
            t.call_reply,
            t.reply_to,
            t.sc,
            t.active_sc,
            t.donated_sc,
            t.enqueued,
            t.execution_hold,
            t.pending_fault,
        )
    }

    pub(super) fn run() {
        unsafe {
            let invoker = setup_invoker(0);
            let mut owners = crate::asid::spec::RootOwners::new();
            let s = KERNEL.get();
            let caller = s.scheduler.admit(crate::tcb::Tcb::default());
            let receiver = s.scheduler.admit(crate::tcb::Tcb::default());
            let sc = s.alloc_sched_context().unwrap();
            s.sched_contexts[sc] = crate::sched_context::SchedContext::new(10, 10);
            owners.cap_source_in(
                s,
                Cap::SchedContext {
                    ptr: KernelState::sched_context_ptr(sc),
                    size_bits: crate::object_type::MIN_SCHED_CONTEXT_BITS as u8,
                },
            );
            crate::sched_context::sc_donate(s, sc, caller);
            let index = s.alloc_reply().unwrap();
            let cap = Cap::Reply {
                ptr: KernelState::reply_ptr(index),
                can_grant: true,
            };
            s.cnodes[0].0[2].set_cap(&cap);
            s.cnodes[0].0[3].set_cap(&cap);
            s.cnodes[0].0[4].set_cap(&target(caller));
            assert_eq!(query(invoker, caller, 2), 0);
            assert_eq!(query(invoker, caller, 3), 0);
            for cptr in [0, 4, 31] {
                assert!(decode_invocation(target(caller), &request(cptr), invoker).is_err());
            }
            for info in [
                request(2).a1 - 1,
                request(2).a1 + 1,
                request(2).a1 | (1 << 7),
                request(2).a1 | (1 << 9),
            ] {
                let mut malformed = request(2);
                malformed.a1 = info;
                assert!(decode_invocation(target(caller), &malformed, invoker).is_err());
                assert_eq!(KERNEL.get().replies[index], crate::reply::Reply::new());
            }
            crate::reply::offer(KERNEL.get(), receiver, index as u16);
            let offered = KERNEL.get().replies[index];
            let receiver_before = thread_snapshot(receiver);
            assert_eq!(query(invoker, caller, 2), 1);
            assert_eq!(query(invoker, caller, 3), 1);
            assert_eq!(KERNEL.get().replies[index], offered);
            assert_eq!(thread_snapshot(receiver), receiver_before);
            KERNEL.get().scheduler.slab.get_mut(receiver).pending_reply = None;
            assert!(decode_invocation(target(caller), &request(2), invoker).is_err());
            KERNEL.get().scheduler.slab.get_mut(receiver).pending_reply = Some(index as u16);
            crate::reply::bind_call(KERNEL.get(), caller, receiver, Some(index as u16));
            let bound = KERNEL.get().replies[index];
            let caller_before = thread_snapshot(caller);
            let receiver_before = thread_snapshot(receiver);
            let current = KERNEL.get().scheduler.current();
            let sc_before = (
                KERNEL.get().sched_contexts[sc].reply_head,
                KERNEL.get().sched_contexts[sc].bound_tcb,
            );
            assert_eq!(query(invoker, caller, 2), 2);
            assert_eq!(query(invoker, caller, 3), 2);
            assert_eq!(query(invoker, receiver, 2), 3);
            assert_eq!(KERNEL.get().replies[index], bound);
            assert_eq!(thread_snapshot(caller), caller_before);
            assert_eq!(thread_snapshot(receiver), receiver_before);
            assert_eq!(KERNEL.get().scheduler.current(), current);
            assert_eq!(
                (
                    KERNEL.get().sched_contexts[sc].reply_head,
                    KERNEL.get().sched_contexts[sc].bound_tcb
                ),
                sc_before
            );
            KERNEL.get().scheduler.slab.get_mut(caller).call_reply = None;
            assert!(decode_invocation(target(caller), &request(2), invoker).is_err());
            KERNEL.get().scheduler.slab.get_mut(caller).call_reply =
                Some(crate::reply::ReplyNode::Object(index as u16));
            KERNEL.get().replies[index].offered_tcb = Some(receiver);
            assert!(decode_invocation(target(caller), &request(2), invoker).is_err());
            KERNEL.get().replies[index] = bound;
            // The extension's numeric label is still ordinary payload on a Reply cap.
            let message = SyscallArgs {
                a1: request(2).a1,
                a2: 0x1234,
                ..Default::default()
            };
            decode_invocation(cap, &message, invoker).unwrap();
            assert_eq!(KERNEL.get().replies[index], crate::reply::Reply::new());
            let caller_tcb = KERNEL.get().scheduler.slab.get(caller);
            assert_eq!(
                caller_tcb.ipc_label,
                InvocationLabel::TCBQueryReplyBinding as u64
            );
            assert_eq!(caller_tcb.msg_regs[0], 0x1234);
            assert_eq!(query(invoker, caller, 2), 0);
            KERNEL.get().replies[index].prev = Some(crate::reply::ReplyNode::Legacy(caller));
            assert!(decode_invocation(target(caller), &request(2), invoker).is_err());
            KERNEL.get().replies[index] = crate::reply::Reply::new();
            let s = KERNEL.get();
            delete_cap_slot(s, MdbId::pack(0, 2)).unwrap();
            delete_cap_slot(s, MdbId::pack(0, 3)).unwrap();
            teardown_thread_in(s, caller);
            teardown_thread_in(s, receiver);
            teardown_thread_in(s, invoker);
            drop(owners);
        }
    }
}
