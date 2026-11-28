mod passive_worker_unbind_specs {
    use super::*;
    use crate::endpoint::{EpState, IpcOutcome, RecvOptions, SendOptions};
    use crate::reply::{Reply, ReplyNode};
    use crate::tcb::ThreadStateType;

    const WORKER_CAP: u64 = 2;
    const ENDPOINT_CAP: u64 = 3;
    const REPLY_CAP: u64 = 4;
    const OTHER_TCB_CAP: u64 = 5;
    const OTHER_ENDPOINT_CAP: u64 = 6;
    const OTHER_REPLY_CAP: u64 = 7;

    fn request(tcb: u64, endpoint: u64, reply: u64) -> SyscallArgs {
        SyscallArgs {
            a1: ((InvocationLabel::SchedContextUnbindPassiveWorker as u64) << 12) | 3,
            a2: tcb,
            a3: endpoint,
            a4: reply,
            ..Default::default()
        }
    }

    fn exact_offer_request(reply: u64, endpoint: u64) -> SyscallArgs {
        SyscallArgs {
            a1: ((InvocationLabel::TCBQueryReplyBinding as u64) << 12) | 2,
            a2: reply,
            a3: endpoint,
            ..Default::default()
        }
    }

    fn sc_cap(index: usize) -> Cap {
        Cap::SchedContext {
            ptr: KernelState::sched_context_ptr(index),
            size_bits: crate::object_type::MIN_SCHED_CONTEXT_BITS as u8,
        }
    }

    fn endpoint_cap(index: usize) -> Cap {
        Cap::Endpoint {
            ptr: KernelState::endpoint_ptr(index),
            badge: Badge(0),
            rights: EndpointRights {
                can_send: true,
                can_receive: true,
                can_grant: true,
                can_grant_reply: true,
            },
        }
    }

    fn tcb_cap(id: TcbId) -> Cap {
        Cap::Thread {
            tcb: PPtr::new(id.0 as u64).unwrap(),
        }
    }

    fn reply_cap(index: usize) -> Cap {
        Cap::Reply {
            ptr: KernelState::reply_ptr(index),
            can_grant: true,
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Snapshot {
        sc_bound: Option<TcbId>,
        sc_reply_head: Option<ReplyNode>,
        worker_sc: Option<u16>,
        worker_state: ThreadStateType,
        worker_pending_reply: Option<u16>,
        worker_active_sc: Option<u16>,
        worker_donated_sc: Option<u16>,
        worker_reply_to: Option<TcbId>,
        worker_call_reply: Option<ReplyNode>,
        worker_pending_fault: u8,
        worker_bound_notification: Option<u16>,
        worker_ep_prev: Option<TcbId>,
        worker_ep_next: Option<TcbId>,
        endpoint_state: EpState,
        endpoint_head: Option<TcbId>,
        endpoint_tail: Option<TcbId>,
        reply: Reply,
    }

    unsafe fn snapshot(sc: usize, worker: TcbId, endpoint: usize, reply: usize) -> Snapshot {
        let s = KERNEL.get();
        let t = s.scheduler.slab.get(worker);
        let ep = &s.endpoints[endpoint];
        Snapshot {
            sc_bound: s.sched_contexts[sc].bound_tcb,
            sc_reply_head: s.sched_contexts[sc].reply_head,
            worker_sc: t.sc,
            worker_state: t.state,
            worker_pending_reply: t.pending_reply,
            worker_active_sc: t.active_sc,
            worker_donated_sc: t.donated_sc,
            worker_reply_to: t.reply_to,
            worker_call_reply: t.call_reply,
            worker_pending_fault: t.pending_fault,
            worker_bound_notification: t.bound_notification,
            worker_ep_prev: t.ep_prev,
            worker_ep_next: t.ep_next,
            endpoint_state: ep.state,
            endpoint_head: ep.head,
            endpoint_tail: ep.tail,
            reply: s.replies[reply],
        }
    }

    unsafe fn refuses_unchanged(
        invoked_sc: Cap,
        args: &SyscallArgs,
        invoker: TcbId,
        sc: usize,
        worker: TcbId,
        endpoint: usize,
        reply: usize,
    ) {
        let before = snapshot(sc, worker, endpoint, reply);
        assert!(decode_invocation(invoked_sc, args, invoker).is_err());
        assert_eq!(snapshot(sc, worker, endpoint, reply), before);
    }

    pub(super) fn run() {
        unsafe {
            // The extension is appended after existing private labels; earlier ABI numbers
            // must remain stable for already built userspace components.
            const _: () = assert!(InvocationLabel::SchedContextUnbindPassiveWorker as u64 == 77);
            let invoker = setup_invoker(0);
            let mut owners = crate::asid::spec::RootOwners::new();
            let s = KERNEL.get();
            let worker = s.scheduler.admit(crate::tcb::Tcb::default());
            bind_invoker_cap(
                s,
                worker,
                crate::cte::TcbSlot::CSpace,
                Cap::CNode {
                    ptr: KernelState::cnode_ptr(0),
                    radix: 5,
                    guard_size: 59,
                    guard: 0,
                },
                0,
            );
            let other = s.scheduler.admit(crate::tcb::Tcb::default());
            let sc = s.alloc_sched_context().unwrap();
            let foreign_sc = s.alloc_sched_context().unwrap();
            let root_sc = s.alloc_sched_context().unwrap();
            for index in [sc, foreign_sc, root_sc] {
                s.sched_contexts[index] = crate::sched_context::SchedContext::new(10, 10);
                owners.cap_source_in(s, sc_cap(index));
            }
            crate::sched_context::sc_donate(s, sc, worker);
            crate::sched_context::sc_donate(s, foreign_sc, other);
            let endpoint = s.alloc_endpoint().unwrap();
            let other_endpoint = s.alloc_endpoint().unwrap();
            owners.cap_source_in(s, endpoint_cap(endpoint));
            owners.cap_source_in(s, endpoint_cap(other_endpoint));
            let reply = s.alloc_reply().unwrap();
            let other_reply = s.alloc_reply().unwrap();
            owners.cap_source_in(s, reply_cap(reply));
            owners.cap_source_in(s, reply_cap(other_reply));
            s.cnodes[0].0[WORKER_CAP as usize].set_cap(&tcb_cap(worker));
            s.cnodes[0].0[ENDPOINT_CAP as usize].set_cap(&endpoint_cap(endpoint));
            s.cnodes[0].0[REPLY_CAP as usize].set_cap(&reply_cap(reply));
            s.cnodes[0].0[OTHER_TCB_CAP as usize].set_cap(&tcb_cap(other));
            s.cnodes[0].0[OTHER_ENDPOINT_CAP as usize].set_cap(&endpoint_cap(other_endpoint));
            s.cnodes[0].0[OTHER_REPLY_CAP as usize].set_cap(&reply_cap(other_reply));

            // This is the first real receive, not a claimed numeric thread state. The
            // kernel offer and endpoint queue are the physical authority for a later Call.
            crate::reply::offer(s, worker, reply as u16);
            assert_eq!(
                crate::endpoint::receive_ipc(
                    &mut s.endpoints[endpoint],
                    &mut s.scheduler,
                    worker,
                    RecvOptions::blocking(),
                ),
                IpcOutcome::Blocked
            );
            assert_eq!(s.replies[reply].offered_tcb, Some(worker));
            let valid = request(WORKER_CAP, ENDPOINT_CAP, REPLY_CAP);
            let target = sc_cap(sc);

            for malformed in [
                valid.a1 - 1,
                valid.a1 + 1,
                valid.a1 | (1 << 7),
                valid.a1 | (1 << 9),
            ] {
                let mut args = valid;
                args.a1 = malformed;
                refuses_unchanged(target, &args, invoker, sc, worker, endpoint, reply);
            }
            let foreign_before = (
                s.sched_contexts[foreign_sc].bound_tcb,
                s.scheduler.slab.get(other).sc,
                s.scheduler.slab.get(other).state,
                s.scheduler.slab.get(other).pending_reply,
                s.endpoints[other_endpoint].state,
                s.endpoints[other_endpoint].head,
                s.endpoints[other_endpoint].tail,
                s.replies[other_reply],
            );
            for args in [
                request(OTHER_TCB_CAP, ENDPOINT_CAP, REPLY_CAP),
                request(WORKER_CAP, OTHER_ENDPOINT_CAP, REPLY_CAP),
                request(WORKER_CAP, ENDPOINT_CAP, OTHER_REPLY_CAP),
                request(ENDPOINT_CAP, ENDPOINT_CAP, REPLY_CAP),
                request(WORKER_CAP, WORKER_CAP, REPLY_CAP),
                request(WORKER_CAP, ENDPOINT_CAP, WORKER_CAP),
                request(0, ENDPOINT_CAP, REPLY_CAP),
            ] {
                refuses_unchanged(target, &args, invoker, sc, worker, endpoint, reply);
            }
            refuses_unchanged(
                sc_cap(foreign_sc),
                &valid,
                invoker,
                sc,
                worker,
                endpoint,
                reply,
            );
            assert_eq!(
                (
                    s.sched_contexts[foreign_sc].bound_tcb,
                    s.scheduler.slab.get(other).sc,
                    s.scheduler.slab.get(other).state,
                    s.scheduler.slab.get(other).pending_reply,
                    s.endpoints[other_endpoint].state,
                    s.endpoints[other_endpoint].head,
                    s.endpoints[other_endpoint].tail,
                    s.replies[other_reply],
                ),
                foreign_before
            );

            s.scheduler.slab.get_mut(worker).state = ThreadStateType::Inactive;
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).state = ThreadStateType::BlockedOnReceive;

            // An extra receiver means the endpoint is not private to this handoff.
            assert_eq!(
                crate::endpoint::receive_ipc(
                    &mut s.endpoints[endpoint],
                    &mut s.scheduler,
                    other,
                    RecvOptions::blocking(),
                ),
                IpcOutcome::Blocked
            );
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, other);
            s.scheduler.block(other, ThreadStateType::Inactive);

            crate::reply::release_offer(s, worker);
            crate::reply::offer(s, other, reply as u16);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            crate::reply::release_offer(s, other);
            crate::reply::offer(s, worker, reply as u16);

            s.replies[reply].bound_tcb = Some(other);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.replies[reply].bound_tcb = None;
            s.sched_contexts[sc].reply_head = Some(ReplyNode::Object(other_reply as u16));
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.sched_contexts[sc].reply_head = None;
            s.scheduler.slab.get_mut(worker).active_sc = Some(sc as u16);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).active_sc = None;
            s.scheduler.slab.get_mut(worker).donated_sc = Some(sc as u16);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).donated_sc = None;
            s.scheduler.slab.get_mut(worker).reply_to = Some(other);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).reply_to = None;
            s.scheduler.slab.get_mut(worker).call_reply = Some(ReplyNode::Legacy(other));
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).call_reply = None;
            s.scheduler.slab.get_mut(worker).bound_notification = Some(0);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).bound_notification = None;
            s.scheduler.slab.get_mut(worker).pending_fault = 1;
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).pending_fault = 0;
            let notification = s.alloc_notification().unwrap();
            s.notifications[notification].bound_sc = Some(sc as u16);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            assert_eq!(s.notifications[notification].bound_sc, Some(sc as u16));
            s.notifications[notification].bound_sc = None;
            s.free_notification(notification);
            s.scheduler.slab.get_mut(other).active_sc = Some(sc as u16);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            assert_eq!(s.scheduler.slab.get(other).active_sc, Some(sc as u16));
            s.scheduler.slab.get_mut(other).active_sc = None;
            s.scheduler.slab.get_mut(other).donated_sc = Some(sc as u16);
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            assert_eq!(s.scheduler.slab.get(other).donated_sc, Some(sc as u16));
            s.scheduler.slab.get_mut(other).donated_sc = None;
            s.sched_contexts[sc].bound_tcb = None;
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.sched_contexts[sc].bound_tcb = Some(worker);
            s.scheduler.slab.get_mut(worker).sc = None;
            refuses_unchanged(target, &valid, invoker, sc, worker, endpoint, reply);
            s.scheduler.slab.get_mut(worker).sc = Some(sc as u16);

            let before = snapshot(sc, worker, endpoint, reply);
            decode_invocation(target, &valid, invoker).expect("atomic first-worker SC unbind");
            assert_eq!(s.sched_contexts[sc].bound_tcb, None);
            assert_eq!(s.scheduler.slab.get(worker).sc, None);
            assert_eq!(s.scheduler.slab.get(worker).state, before.worker_state);
            assert_eq!(s.endpoints[endpoint].head, before.endpoint_head);
            assert_eq!(s.endpoints[endpoint].tail, before.endpoint_tail);
            assert_eq!(s.replies[reply], before.reply);
            assert_eq!(
                (
                    s.scheduler.slab.get(invoker).ipc_label,
                    s.scheduler.slab.get(invoker).ipc_length
                ),
                (0, 0)
            );

            // A reusable worker needs stronger evidence than the legacy Offered response:
            // this exact TCB must be blocked on its private endpoint with this Reply pending.
            // The same query will be made after each atomic ReplyRecv before reuse.
            let invoker_before_query = {
                let tcb = s.scheduler.slab.get(invoker);
                (tcb.ipc_label, tcb.ipc_length, tcb.msg_regs[0])
            };
            let exact = exact_offer_request(REPLY_CAP, ENDPOINT_CAP);
            let before_query = snapshot(sc, worker, endpoint, reply);
            decode_invocation(tcb_cap(worker), &exact, invoker)
                .expect("exact offered receive for the worker");
            assert_eq!(
                (
                    s.scheduler.slab.get(invoker).ipc_label,
                    s.scheduler.slab.get(invoker).ipc_length,
                    s.scheduler.slab.get(invoker).msg_regs[0],
                ),
                (0, 1, 1)
            );
            assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);

            for (subject, request) in [
                (tcb_cap(other), exact),
                (
                    tcb_cap(worker),
                    exact_offer_request(OTHER_REPLY_CAP, ENDPOINT_CAP),
                ),
                (
                    tcb_cap(worker),
                    exact_offer_request(REPLY_CAP, OTHER_ENDPOINT_CAP),
                ),
            ] {
                let before_query = snapshot(sc, worker, endpoint, reply);
                decode_invocation(subject, &request, invoker)
                    .expect("valid wrong-owner exact offer query");
                assert_eq!(
                    (
                        s.scheduler.slab.get(invoker).ipc_label,
                        s.scheduler.slab.get(invoker).ipc_length,
                        s.scheduler.slab.get(invoker).msg_regs[0],
                    ),
                    (0, 1, 0)
                );
                assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);
            }

            for request in [
                exact_offer_request(0, ENDPOINT_CAP),
                exact_offer_request(REPLY_CAP, 0),
            ] {
                let before_query = snapshot(sc, worker, endpoint, reply);
                assert!(decode_invocation(tcb_cap(worker), &request, invoker).is_err());
                assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);
            }

            // A corrupt pending Reply or endpoint queue may be reported as an error or false,
            // but must never authorize the worker's next run or change the corrupt state.
            s.scheduler.slab.get_mut(worker).pending_reply = None;
            let before_query = snapshot(sc, worker, endpoint, reply);
            if decode_invocation(tcb_cap(worker), &exact, invoker).is_ok() {
                assert_eq!(s.scheduler.slab.get(invoker).msg_regs[0], 0);
            }
            assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);
            s.scheduler.slab.get_mut(worker).pending_reply = Some(reply as u16);

            s.endpoints[endpoint].head = None;
            let before_query = snapshot(sc, worker, endpoint, reply);
            if decode_invocation(tcb_cap(worker), &exact, invoker).is_ok() {
                assert_eq!(s.scheduler.slab.get(invoker).msg_regs[0], 0);
            }
            assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);
            s.endpoints[endpoint].head = Some(worker);

            s.endpoints[endpoint].tail = None;
            let before_query = snapshot(sc, worker, endpoint, reply);
            if decode_invocation(tcb_cap(worker), &exact, invoker).is_ok() {
                assert_eq!(s.scheduler.slab.get(invoker).msg_regs[0], 0);
            }
            assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);
            s.endpoints[endpoint].tail = Some(worker);

            s.endpoints[endpoint].state = EpState::Idle;
            let before_query = snapshot(sc, worker, endpoint, reply);
            if decode_invocation(tcb_cap(worker), &exact, invoker).is_ok() {
                assert_eq!(s.scheduler.slab.get(invoker).msg_regs[0], 0);
            }
            assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);
            s.endpoints[endpoint].state = EpState::Recv;

            s.scheduler.slab.get_mut(worker).state = ThreadStateType::Inactive;
            let before_query = snapshot(sc, worker, endpoint, reply);
            if decode_invocation(tcb_cap(worker), &exact, invoker).is_ok() {
                assert_eq!(s.scheduler.slab.get(invoker).msg_regs[0], 0);
            }
            assert_eq!(snapshot(sc, worker, endpoint, reply), before_query);
            s.scheduler.slab.get_mut(worker).state = ThreadStateType::BlockedOnReceive;
            let invoker_tcb = s.scheduler.slab.get_mut(invoker);
            invoker_tcb.ipc_label = invoker_before_query.0;
            invoker_tcb.ipc_length = invoker_before_query.1;
            invoker_tcb.msg_regs[0] = invoker_before_query.2;

            // The root's first Call must use that same offered Reply and donate root's SC
            // to the now-passive worker, rather than reviving the old bootstrap SC.
            crate::sched_context::sc_donate(s, root_sc, invoker);
            assert_eq!(
                crate::endpoint::send_ipc(
                    &mut s.endpoints[endpoint],
                    &mut s.scheduler,
                    invoker,
                    SendOptions {
                        blocking: true,
                        do_call: true,
                        badge: 0,
                        can_grant: true,
                        can_donate: true
                    },
                ),
                IpcOutcome::Transferred { peer: worker }
            );
            assert_eq!(
                s.scheduler.slab.get(invoker).state,
                ThreadStateType::BlockedOnReply
            );
            assert_eq!(s.scheduler.slab.get(worker).sc, Some(root_sc as u16));
            assert_eq!(s.replies[reply].bound_tcb, Some(invoker));
            assert_eq!(
                s.sched_contexts[root_sc].reply_head,
                Some(ReplyNode::Object(reply as u16))
            );

            // Exercise the actual atomic ReplyRecv syscall. Its Reply half returns the
            // donated SC to root, while its Recv half offers the same private Reply and
            // blocks this worker on its endpoint. A query made before root's next Call
            // must observe that new receive, not the already-consumed first offer.
            struct Sink;
            impl crate::syscall_handler::DebugSink for Sink {
                fn put_byte(&mut self, _: u8) {}
            }
            crate::arch::set_composite_send_destination(
                &mut s.scheduler.slab.get_mut(worker).user_context,
                true,
                REPLY_CAP,
            );
            s.scheduler.set_current(Some(worker));
            crate::syscall_handler::handle_syscall(
                crate::syscalls::Syscall::SysReplyRecv,
                &SyscallArgs {
                    a0: ENDPOINT_CAP,
                    ..Default::default()
                },
                &mut Sink,
            )
            .expect("worker ReplyRecv replies and rearms its private receive");
            assert_eq!(s.scheduler.slab.get(invoker).state, ThreadStateType::Running);
            assert_eq!(s.scheduler.slab.get(invoker).sc, Some(root_sc as u16));
            assert_eq!(s.scheduler.slab.get(worker).state, ThreadStateType::BlockedOnReceive);
            assert_eq!(s.scheduler.slab.get(worker).pending_reply, Some(reply as u16));
            assert_eq!(s.replies[reply].offered_tcb, Some(worker));
            assert_eq!(s.endpoints[endpoint].state, EpState::Recv);
            assert_eq!(s.endpoints[endpoint].head, Some(worker));
            assert_eq!(s.endpoints[endpoint].tail, Some(worker));
            s.scheduler.set_current(Some(invoker));
            let before_query = snapshot(root_sc, worker, endpoint, reply);
            decode_invocation(tcb_cap(worker), &exact, invoker)
                .expect("exact offered receive after ReplyRecv");
            assert_eq!(
                (
                    s.scheduler.slab.get(invoker).ipc_label,
                    s.scheduler.slab.get(invoker).ipc_length,
                    s.scheduler.slab.get(invoker).msg_regs[0],
                ),
                (0, 1, 1)
            );
            assert_eq!(snapshot(root_sc, worker, endpoint, reply), before_query);

            // Rearm proof is membership of this exact worker in the receive queue, not
            // proof that its endpoint has no other receivers. A higher-priority receiver
            // can join ahead of it without taking its pending Reply offer.
            s.scheduler.slab.get_mut(other).priority = 255;
            assert_eq!(
                crate::endpoint::receive_ipc(
                    &mut s.endpoints[endpoint],
                    &mut s.scheduler,
                    other,
                    RecvOptions::blocking(),
                ),
                IpcOutcome::Blocked
            );
            assert_eq!(s.endpoints[endpoint].head, Some(other));
            assert_eq!(s.endpoints[endpoint].tail, Some(worker));
            assert_eq!(s.scheduler.slab.get(worker).ep_prev, Some(other));
            let before_query = snapshot(root_sc, worker, endpoint, reply);
            decode_invocation(tcb_cap(worker), &exact, invoker)
                .expect("exact rearm proof with another receiver ahead");
            assert_eq!(s.scheduler.slab.get(invoker).msg_regs[0], 1);
            assert_eq!(snapshot(root_sc, worker, endpoint, reply), before_query);
            crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, other);
            s.scheduler.block(other, ThreadStateType::Inactive);

            crate::reply::remove(s, ReplyNode::Object(reply as u16));
            teardown_thread_in(s, worker);
            teardown_thread_in(s, other);
            teardown_thread_in(s, invoker);
            drop(owners);
        }
        arch::log("  ✓ checked passive worker SC unbind preserves first Call authority\n");
    }
}
