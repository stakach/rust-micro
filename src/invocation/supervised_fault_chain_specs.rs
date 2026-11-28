mod supervised_fault_chain_specs {
    use super::*;
    use crate::cap::{Badge, EndpointRights};
    use crate::endpoint::{IpcOutcome, RecvOptions, SendOptions};
    use crate::reply::{Reply, ReplyNode};
    use crate::tcb::{Tcb, ThreadStateType};

    fn tcb_cap(id: TcbId) -> Cap {
        Cap::Thread {
            tcb: PPtr::new(id.0 as u64).unwrap(),
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

    fn reply_cap(index: usize) -> Cap {
        Cap::Reply {
            ptr: KernelState::reply_ptr(index),
            can_grant: true,
        }
    }

    fn sc_cap(index: usize) -> Cap {
        Cap::SchedContext {
            ptr: KernelState::sched_context_ptr(index),
            size_bits: crate::object_type::MIN_SCHED_CONTEXT_BITS as u8,
        }
    }

    unsafe fn binding(supervisor: TcbId, expected: TcbId, reply_slot: u64) -> u64 {
        decode_invocation(
            tcb_cap(expected),
            &SyscallArgs {
                a1: ((InvocationLabel::TCBQueryReplyBinding as u64) << 12) | 1,
                a2: reply_slot,
                ..Default::default()
            },
            supervisor,
        )
        .expect("exact Reply binding query");
        let tcb = KERNEL.get().scheduler.slab.get(supervisor);
        assert_eq!((tcb.ipc_label, tcb.ipc_length), (0, 1));
        tcb.msg_regs[0]
    }

    pub(super) fn run() {
        unsafe {
            let controller = setup_invoker(0);
            let mut owners = crate::asid::spec::RootOwners::new();
            let s = KERNEL.get();
            let root = s.scheduler.admit(Tcb::default());
            let worker = s.scheduler.admit(Tcb::default());
            let supervisor = s.scheduler.admit(Tcb::default());
            let root_sc = s.alloc_sched_context().expect("root SC");
            let supervisor_sc = s.alloc_sched_context().expect("supervisor SC");
            for sc in [root_sc, supervisor_sc] {
                s.sched_contexts[sc] = crate::sched_context::SchedContext::new(10, 10);
                owners.cap_source_in(s, sc_cap(sc));
            }
            crate::sched_context::sc_donate(s, root_sc, root);
            crate::sched_context::sc_donate(s, supervisor_sc, supervisor);

            let work_ep = s.alloc_endpoint().expect("private worker endpoint");
            let fault_ep = s
                .alloc_endpoint()
                .expect("private supervisor fault endpoint");
            owners.cap_source_in(s, endpoint_cap(work_ep));
            let fault_source = owners.cap_source_in(s, endpoint_cap(fault_ep));
            derive_tcb_cap(s, worker, TcbSlot::FaultHandler, Some(fault_source), 0)
                .expect("worker fault endpoint ownership");
            let root_reply = s.alloc_reply().expect("worker Call Reply");
            let fault_reply = s.alloc_reply().expect("supervisor fault Reply");
            owners.cap_source_in(s, reply_cap(root_reply));
            owners.cap_source_in(s, reply_cap(fault_reply));

            // The supervisor has its own CSpace and SC before root can block on a Call.
            // An alias of the worker's Reply must exist before that Call has any effect.
            let cspace = s.scheduler.slab.get(controller).cspace_root();
            bind_invoker_cap(s, supervisor, TcbSlot::CSpace, cspace, 0);
            s.cnodes[0].0[2].set_cap(&reply_cap(root_reply));
            s.cnodes[0].0[3].set_cap(&reply_cap(fault_reply));
            s.cnodes[0].0[6].set_cap(&tcb_cap(root));
            s.cnodes[0].0[7].set_cap(&tcb_cap(worker));
            decode_invocation(
                cspace,
                &SyscallArgs {
                    a1: (InvocationLabel::CNodeCopy as u64) << 12,
                    a2: 5,
                    a3: 2,
                    ..Default::default()
                },
                controller,
            )
            .expect("retain worker Reply alias before root Call");
            assert_eq!(s.cnodes[0].0[2].cap(), s.cnodes[0].0[5].cap());

            crate::reply::offer(s, worker, root_reply as u16);
            assert_eq!(
                crate::endpoint::receive_ipc(
                    &mut s.endpoints[work_ep],
                    &mut s.scheduler,
                    worker,
                    RecvOptions::blocking(),
                ),
                IpcOutcome::Blocked,
            );
            crate::reply::offer(s, supervisor, fault_reply as u16);
            assert_eq!(
                crate::endpoint::receive_ipc(
                    &mut s.endpoints[fault_ep],
                    &mut s.scheduler,
                    supervisor,
                    RecvOptions::blocking(),
                ),
                IpcOutcome::Blocked,
            );
            assert_eq!(
                s.scheduler.slab.get(supervisor).sc,
                Some(supervisor_sc as u16)
            );

            assert_eq!(
                crate::endpoint::send_ipc(
                    &mut s.endpoints[work_ep],
                    &mut s.scheduler,
                    root,
                    SendOptions {
                        blocking: true,
                        do_call: true,
                        badge: 0,
                        can_grant: true,
                        can_donate: true,
                    },
                ),
                IpcOutcome::Transferred { peer: worker },
            );
            assert_eq!(
                s.scheduler.slab.get(root).state,
                ThreadStateType::BlockedOnReply
            );
            assert_eq!(s.scheduler.slab.get(root).sc, None);
            assert_eq!(s.scheduler.slab.get(worker).sc, Some(root_sc as u16));
            assert_eq!(
                s.sched_contexts[root_sc].reply_head,
                Some(ReplyNode::Object(root_reply as u16))
            );

            // Model an x86 #UD at the worker's instruction pointer. The kernel must
            // deliver a UserException as a second Call, while the supervisor runs on
            // its independent SC and root's donation remains with the faulted worker.
            crate::fault::deliver_fault_in(
                s,
                worker,
                crate::fault::FaultMessage::UserException { number: 6, code: 0 },
            )
            .expect("worker UserException delivery");
            assert_eq!(s.scheduler.slab.get(supervisor).ipc_label, 3);
            assert_eq!(
                s.scheduler.slab.get(worker).state,
                ThreadStateType::BlockedOnReply
            );
            assert_eq!(s.scheduler.slab.get(worker).pending_fault, 3);
            assert_eq!(
                s.scheduler.slab.get(supervisor).sc,
                Some(supervisor_sc as u16)
            );
            assert_eq!(s.scheduler.slab.get(worker).sc, Some(root_sc as u16));
            assert_eq!(binding(supervisor, root, 5), 2);
            assert_eq!(binding(supervisor, worker, 3), 2);
            assert_eq!(binding(supervisor, worker, 5), 3);
            assert_eq!(binding(supervisor, root, 3), 3);

            // The fault Reply is the inner chain node. Suspending only the worker
            // severs it; the independent supervisor can still reply through the
            // precreated outer alias to wake root and return its donated SC.
            s.scheduler.set_current(Some(supervisor));
            decode_invocation(
                tcb_cap(worker),
                &SyscallArgs {
                    a1: (InvocationLabel::TCBSuspend as u64) << 12,
                    ..Default::default()
                },
                supervisor,
            )
            .expect("suspend exact faulted worker");
            assert_eq!(
                s.scheduler.slab.get(worker).state,
                ThreadStateType::Inactive
            );
            assert_eq!(binding(supervisor, worker, 3), 0);
            assert_eq!(binding(supervisor, root, 5), 2);
            assert_eq!(
                s.scheduler.slab.get(root).state,
                ThreadStateType::BlockedOnReply
            );
            assert_eq!(s.scheduler.slab.get(root).sc, None);

            let alias = s.cnodes[0].0[5].cap();
            let terminal = SyscallArgs {
                a1: crate::types::seL4_MessageInfo_t::new(0x382, 0, 0, 1).words[0],
                a2: 0xc0000005,
                ..Default::default()
            };
            decode_invocation(alias, &terminal, supervisor)
                .expect("supervisor terminal through retained outer Reply alias");
            let r = s.scheduler.slab.get(root);
            assert_eq!(r.state, ThreadStateType::Running);
            assert_eq!(r.sc, Some(root_sc as u16));
            assert_eq!(r.call_reply, None);
            assert_eq!(
                (r.ipc_label, r.ipc_length, r.msg_regs[0]),
                (0x382, 1, 0xc0000005)
            );
            assert_eq!(s.sched_contexts[root_sc].bound_tcb, Some(root));
            assert_eq!(s.sched_contexts[root_sc].reply_head, None);
            assert_eq!(
                s.scheduler.slab.get(supervisor).sc,
                Some(supervisor_sc as u16)
            );
            assert_eq!(
                s.scheduler.slab.get(worker).state,
                ThreadStateType::Inactive
            );
            assert_eq!(s.replies[root_reply], Reply::new());
            assert!(decode_invocation(alias, &terminal, supervisor).is_err());

            for slot in [2, 3, 5, 6, 7] {
                delete_cap_slot(s, MdbId::pack(0, slot)).unwrap();
            }
            for thread in [root, worker, supervisor, controller] {
                teardown_thread_in(s, thread);
            }
            drop(owners);
        }
        arch::log("  ✓ independent supervisor returns faulted worker Call without replay\n");
    }
}
