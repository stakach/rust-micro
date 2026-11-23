mod yield_to_specs {
    use super::*;
    use crate::tcb::ThreadStateType;

    fn request() -> SyscallArgs {
        SyscallArgs {
            a1: (InvocationLabel::TCBYieldTo as u64) << 12,
            ..Default::default()
        }
    }

    fn thread(id: TcbId) -> Cap {
        Cap::Thread {
            tcb: PPtr::new(id.0 as u64).unwrap(),
        }
    }

    unsafe fn invoke_slot(invoker: TcbId, cptr: u64, args: &SyscallArgs) -> KResult<()> {
        let s = KERNEL.get();
        let root = s.scheduler.slab.get(invoker).cspace_root();
        let cap = lookup_cap(s, &root, cptr)?;
        decode_invocation(cap, args, invoker)
    }

    pub(super) fn run() {
        unsafe {
            // Append the extension label after existing rust-micro methods so their ABI stays
            // stable. A TCB cap, rather than a numeric TCB ID in a message word, is authority.
            const _: () = assert!(InvocationLabel::TCBYieldTo as u64 == 76);
            let invoker = setup_invoker(0);
            let s = KERNEL.get();
            {
                let root = s.scheduler.slab.get_mut(invoker);
                root.priority = 255;
                root.sc = Some(0);
            }
            s.scheduler.on_sc_gained(invoker);
            s.scheduler.set_current(Some(invoker));

            let mut worker_tcb = crate::tcb::Tcb::default();
            worker_tcb.priority = 100;
            worker_tcb.state = ThreadStateType::Running;
            worker_tcb.sc = Some(0);
            let worker = s.scheduler.admit(worker_tcb);
            s.cnodes[0].0[2].set_cap(&thread(worker));

            // The request has no words or extra caps. Malformed variants cannot schedule work.
            for malformed_info in [request().a1 | 1, request().a1 | (1 << 7), request().a1 | (1 << 9)] {
                let mut malformed = request();
                malformed.a1 = malformed_info;
                assert!(invoke_slot(invoker, 2, &malformed).is_err());
                assert_eq!(s.scheduler.take_direct_handoff(), None);
            }
            assert!(decode_invocation(thread(invoker), &request(), invoker).is_err());
            assert_eq!(s.scheduler.take_direct_handoff(), None);

            // A valid, exact capability grants one dispatch opportunity only; all physical
            // priorities and IPC state remain unchanged.
            assert!(invoke_slot(invoker, 2, &request()).is_ok());
            assert_eq!(s.scheduler.take_direct_handoff(), Some(worker));
            assert_eq!(s.scheduler.take_direct_handoff(), None);
            assert_eq!(s.scheduler.slab.get(invoker).priority, 255);
            assert_eq!(s.scheduler.slab.get(worker).priority, 100);
            assert_eq!(s.scheduler.slab.get(worker).call_reply, None);

            let mut blocked_tcb = crate::tcb::Tcb::default();
            blocked_tcb.priority = 100;
            blocked_tcb.state = ThreadStateType::Running;
            blocked_tcb.sc = Some(0);
            let blocked = s.scheduler.admit(blocked_tcb);
            s.scheduler.block(blocked, ThreadStateType::BlockedOnReceive);
            s.cnodes[0].0[3].set_cap(&thread(blocked));
            assert!(invoke_slot(invoker, 3, &request()).is_err());

            let mut other_domain_tcb = crate::tcb::Tcb::default();
            other_domain_tcb.priority = 100;
            other_domain_tcb.state = ThreadStateType::Running;
            other_domain_tcb.sc = Some(0);
            other_domain_tcb.domain = 1;
            let other_domain = s.scheduler.admit(other_domain_tcb);
            s.cnodes[0].0[4].set_cap(&thread(other_domain));
            assert!(invoke_slot(invoker, 4, &request()).is_err());
            assert_eq!(s.scheduler.take_direct_handoff(), None);

            // Removing the only authorized cap makes the old CPtr unusable even while the
            // caller retains its numeric value. A forged non-TCB cap cannot name the worker.
            delete_cap_slot(s, MdbId::pack(0, 2)).unwrap();
            assert!(invoke_slot(invoker, 2, &request()).is_err());
            teardown_thread_in(s, worker);
            assert!(decode_invocation(thread(worker), &request(), invoker).is_err());
            // A forged PPtr that truncates to the old TcbId must not select a new occupant.
            let forged = Cap::Thread {
                tcb: PPtr::new(0x1_0000 + u64::from(worker.0)).unwrap(),
            };
            assert!(decode_invocation(forged, &request(), invoker).is_err());
            let reply = s.alloc_reply().unwrap();
            s.cnodes[0].0[5].set_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply),
                can_grant: true,
            });
            assert!(invoke_slot(invoker, 5, &request()).is_err());
            assert_eq!(s.scheduler.take_direct_handoff(), None);

            for slot in [3, 4, 5] {
                delete_cap_slot(s, MdbId::pack(0, slot)).unwrap();
            }
            teardown_thread_in(s, blocked);
            teardown_thread_in(s, other_domain);
            teardown_thread_in(s, invoker);
            arch::log("  ✓ TCB YieldTo requires an exact live cap and grants one dispatch\n");
        }
    }
}
