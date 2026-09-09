mod execution_hold_specs {
    use super::*;
    use crate::tcb::ThreadStateType;

    fn cap(id: TcbId) -> Cap {
        Cap::Thread {
            tcb: PPtr::new(id.0 as u64).unwrap(),
        }
    }

    fn request(acquire: bool, token: u64) -> SyscallArgs {
        SyscallArgs {
            a1: if acquire {
                (InvocationLabel::TCBAcquireExecutionHold as u64) << 12
            } else {
                ((InvocationLabel::TCBReleaseExecutionHold as u64) << 12) | 1
            },
            a2: token,
            ..Default::default()
        }
    }

    unsafe fn acquire(invoker: TcbId, target: TcbId) -> u64 {
        decode_invocation(cap(target), &request(true, 0), invoker).unwrap();
        let result = KERNEL.get().scheduler.slab.get(invoker);
        assert_eq!((result.ipc_label, result.ipc_length), (0, 1));
        assert_ne!(result.msg_regs[0], 0);
        result.msg_regs[0]
    }

    unsafe fn release(invoker: TcbId, target: TcbId, token: u64) {
        decode_invocation(cap(target), &request(false, token), invoker).unwrap();
        let result = KERNEL.get().scheduler.slab.get(invoker);
        assert_eq!((result.ipc_label, result.ipc_length), (0, 0));
    }

    unsafe fn owned_sc(
        s: &mut KernelState,
        owners: &mut crate::asid::spec::RootOwners,
        id: TcbId,
    ) -> usize {
        let index = s.alloc_sched_context().unwrap();
        s.sched_contexts[index] = crate::sched_context::SchedContext::new(10, 10);
        owners.cap_source_in(
            s,
            Cap::SchedContext {
                ptr: KernelState::sched_context_ptr(index),
                size_bits: crate::object_type::MIN_SCHED_CONTEXT_BITS as u8,
            },
        );
        crate::sched_context::sc_donate(s, index, id);
        index
    }

    unsafe fn admission_and_tokens() {
        let invoker = setup_invoker(0);
        let mut owners = crate::asid::spec::RootOwners::new();
        let s = KERNEL.get();
        let target = s.scheduler.admit(crate::tcb::Tcb::default());
        let other = s.scheduler.admit(crate::tcb::Tcb::default());
        owned_sc(s, &mut owners, target);
        s.scheduler.make_runnable(target);
        s.scheduler.set_current(Some(invoker));
        s.scheduler.set_active_user(Some(target));
        s.scheduler.nodes[crate::arch::get_cpu_id() as usize].direct_handoff = Some(target);
        let context = s.scheduler.slab.get(target).user_context;
        let mut malformed = request(true, 0);
        malformed.a1 |= 1;
        assert!(decode_invocation(cap(target), &malformed, invoker).is_err());
        assert_eq!(KERNEL.get().scheduler.slab.get(target).execution_hold, 0);
        let token = acquire(invoker, target);
        let s = KERNEL.get();
        let t = s.scheduler.slab.get(target);
        assert_eq!(t.state, ThreadStateType::Running);
        // Both architecture UserContexts are repr(C) images containing only u64 fields.
        assert_eq!(
            core::slice::from_raw_parts(
                core::ptr::addr_of!(t.user_context).cast::<u8>(),
                core::mem::size_of_val(&context)
            ),
            core::slice::from_raw_parts(
                core::ptr::addr_of!(context).cast::<u8>(),
                core::mem::size_of_val(&context)
            ),
        );
        assert!(!t.enqueued && !t.is_schedulable());
        assert_ne!(s.scheduler.active_user(), Some(target));
        assert_eq!(s.scheduler.take_direct_handoff(), None);
        for mut invalid in [
            request(true, 0),
            request(false, 0),
            request(false, token + 1),
        ] {
            assert!(decode_invocation(cap(target), &invalid, invoker).is_err());
            invalid.a1 |= 1 << 9;
            assert!(decode_invocation(cap(target), &invalid, invoker).is_err());
            assert_eq!(
                KERNEL.get().scheduler.slab.get(target).execution_hold,
                token
            );
        }
        let other_token = acquire(invoker, other);
        assert_ne!(token, other_token);
        assert!(decode_invocation(cap(target), &request(false, other_token), invoker).is_err());
        let resume = SyscallArgs {
            a1: (InvocationLabel::TCBResume as u64) << 12,
            ..Default::default()
        };
        decode_invocation(cap(target), &resume, invoker).unwrap();
        let s = KERNEL.get();
        assert_eq!(s.scheduler.slab.get(target).execution_hold, token);
        s.scheduler.make_runnable(target);
        s.scheduler.on_sc_gained(target);
        assert!(!s.scheduler.slab.get(target).enqueued);
        assert!(!crate::sched_context::dispatch_budget_check(target));
        assert_ne!(s.scheduler.choose_thread(), Some(target));
        release(invoker, target, token);
        assert!(KERNEL.get().scheduler.slab.get(target).is_schedulable());
        assert!(KERNEL.get().scheduler.slab.get(target).enqueued);
        assert!(decode_invocation(cap(target), &request(false, token), invoker).is_err());
        // A later hold, including after TCB reuse, cannot accept the old token.
        let second = acquire(invoker, target);
        assert_ne!(second, token);
        assert!(decode_invocation(cap(target), &request(false, token), invoker).is_err());
        let s = KERNEL.get();
        teardown_thread_in(s, target);
        let replacement = s.scheduler.admit(crate::tcb::Tcb::default());
        let third = acquire(invoker, replacement);
        assert_ne!(third, second);
        assert!(decode_invocation(cap(replacement), &request(false, second), invoker).is_err());
        release(invoker, replacement, third);
        assert_eq!(
            KERNEL.get().scheduler.slab.get(replacement).state,
            ThreadStateType::Inactive
        );
        release(invoker, other, other_token);
        let s = KERNEL.get();
        teardown_thread_in(s, replacement);
        teardown_thread_in(s, other);
        teardown_thread_in(s, invoker);
        drop(owners);
    }

    unsafe fn held_reply(fault: bool) {
        let invoker = setup_invoker(0);
        let mut owners = crate::asid::spec::RootOwners::new();
        let s = KERNEL.get();
        let caller = s.scheduler.admit(crate::tcb::Tcb::default());
        let receiver = s.scheduler.admit(crate::tcb::Tcb::default());
        let sc = owned_sc(s, &mut owners, caller);
        let reply = s.alloc_reply().unwrap();
        let reply_cap = Cap::Reply {
            ptr: KernelState::reply_ptr(reply),
            can_grant: true,
        };
        owners.cap_source_in(s, reply_cap);
        crate::reply::offer(s, receiver, reply as u16);
        crate::reply::bind_call(s, caller, receiver, Some(reply as u16));
        if fault {
            s.scheduler.slab.get_mut(caller).pending_fault = 3;
        }
        s.scheduler.set_current(Some(invoker));
        let before_reply = s.replies[reply];
        let before_head = s.sched_contexts[sc].reply_head;
        let token = acquire(invoker, caller);
        let s = KERNEL.get();
        assert_eq!(s.replies[reply], before_reply);
        assert_eq!(s.sched_contexts[sc].reply_head, before_head);
        assert_eq!(
            s.scheduler.slab.get(caller).state,
            ThreadStateType::BlockedOnReply
        );
        assert_eq!(
            s.scheduler.slab.get(caller).pending_fault,
            if fault { 3 } else { 0 }
        );
        decode_invocation(reply_cap, &SyscallArgs::default(), invoker).unwrap();
        let s = KERNEL.get();
        assert_eq!(s.replies[reply], crate::reply::Reply::new());
        assert_eq!(s.scheduler.slab.get(caller).pending_fault, 0);
        assert_eq!(s.scheduler.slab.get(caller).state, ThreadStateType::Running);
        assert_eq!(s.scheduler.slab.get(caller).sc, Some(sc as u16));
        assert!(!s.scheduler.slab.get(caller).enqueued);
        assert!(!s.scheduler.slab.get(caller).is_schedulable());
        release(invoker, caller, token);
        assert!(KERNEL.get().scheduler.slab.get(caller).enqueued);
        let s = KERNEL.get();
        teardown_thread_in(s, caller);
        teardown_thread_in(s, receiver);
        teardown_thread_in(s, invoker);
        drop(owners);
    }

    unsafe fn held_receive() {
        let invoker = setup_invoker(0);
        let mut owners = crate::asid::spec::RootOwners::new();
        let s: *mut KernelState = KERNEL.get();
        let receiver = (*s).scheduler.admit(crate::tcb::Tcb::default());
        let sender = (*s).scheduler.admit(crate::tcb::Tcb::default());
        owned_sc(&mut *s, &mut owners, receiver);
        let endpoint = (*s).alloc_endpoint().unwrap();
        owners.cap_source_in(
            &mut *s,
            Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(endpoint),
                badge: Badge(0),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            },
        );
        let reply = (*s).alloc_reply().unwrap();
        owners.cap_source_in(
            &mut *s,
            Cap::Reply {
                ptr: KernelState::reply_ptr(reply),
                can_grant: true,
            },
        );
        crate::reply::offer(&mut *s, receiver, reply as u16);
        crate::endpoint::receive_ipc(
            &mut (*s).endpoints[endpoint],
            &mut (*s).scheduler,
            receiver,
            crate::endpoint::RecvOptions { blocking: true },
        );
        (*s).scheduler.set_current(Some(invoker));
        let token = acquire(invoker, receiver);
        assert_eq!((*s).endpoints[endpoint].head, Some(receiver));
        assert_eq!((*s).replies[reply].offered_tcb, Some(receiver));
        assert_eq!(
            (*s).scheduler.slab.get(receiver).state,
            ThreadStateType::BlockedOnReceive
        );
        crate::endpoint::send_ipc(
            &mut (*s).endpoints[endpoint],
            &mut (*s).scheduler,
            sender,
            crate::endpoint::SendOptions {
                blocking: true,
                do_call: false,
                badge: 7,
                can_grant: false,
                can_donate: false,
            },
        );
        assert_eq!((*s).endpoints[endpoint].head, None);
        assert_eq!((*s).replies[reply], crate::reply::Reply::new());
        assert_eq!(
            (*s).scheduler.slab.get(receiver).state,
            ThreadStateType::Running
        );
        assert!(!(*s).scheduler.slab.get(receiver).enqueued);
        release(invoker, receiver, token);
        assert!((*s).scheduler.slab.get(receiver).enqueued);
        teardown_thread_in(&mut *s, receiver);
        teardown_thread_in(&mut *s, sender);
        teardown_thread_in(&mut *s, invoker);
        drop(owners);
    }

    unsafe fn held_notification_and_budget() {
        let invoker = setup_invoker(0);
        let mut owners = crate::asid::spec::RootOwners::new();
        let s: *mut KernelState = KERNEL.get();
        let target = (*s).scheduler.admit(crate::tcb::Tcb::default());
        let sc = owned_sc(&mut *s, &mut owners, target);
        let ntfn = (*s).alloc_notification().unwrap();
        owners.cap_source_in(
            &mut *s,
            Cap::Notification {
                ptr: KernelState::ntfn_ptr(ntfn),
                badge: Badge(0),
                rights: crate::cap::NotificationRights {
                    can_send: true,
                    can_receive: true,
                },
            },
        );
        crate::notification::wait(&mut (*s).notifications[ntfn], &mut (*s).scheduler, target);
        (*s).scheduler.set_current(Some(invoker));
        let token = acquire(invoker, target);
        assert_eq!((*s).notifications[ntfn].head, Some(target));
        assert_eq!(
            (*s).scheduler.slab.get(target).state,
            ThreadStateType::BlockedOnNotification
        );
        release(invoker, target, token);
        assert_eq!((*s).notifications[ntfn].head, Some(target));
        assert!(!(*s).scheduler.slab.get(target).enqueued);
        let token = acquire(invoker, target);
        crate::notification::signal(&mut (*s).notifications[ntfn], &mut (*s).scheduler, 0x42);
        assert_eq!((*s).notifications[ntfn].head, None);
        assert_eq!(
            (*s).scheduler.slab.get(target).state,
            ThreadStateType::Running
        );
        assert!(!(*s).scheduler.slab.get(target).enqueued);
        release(invoker, target, token);
        assert!((*s).scheduler.slab.get(target).enqueued);

        (*s).sched_contexts[sc].budget = 1;
        (*s).sched_contexts[sc].period = 10;
        (*s).sched_contexts[sc].count = 1;
        (*s).sched_contexts[sc].head = 0;
        (*s).sched_contexts[sc].refills[0] = crate::sched_context::Refill {
            release_time: 10,
            amount: 1,
        };
        (*s).scheduler
            .block(target, ThreadStateType::BlockedOnBudget);
        let token = acquire(invoker, target);
        crate::sched_context::set_test_time(Some(10));
        crate::sched_context::mcs_tick(0);
        assert_eq!(
            (*s).scheduler.slab.get(target).state,
            ThreadStateType::Running
        );
        assert!(!(*s).scheduler.slab.get(target).enqueued);
        let consumed = (*s).sched_contexts[sc].consumed;
        let slice = (*s).scheduler.slab.get(target).time_slice;
        (*s).scheduler.set_current(Some(target));
        crate::sched_context::mcs_tick(1);
        assert!(!(*s).scheduler.tick());
        assert_eq!((*s).sched_contexts[sc].consumed, consumed);
        assert_eq!((*s).scheduler.slab.get(target).time_slice, slice);
        (*s).scheduler.set_current(Some(invoker));
        release(invoker, target, token);
        assert!((*s).scheduler.slab.get(target).enqueued);
        crate::sched_context::set_test_time(None);
        teardown_thread_in(&mut *s, target);
        teardown_thread_in(&mut *s, invoker);
        drop(owners);
    }

    pub(super) fn run() {
        let exhausted = core::sync::atomic::AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            execution_hold::reserve_generation(&exhausted),
            Some(u64::MAX)
        );
        assert_eq!(execution_hold::reserve_generation(&exhausted), None);
        unsafe {
            admission_and_tokens();
            held_reply(false);
            held_reply(true);
            held_receive();
            held_notification_and_budget();
        }
        arch::log(
            "  Execution hold preserves waits and excludes completed targets until exact release\n",
        );
    }
}
