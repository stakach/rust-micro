#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeferredDebugTrap {
    fault_ip: u64,
    reason: u64,
    trigger_addr: u64,
    bp_num: u64,
}

fn acquire_user_fault_entry() {
    let context = *crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
    let snapshot = crate::smp::UserEntrySnapshot { context, kind: crate::smp::UserEntryKind::Fault };
    if crate::smp::bkl_acquire_for_user_entry(Some(snapshot)) {
        unsafe { dispatch_next_or_idle("[fault entry quiesced]\n") }
    }
}

/// Normalize before another CPU changes the stopped thread's debug configuration. A trap
/// reports an already-observed event, so replaying the user instruction cannot recover it.
pub(crate) fn defer_quiesced_debug(tcb: &mut crate::tcb::Tcb, kind: crate::smp::UserEntryKind) {
    use crate::arch::x86_64::debug;
    let (reason, trigger_addr, bp_num) = match kind {
        crate::smp::UserEntryKind::Breakpoint => (debug::SEL4_SOFTWARE_BREAK_REQUEST, 0, 0),
        crate::smp::UserEntryKind::Debug { status } => {
            // Retain actual status even when counted stepping suppresses delivery, or this
            // exact user entry was adopted by a remote quiescence controller.
            tcb.debug.dr[4] = status;
            if let Some(bp) = (0..4).find(|&bp|
                status & (1 << bp) != 0 && debug::breakpoint_enabled(&tcb.debug, bp)) {
                (debug::breakpoint_reason(&tcb.debug, bp), tcb.debug.dr[bp], bp as u64)
            } else if status & debug::DR6_SINGLE_STEP != 0 {
                tcb.user_context.rflags |= debug::FLAGS_RF;
                if !debug::single_step_counter_ready(&mut tcb.debug) { return; }
                (debug::SEL4_SINGLE_STEP, 0, 0)
            } else {
                return;
            }
        }
        _ => return,
    };
    assert!(tcb.deferred_debug.is_none(), "a stopped thread cannot overwrite an undelivered trap");
    tcb.deferred_debug = Some(DeferredDebugTrap {
        fault_ip: tcb.user_context.rip, reason, trigger_addr, bp_num,
    });
}

/// Returns true when selection must restart: delivery blocks the original thread, and may
/// wake its handler. Removing the event before delivery makes this an exactly-once action.
pub(crate) fn deliver_deferred_debug(s: &mut crate::kernel::KernelState, id: crate::tcb::TcbId) -> bool {
    let Some(trap) = s.scheduler.slab.get_mut(id).deferred_debug.take() else { return false; };
    let fault = crate::fault::FaultMessage::DebugException {
        fault_ip: trap.fault_ip, reason: trap.reason,
        trigger_addr: trap.trigger_addr, bp_num: trap.bp_num,
    };
    if crate::fault::deliver_fault_in(s, id, fault).is_err() {
        crate::arch::log("[debug fault - no handler, suspending]\n");
        s.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
    }
    true
}

pub(crate) fn debug_ready_thread(
    s: &mut crate::kernel::KernelState, mut candidate: Option<crate::tcb::TcbId>,
) -> Option<crate::tcb::TcbId> {
    while let Some(id) = candidate {
        if !s.scheduler.slab.get(id).execution_held()
            && !deliver_deferred_debug(s, id) { return Some(id); }
        candidate = s.scheduler.choose_thread();
    }
    None
}

#[cfg(feature = "spec")]
fn test_deferred_debug() {
    use crate::arch::x86_64::debug;
    use crate::smp::UserEntryKind;
    let mut thread = crate::tcb::Tcb::default();
    thread.user_context.rip = 0x1235;
    defer_quiesced_debug(&mut thread, UserEntryKind::Breakpoint);
    assert_eq!(thread.deferred_debug.take().unwrap(), DeferredDebugTrap {
        fault_ip: 0x1235, reason: debug::SEL4_SOFTWARE_BREAK_REQUEST, trigger_addr: 0, bp_num: 0,
    });
    assert_eq!(thread.user_context.rip, 0x1235, "INT3 is not replayed by rewinding RIP");

    debug::set_breakpoint(&mut thread.debug, 2, 0x5566,
        debug::SEL4_INSTRUCTION_BREAKPOINT, 0, debug::SEL4_BREAK_ON_READ);
    let reason = debug::breakpoint_reason(&thread.debug, 2);
    defer_quiesced_debug(&mut thread, UserEntryKind::Debug { status: 1 << 2 });
    assert_eq!(thread.debug.dr[4], 1 << 2);
    thread.debug.dr[2] = 0x7788;
    let trap = thread.deferred_debug.take().unwrap();
    assert_eq!(trap.trigger_addr, 0x5566, "later debug configuration cannot rewrite the event");
    assert_eq!(trap.reason, reason);
    assert_eq!(trap.bp_num, 2);

    debug::configure_single_stepping(&mut thread.debug, 2);
    defer_quiesced_debug(&mut thread, UserEntryKind::Debug { status: debug::DR6_SINGLE_STEP });
    assert!(thread.deferred_debug.is_none());
    assert_eq!(thread.debug.n_instructions, 1);
    assert_eq!(thread.debug.dr[4], debug::DR6_SINGLE_STEP);
    assert_ne!(thread.user_context.rflags & debug::FLAGS_RF, 0);
    defer_quiesced_debug(&mut thread, UserEntryKind::Debug { status: debug::DR6_SINGLE_STEP });
    assert_eq!(thread.deferred_debug.take().unwrap().reason, debug::SEL4_SINGLE_STEP);
    assert_eq!(thread.debug.n_instructions, 0);
    defer_quiesced_debug(&mut thread, UserEntryKind::Debug { status: 0 });
    assert!(thread.deferred_debug.is_none());
    assert_eq!(thread.debug.dr[4], 0);
    debug::unset_breakpoint(&mut thread.debug, 2);
    defer_quiesced_debug(&mut thread, UserEntryKind::Debug { status: 1 << 2 });
    assert_eq!(thread.debug.dr[4], 1 << 2);
    assert!(thread.deferred_debug.is_none(), "disabled comparator status is not an active breakpoint");

    let _guard = crate::spec::KernelGuard::acquire();
    for with_handler in [false, true] {
        let mut owners = crate::asid::spec::RootOwners::new();
        unsafe {
            let state = crate::kernel::KERNEL.get();
            let id = state.scheduler.admit(crate::tcb::Tcb::default());
            let endpoint = if with_handler {
                let index = state.alloc_endpoint().unwrap();
                let cap = crate::cap::Cap::Endpoint {
                    ptr: crate::kernel::KernelState::endpoint_ptr(index),
                    badge: crate::cap::Badge(0),
                    rights: crate::cap::EndpointRights {
                        can_send: true, can_receive: true, can_grant: true, can_grant_reply: true,
                    },
                };
                let source = owners.cap_source_in(state, cap);
                crate::invocation::derive_tcb_cap(state, id, crate::cte::TcbSlot::FaultHandler,
                    Some(source), 0).unwrap();
                Some(index)
            } else { None };
            let thread = state.scheduler.slab.get_mut(id);
            thread.user_context.rip = 0x4243;
            thread.use_iretq_resume = true;
            let event = if with_handler {
                debug::set_breakpoint(&mut thread.debug, 0, 0x4243,
                    debug::SEL4_INSTRUCTION_BREAKPOINT, 0, debug::SEL4_BREAK_ON_READ);
                UserEntryKind::Debug { status: 0xffff_0ff1 }
            } else {
                UserEntryKind::Breakpoint
            };
            defer_quiesced_debug(thread, event);
            let observed_trap = thread.deferred_debug;
            let replacement = debug::validate_raw_context(thread.debug.dr).unwrap();
            debug::install_raw_context(&mut thread.debug, &replacement);
            assert_eq!(thread.deferred_debug, observed_trap, "register writes do not acknowledge an event");
            assert!(deliver_deferred_debug(state, id));
            assert!(!deliver_deferred_debug(state, id), "dispatch cannot deliver the event twice");
            assert!(state.scheduler.slab.get(id).deferred_debug.is_none());
            assert_eq!(state.scheduler.slab.get(id).user_context.rip, 0x4243);
            if let Some(index) = endpoint {
                assert_eq!(state.endpoints[index].head, Some(id));
                assert_eq!(state.endpoints[index].tail, Some(id));
                assert_eq!(state.scheduler.slab.get(id).ipc_label,
                    crate::fault::FaultMessage::DebugException {
                        fault_ip: 0, reason: 0, trigger_addr: 0, bp_num: 0,
                    }.type_word());
                assert_eq!(state.scheduler.slab.get(id).debug.dr[4], 0xffff_0ff1);
                assert!(crate::fault::apply_fault_reply(state, id, 0, 0, &[]));
                let thread = state.scheduler.slab.get_mut(id);
                assert_eq!(thread.debug.dr[4], 0xffff_0ff0, "only fault acknowledgement consumes status");
                debug::configure_single_stepping(&mut thread.debug, 1);
                let next_status = thread.debug.dr[4] | debug::DR6_SINGLE_STEP;
                defer_quiesced_debug(thread, UserEntryKind::Debug { status: next_status });
                assert_eq!(thread.deferred_debug.take().unwrap().reason, debug::SEL4_SINGLE_STEP,
                    "a later BS trap must not be mistaken for the acknowledged B0 event");
            } else {
                assert_eq!(state.scheduler.slab.get(id).state, crate::tcb::ThreadStateType::Inactive);
            }
            crate::invocation::retire_tcb(state, id);
            if let Some(index) = endpoint {
                assert_eq!(state.endpoints[index].head, None);
                assert_eq!(state.endpoints[index].tail, None);
            }
        }
        drop(owners);
    }
    crate::arch::log("  deferred debug events preserve trap identity and deliver exactly once\n");
}
