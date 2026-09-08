#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeferredDebugTrap {
    fault_ip: u64,
    reason: u64,
    trigger_addr: u64,
    bp_num: u64,
}

pub(crate) fn defer_quiesced_debug(tcb: &mut crate::tcb::Tcb, kind: crate::smp::UserEntryKind) {
    use crate::arch::aarch64::debug;
    let crate::smp::UserEntryKind::ArmDebug { esr, far } = kind else { return; };
    let (reason, trigger_addr, bp_num) = match esr >> 26 {
        class @ (0x30 | 0x34) => {
            let reason = if class == 0x30 { debug::SEL4_INSTRUCTION_BREAKPOINT }
                else { debug::SEL4_DATA_BREAKPOINT };
            let bp = debug::active_breakpoint(&tcb.debug, far, reason)
                .expect("observed ARM debug trap must match the captured debug configuration");
            (reason, far, bp as u64)
        }
        0x32 => {
            if !debug::single_step_counter_ready(&mut tcb.debug) { return; }
            (debug::SEL4_SINGLE_STEP, 0, 0)
        }
        0x3c => (debug::SEL4_SOFTWARE_BREAK_REQUEST, 0, 0),
        _ => panic!("invalid ARM debug exception class"),
    };
    assert!(tcb.deferred_debug.is_none(), "an undelivered debug event cannot be overwritten");
    tcb.deferred_debug = Some(DeferredDebugTrap {
        fault_ip: tcb.user_context.elr_el1, reason, trigger_addr, bp_num,
    });
}

pub(crate) fn deliver_deferred_debug(state: &mut crate::kernel::KernelState, id: crate::tcb::TcbId) -> bool {
    let Some(trap) = state.scheduler.slab.get_mut(id).deferred_debug.take() else { return false; };
    if crate::fault::deliver_fault_in(state, id, crate::fault::FaultMessage::DebugException {
        fault_ip: trap.fault_ip, reason: trap.reason, trigger_addr: trap.trigger_addr, bp_num: trap.bp_num,
    }).is_err() {
        state.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
    }
    true
}

pub(crate) fn debug_ready_thread(
    state: &mut crate::kernel::KernelState, mut candidate: Option<crate::tcb::TcbId>,
) -> Option<crate::tcb::TcbId> {
    while let Some(id) = candidate {
        if !deliver_deferred_debug(state, id) { return Some(id); }
        candidate = state.scheduler.choose_thread();
    }
    None
}

#[cfg(feature = "spec")]
fn test_deferred_debug() {
    use crate::arch::aarch64::debug;
    use crate::smp::UserEntryKind;
    let mut tcb = crate::tcb::Tcb::default();
    tcb.user_context.elr_el1 = 0x8004;
    defer_quiesced_debug(&mut tcb, UserEntryKind::ArmDebug { esr: 0x3c << 26, far: 0x8004 });
    assert_eq!(tcb.deferred_debug.take().unwrap().fault_ip, 0x8004);
    assert_eq!(tcb.user_context.elr_el1, 0x8004, "deferred BRK does not change the observed ELR");

    let bp = debug::SEL4_NUM_EXCLUSIVE_BREAKPOINTS;
    debug::set_breakpoint(&mut tcb.debug, bp, 0x1000, debug::SEL4_DATA_BREAKPOINT,
        8, debug::SEL4_BREAK_ON_READWRITE);
    defer_quiesced_debug(&mut tcb, UserEntryKind::ArmDebug { esr: 0x34 << 26, far: 0x1003 });
    debug::unset_breakpoint(&mut tcb.debug, bp);
    let trap = tcb.deferred_debug.take().unwrap();
    assert_eq!(trap.trigger_addr, 0x1003);
    assert_eq!(trap.bp_num, bp as u64);
    assert_eq!(trap.reason, debug::SEL4_DATA_BREAKPOINT);

    debug::configure_single_stepping(&mut tcb.debug, 2);
    defer_quiesced_debug(&mut tcb, UserEntryKind::ArmDebug { esr: 0x32 << 26, far: 0 });
    assert!(tcb.deferred_debug.is_none());
    defer_quiesced_debug(&mut tcb, UserEntryKind::ArmDebug { esr: 0x32 << 26, far: 0 });
    assert_eq!(tcb.deferred_debug.take().unwrap().reason, debug::SEL4_SINGLE_STEP);
    crate::arch::log("  deferred ARM debug events retain observed identity\n");
}
