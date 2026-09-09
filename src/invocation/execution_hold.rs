use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

static LAST_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(super) fn reserve_generation(last: &AtomicU64) -> Option<u64> {
    last.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        old.checked_add(1)
    })
    .ok()
    .map(|old| old + 1)
}

pub(super) fn invoke(
    s: &mut KernelState,
    target: TcbId,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    #[cfg(target_arch = "x86_64")]
    const _: () = assert!(InvocationLabel::TCBAcquireExecutionHold as u64 == 71);
    #[cfg(target_arch = "x86_64")]
    const _: () = assert!(InvocationLabel::TCBReleaseExecutionHold as u64 == 72);
    let acquire = label == InvocationLabel::TCBAcquireExecutionHold;
    let words = if acquire { 0 } else { 1 };
    if args.a1 != (((label as u64) << 12) | words) {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidArgument));
    }
    if acquire {
        if s.scheduler.slab.get(target).execution_held() {
            return Err(tcb_cap_error(seL4_Error::seL4_DeleteFirst));
        }
        let generation = reserve_generation(&LAST_GENERATION)
            .ok_or_else(|| tcb_cap_error(seL4_Error::seL4_NotEnoughMemory))?;
        unsafe {
            crate::smp::remote_tcb_stall(s, target);
        }
        s.scheduler.slab.get_mut(target).execution_hold = generation;
        // This withdraws only execution references, not IPC queues, state, SC or context.
        s.scheduler.on_sc_lost(target);
        let caller = s.scheduler.slab.get_mut(invoker);
        caller.ipc_label = 0;
        caller.ipc_length = 1;
        caller.msg_regs[0] = generation;
    } else {
        if args.a2 == 0 || s.scheduler.slab.get(target).execution_hold != args.a2 {
            return Err(tcb_cap_error(seL4_Error::seL4_InvalidArgument));
        }
        s.scheduler.slab.get_mut(target).execution_hold = 0;
        s.scheduler.on_sc_gained(target);
        let caller = s.scheduler.slab.get_mut(invoker);
        caller.ipc_label = 0;
        caller.ipc_length = 0;
    }
    Ok(())
}
