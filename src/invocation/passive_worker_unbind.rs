use super::*;
use crate::endpoint::EpState;
use crate::reply::{Reply, ReplyNode};
use crate::tcb::ThreadStateType;

fn error(code: seL4_Error) -> KException {
    KException::SyscallError(SyscallError::new(code))
}

/// Retire only the bootstrap SC of a worker on its first, private receive.
/// All physical owners are checked under the invocation lock before the SC or
/// scheduler is touched. The Endpoint queue and offered Reply stay live for
/// the root's first Call and its normal scheduling-context donation.
pub(super) fn invoke(
    s: &mut KernelState,
    sc_index: usize,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    const _: () = assert!(InvocationLabel::SchedContextUnbindPassiveWorker as u64 == 77);
    if args.a1 != (((InvocationLabel::SchedContextUnbindPassiveWorker as u64) << 12) | 3)
        || s.scheduler.slab.get(invoker).pending_extra_caps_count != 0
    {
        return Err(error(seL4_Error::seL4_InvalidArgument));
    }

    let sc_id = u16::try_from(sc_index)
        .map_err(|_| error(seL4_Error::seL4_InvalidCapability))?;
    let sc = s.sched_contexts
        .get(sc_index)
        .ok_or_else(|| error(seL4_Error::seL4_InvalidCapability))?;
    let root = s.scheduler.slab.get(invoker).cspace_root();
    let worker = match lookup_cap(s, &root, args.a2)? {
        Cap::Thread { tcb } => u16::try_from(tcb.addr())
            .ok()
            .map(TcbId)
            .filter(|id| s.scheduler.slab.try_get(*id).is_some())
            .ok_or_else(|| error(seL4_Error::seL4_InvalidCapability))?,
        _ => return Err(error(seL4_Error::seL4_InvalidCapability)),
    };
    let endpoint_index = match lookup_cap(s, &root, args.a3)? {
        Cap::Endpoint { ptr, rights, .. } if rights.can_receive =>
            KernelState::endpoint_index(ptr),
        _ => return Err(error(seL4_Error::seL4_InvalidCapability)),
    };
    let endpoint = s.endpoints
        .get(endpoint_index)
        .ok_or_else(|| error(seL4_Error::seL4_InvalidCapability))?;
    let reply_index = match lookup_cap(s, &root, args.a4)? {
        Cap::Reply { ptr, .. } => KernelState::reply_index(ptr),
        _ => return Err(error(seL4_Error::seL4_InvalidCapability)),
    };
    let reply_id = u16::try_from(reply_index)
        .map_err(|_| error(seL4_Error::seL4_InvalidCapability))?;
    let reply = s.replies
        .get(reply_index)
        .ok_or_else(|| error(seL4_Error::seL4_InvalidCapability))?;
    let tcb = s.scheduler.slab.get(worker);
    let invalid = || error(seL4_Error::seL4_IllegalOperation);

    let fresh_sc = sc.bound_tcb == Some(worker)
        && sc.reply_head.is_none()
        && sc.yield_from.is_none()
        && !s.notifications.iter().any(|n| n.bound_sc == Some(sc_id));
    let blocked_worker = worker != invoker
        && tcb.sc == Some(sc_id)
        && tcb.state == ThreadStateType::BlockedOnReceive
        && !tcb.enqueued
        && tcb.ep_prev.is_none()
        && tcb.ep_next.is_none()
        && tcb.pending_reply == Some(reply_id)
        && tcb.active_sc.is_none()
        && tcb.donated_sc.is_none()
        && tcb.reply_to.is_none()
        && tcb.call_reply.is_none()
        && tcb.composite_reply_handoff.is_none()
        && tcb.legacy_reply == Reply::new()
        && !tcb.execution_held()
        && tcb.bound_notification.is_none()
        && tcb.pending_fault == 0;
    let sole_receiver = endpoint.state == EpState::Recv
        && endpoint.head == Some(worker)
        && endpoint.tail == Some(worker);
    let exact_offer = reply.offered_tcb == Some(worker)
        && reply.bound_tcb.is_none()
        && reply.prev.is_none()
        && reply.next.is_none();
    let no_other_owner = !s.scheduler.nodes.iter().any(|n| {
        n.current == Some(worker)
            || n.active_user == Some(worker)
            || n.direct_handoff == Some(worker)
    }) && !s.scheduler.slab.entries.iter().enumerate().any(|(index, entry)| {
        let Some(other) = entry else { return false; };
        index != worker.0 as usize
            && (other.sc == Some(sc_id)
                || other.active_sc == Some(sc_id)
                || other.donated_sc == Some(sc_id)
                || other.pending_reply == Some(reply_id)
                || other.call_reply == Some(ReplyNode::Object(reply_id))
                || other.reply_to == Some(worker))
    });
    if !(fresh_sc && blocked_worker && sole_receiver && exact_offer && no_other_owner) {
        return Err(invalid());
    }

    crate::smp::remote_tcb_stall(s, worker);
    s.scheduler.on_sc_lost(worker);
    s.scheduler.slab.get_mut(worker).sc = None;
    s.sched_contexts[sc_index].bound_tcb = None;
    let response = s.scheduler.slab.get_mut(invoker);
    response.ipc_label = 0;
    response.ipc_length = 0;
    Ok(())
}
