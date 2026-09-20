use super::*;

pub(super) fn invoke(
    s: &mut KernelState,
    target: u64,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    #[cfg(target_arch = "x86_64")]
    const _: () = assert!(InvocationLabel::TCBQueryReplyBinding as u64 == 73);
    if args.a1 != (((InvocationLabel::TCBQueryReplyBinding as u64) << 12) | 1) {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidArgument));
    }
    let target = u16::try_from(target)
        .ok()
        .map(TcbId)
        .filter(|id| s.scheduler.slab.try_get(*id).is_some())
        .ok_or_else(|| tcb_cap_error(seL4_Error::seL4_InvalidCapability))?;
    let root = s.scheduler.slab.get(invoker).cspace_root();
    let Cap::Reply { ptr, .. } = lookup_cap(s, &root, args.a2)? else {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
    };
    let index = KernelState::reply_index(ptr);
    let reply = s
        .replies
        .get(index)
        .ok_or_else(|| tcb_cap_error(seL4_Error::seL4_InvalidCapability))?;
    let invalid = || tcb_cap_error(seL4_Error::seL4_IllegalOperation);
    let state = if *reply == crate::reply::Reply::new() {
        0
    } else if let Some(receiver) = reply.offered_tcb {
        if reply.bound_tcb.is_some()
            || reply.prev.is_some()
            || reply.next.is_some()
            || !s
                .scheduler
                .slab
                .try_get(receiver)
                .is_some_and(|tcb| tcb.pending_reply == Some(index as u16))
        {
            return Err(invalid());
        }
        1
    } else {
        let caller = crate::reply::caller(s, crate::reply::ReplyNode::Object(index as u16))
            .ok_or_else(invalid)?;
        if caller == target {
            2
        } else {
            3
        }
    };
    let response = s.scheduler.slab.get_mut(invoker);
    response.ipc_label = 0;
    response.ipc_length = 1;
    response.msg_regs[0] = state;
    Ok(())
}
