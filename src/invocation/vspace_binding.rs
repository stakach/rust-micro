use super::*;

/// A serialized observation, not a pin, execution hold or transferable authorization token.
pub(super) fn invoke(
    s: &mut KernelState,
    target: u64,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    #[cfg(target_arch = "x86_64")]
    const _: () = assert!(InvocationLabel::TCBQueryVSpaceBinding as u64 == 74);
    if args.a1 != (((InvocationLabel::TCBQueryVSpaceBinding as u64) << 12) | 2) {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidArgument));
    }
    let target = u16::try_from(target)
        .ok()
        .map(TcbId)
        .filter(|id| s.scheduler.slab.try_get(*id).is_some())
        .ok_or_else(|| tcb_cap_error(seL4_Error::seL4_InvalidCapability))?;
    let cspace = s.scheduler.slab.get(invoker).cspace_root();
    let expected = lookup_cap(s, &cspace, args.a2)?;
    let provider = lookup_cap(s, &cspace, args.a3)?;
    if !matches!(expected, Cap::PML4 { .. }) || !matches!(provider, Cap::PML4 { .. }) {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
    }
    let actual = s.scheduler.slab.get(target).vspace_root();
    let matches_separate = crate::asid::root_is_current(&actual)
        && crate::asid::root_is_current(&expected)
        && crate::asid::root_is_current(&provider)
        && matches!((actual, expected, provider),
            (Cap::PML4 { ptr: actual, asid: actual_asid, .. },
             Cap::PML4 { ptr: expected, asid: expected_asid, .. },
             Cap::PML4 { ptr: provider, .. })
                if actual == expected && actual_asid == expected_asid && actual != provider);
    let response = s.scheduler.slab.get_mut(invoker);
    response.ipc_label = 0;
    response.ipc_length = 1;
    response.msg_regs[0] = u64::from(matches_separate);
    Ok(())
}
