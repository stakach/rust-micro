#[derive(Clone, Copy)]
struct TcbCapUpdate {
    destination: MdbId,
    source: Option<(MdbId, Cap)>,
    cap: Cap,
    data: u64,
}

fn tcb_cap_error(code: seL4_Error) -> KException {
    KException::SyscallError(SyscallError::new(code))
}

fn prepare_tcb_cap(
    s: &KernelState, target: TcbId, slot: TcbSlot, source: Option<MdbId>, data: u64,
) -> KResult<TcbCapUpdate> {
    let destination = MdbId::tcb(target, slot);
    if s.cte(destination).is_none() {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
    }
    let source = if slot == TcbSlot::IpcBuffer && data == 0 { None } else { source };
    let Some(source) = source else {
        return Ok(TcbCapUpdate { destination, source: None, cap: Cap::Null, data: 0 });
    };
    // Public configuration derives from a real CSpace slot, never from an ambient cap snapshot.
    if source.tcb_slot().is_some() {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
    }
    let original = s.cte(source).ok_or_else(|| tcb_cap_error(seL4_Error::seL4_InvalidCapability))?.cap();
    let cap = match (slot, original) {
        (TcbSlot::CSpace, Cap::CNode { ptr, radix, guard_size, guard }) => {
            if s.cnode_slots_at(KernelState::cnode_index(ptr)).is_none() {
                return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
            }
            let (guard_size, guard) = if data == 0 {
                (guard_size, guard)
            } else {
                let guard_size = (data & 0x3f) as u8;
                if guard_size as u32 + radix as u32 > 64 {
                    return Err(tcb_cap_error(seL4_Error::seL4_RangeError));
                }
                let mask = if guard_size == 0 { 0 } else { (1u64 << guard_size) - 1 };
                (guard_size, (data >> 6) & mask)
            };
            Cap::CNode { ptr, radix, guard_size, guard }
        }
        (TcbSlot::VSpace, cap @ Cap::PML4 { .. }) if crate::asid::root_is_current(&cap) => cap,
        (TcbSlot::IpcBuffer, Cap::Frame { ptr, size, rights, is_device: false, .. }) => {
            if data & (crate::ipc_buffer::SIZE_BYTES as u64 - 1) != 0 {
                return Err(tcb_cap_error(seL4_Error::seL4_AlignmentError));
            }
            Cap::Frame { ptr, size, rights, is_device: false, mapped: None, asid: 0,
                map_type: crate::cap::FrameMapType::None }
        }
        (TcbSlot::FaultHandler | TcbSlot::Timeout, cap @ Cap::Endpoint { rights, .. })
            if rights.can_send && (rights.can_grant || rights.can_grant_reply) => cap,
        (TcbSlot::FaultHandler | TcbSlot::Timeout, Cap::Null) => Cap::Null,
        _ => return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability)),
    };
    let source = (!cap.is_null()).then_some((source, original));
    Ok(TcbCapUpdate { destination, source, cap, data })
}

unsafe fn commit_tcb_caps(s: &mut KernelState, updates: &[Option<TcbCapUpdate>]) -> KResult<()> {
    assert!(updates.len() <= TcbSlot::ALL.len());
    // Validate the complete batch before changing any old root or derivation edge.
    for (index, update) in updates.iter().enumerate() {
        let Some(update) = update else { continue; };
        if s.cte(update.destination).is_none()
            || updates[..index].iter().flatten().any(|old| old.destination == update.destination)
        {
            return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
        }
        let old = s.cte(update.destination).unwrap().cap();
        if !cnode_release_mappings_valid(s, &old, 1, 0) {
            return Err(tcb_cap_error(seL4_Error::seL4_IllegalOperation));
        }
        if let Some((source, expected)) = update.source {
            if s.cte(source).map(|slot| slot.cap()) != Some(expected) {
                return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
            }
            s.cte(source).unwrap().child_count().checked_add(updates.len() as u32)
                .ok_or_else(|| tcb_cap_error(seL4_Error::seL4_NotEnoughMemory))?;
        }
    }
    let mut retired = [Cap::Null; 5];
    if let Some(update) = updates.iter().flatten().next() {
        crate::smp::remote_tcb_stall(s, update.destination.tcb_slot().unwrap().0);
    }
    for (index, update) in updates.iter().enumerate() {
        let Some(update) = update else { continue; };
        let old = s.cte(update.destination).unwrap().cap();
        let old_parent = splice_cte_out(s, update.destination);
        finalise_cap_mapping(s, &old);
        if let Some((source, _)) = update.source {
            let parent = s.cte_mut(source).unwrap();
            parent.set_child_count(parent.child_count().checked_add(1).unwrap());
        }
        assert!(s.write_cte_cap(update.destination, &update.cap));
        let destination = s.cte_mut(update.destination).unwrap();
        destination.set_parent(update.source.map(|(source, _)| source));
        destination.set_child_count(0);
        destination.set_revoke_epoch(0);
        if let Some((target, TcbSlot::IpcBuffer)) = update.destination.tcb_slot() {
            s.scheduler.slab.get_mut(target).ipc_buffer = if update.cap.is_null() { 0 } else { update.data };
        }
        release_parent_edge(s, old_parent);
        retired[index] = old;
    }
    // Incoming roots are owned before releasing any old CSpace which may contain their sources.
    for cap in retired {
        maybe_free_object(s, &cap);
    }
    Ok(())
}

fn read_tcb_register_request<const N: usize>(
    invoker: &crate::tcb::Tcb, args: &SyscallArgs,
) -> KResult<([u64; N], usize)> {
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    if info.length() < 2 {
        return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
    }
    let buffer = invoker.ipc_buffer_send_paddr();
    if info.length() > crate::types::seL4_MsgMaxLength as u64
        || args.a3 > info.length() - 2
        || (args.a3 > 2 && buffer == 0)
    {
        return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
    }
    // seL4 accepts zero and ignores a fully supplied excess tail, but never reads past
    // the architecture context or the validated IPC message extent.
    let count = (args.a3 as usize).min(N);
    let mut registers = [0; N];
    if count > 0 {
        registers[0] = args.a4;
    }
    if count > 1 {
        registers[1] = args.a5;
    }
    // Only the first two context words are inline. Read the remainder from the retained
    // sender Frame, not an earlier invocation's longer scratch-register staging.
    for index in 2..count {
        registers[index] = unsafe {
            (crate::arch::phys_to_virt(buffer) as *const u64).add(index + 3).read_volatile()
        };
    }
    Ok((registers, count))
}

unsafe fn suspend_tcb(s: &mut KernelState, id: TcbId) {
    crate::smp::remote_tcb_stall(s, id);
    if let Some(node) = s.scheduler.slab.get(id).call_reply {
        // Cancellation severs the exact call chain; it must not reclaim an SC
        // still executing a downstream continuation.
        crate::reply::unlink(s, node);
    }
    crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, id);
    if let Some(sc_idx) = s.scheduler.slab.get(id).sc {
        if let Some(yielder) = s.sched_contexts[sc_idx as usize].yield_from {
            crate::sched_context::complete_yield_to(s, yielder, sc_idx as usize);
        }
    }
    s.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
}

/// Kernel bootstrap and fixtures use the same admitted-slot derivation path as TCB invocations.
pub(crate) unsafe fn derive_tcb_cap(
    s: &mut KernelState, target: TcbId, slot: TcbSlot, source: Option<MdbId>, data: u64,
) -> KResult<()> {
    let update = prepare_tcb_cap(s, target, slot, source, data)?;
    commit_tcb_caps(s, &[Some(update)])
}

fn tcb_source_cptr(s: &KernelState, invoker: TcbId, cptr: u64) -> KResult<MdbId> {
    let cspace = s.scheduler.slab.get(invoker).cspace_root();
    let (ci, si, _) = asid_cap_slot(s, &cspace, cptr, None)?;
    Ok(MdbId::pack(ci as u32, si as u32))
}

fn tcb_staged_source(s: &KernelState, invoker: TcbId, index: usize) -> KResult<MdbId> {
    let tcb = s.scheduler.slab.get(invoker);
    if index >= tcb.pending_extra_caps_count as usize {
        return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
    }
    let buffer = tcb.ipc_buffer_send_paddr();
    if buffer == 0 {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
    }
    let cptr = unsafe {
        (crate::arch::phys_to_virt(buffer) as *const u64)
            .add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET + index).read_volatile()
    };
    let source = tcb_source_cptr(s, invoker, cptr)?;
    if s.cte(source).unwrap().cap() != tcb.pending_extra_caps[index] {
        return Err(tcb_cap_error(seL4_Error::seL4_InvalidCapability));
    }
    Ok(source)
}

fn compact_fault_source(
    s: &KernelState, target: TcbId, cptr: u64, cspace_update: Option<TcbCapUpdate>,
) -> KResult<Option<MdbId>> {
    if cptr == 0 { return Ok(None); }
    // The project compressed ABI names a slot in the supplied target CSpace. Resolve it once
    // through that possessed CNode, then retain the real derived slot instead of a future lookup.
    let cspace = cspace_update.map(|update| update.cap)
        .unwrap_or_else(|| s.scheduler.slab.get(target).cspace_root());
    let (ci, si, _) = asid_cap_slot(s, &cspace, cptr, None)?;
    Ok(Some(MdbId::pack(ci as u32, si as u32)))
}

unsafe fn configure_tcb_caps(s: &mut KernelState, target: TcbId, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let upstream = info.extra_caps() != 0;
    let prepared = (|| -> KResult<[Option<TcbCapUpdate>; 3]> {
        if upstream {
            // MCS Configure has three words: CSpace data, VSpace data, IPC-buffer VA.
            if info.length() < 3 || info.extra_caps() < 3
                || s.scheduler.slab.get(invoker).pending_extra_caps_count < 3
            {
                return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
            }
            let cspace = tcb_staged_source(s, invoker, 0)?;
            let vspace = tcb_staged_source(s, invoker, 1)?;
            let buffer = if args.a4 == 0 { None } else { Some(tcb_staged_source(s, invoker, 2)?) };
            Ok([
                Some(prepare_tcb_cap(s, target, TcbSlot::CSpace, Some(cspace), args.a2)?),
                Some(prepare_tcb_cap(s, target, TcbSlot::VSpace, Some(vspace), args.a3)?),
                Some(prepare_tcb_cap(s, target, TcbSlot::IpcBuffer, buffer, args.a4)?),
            ])
        } else {
            let cspace = if args.a3 == 0 { None } else {
                Some(prepare_tcb_cap(s, target, TcbSlot::CSpace,
                    Some(tcb_source_cptr(s, invoker, args.a3)?), 0)?)
            };
            let vspace = if args.a4 == 0 { None } else {
                Some(prepare_tcb_cap(s, target, TcbSlot::VSpace,
                    Some(tcb_source_cptr(s, invoker, args.a4)?), 0)?)
            };
            let fault = compact_fault_source(s, target, args.a2, cspace)?;
            Ok([cspace, vspace, Some(prepare_tcb_cap(s, target, TcbSlot::FaultHandler, fault, 0)?)])
        }
    })();
    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
    commit_tcb_caps(s, &prepared?)?;
    if !upstream {
        if s.scheduler.slab.try_get(target).is_some() {
            let tcb = s.scheduler.slab.get_mut(target);
            tcb.priority = args.a5 as u8;
            let mcp = (args.a5 >> 8) as u8;
            if mcp != 0 { tcb.mcp = mcp; }
        }
    }
    Ok(())
}

unsafe fn set_tcb_space(s: &mut KernelState, target: TcbId, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let prepared = (|| -> KResult<[Option<TcbCapUpdate>; 3]> {
        if info.extra_caps() != 0 {
            if info.length() < 2 || info.extra_caps() < 3
                || s.scheduler.slab.get(invoker).pending_extra_caps_count < 3
            {
                return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
            }
            Ok([
                Some(prepare_tcb_cap(s, target, TcbSlot::FaultHandler,
                    Some(tcb_staged_source(s, invoker, 0)?), 0)?),
                Some(prepare_tcb_cap(s, target, TcbSlot::CSpace,
                    Some(tcb_staged_source(s, invoker, 1)?), args.a2)?),
                Some(prepare_tcb_cap(s, target, TcbSlot::VSpace,
                    Some(tcb_staged_source(s, invoker, 2)?), args.a3)?),
            ])
        } else {
            let cspace = if args.a3 == 0 { None } else {
                Some(prepare_tcb_cap(s, target, TcbSlot::CSpace,
                    Some(tcb_source_cptr(s, invoker, args.a3)?), 0)?)
            };
            let vspace = if args.a4 == 0 { None } else {
                Some(prepare_tcb_cap(s, target, TcbSlot::VSpace,
                    Some(tcb_source_cptr(s, invoker, args.a4)?), 0)?)
            };
            let fault = compact_fault_source(s, target, args.a2, cspace)?;
            Ok([cspace, vspace, Some(prepare_tcb_cap(s, target, TcbSlot::FaultHandler, fault, 0)?)])
        }
    })();
    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
    commit_tcb_caps(s, &prepared?)
}

unsafe fn set_tcb_ipc_buffer(s: &mut KernelState, target: TcbId, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let prepared = (|| -> KResult<TcbCapUpdate> {
        let upstream = info.extra_caps() != 0;
        if upstream && (info.length() < 1 || s.scheduler.slab.get(invoker).pending_extra_caps_count == 0) {
            return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
        }
        let source = if args.a2 == 0 { None } else if upstream {
            Some(tcb_staged_source(s, invoker, 0)?)
        } else {
            Some(tcb_source_cptr(s, invoker, args.a3)?)
        };
        prepare_tcb_cap(s, target, TcbSlot::IpcBuffer, source, args.a2)
    })();
    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
    commit_tcb_caps(s, &[Some(prepared?)])
}

unsafe fn set_tcb_timeout(s: &mut KernelState, target: TcbId, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let prepared = (|| -> KResult<TcbCapUpdate> {
        let source = if info.extra_caps() != 0 {
            Some(tcb_staged_source(s, invoker, 0)?)
        } else if args.a2 == 0 { None } else { Some(tcb_source_cptr(s, invoker, args.a2)?) };
        prepare_tcb_cap(s, target, TcbSlot::Timeout, source, 0)
    })();
    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
    commit_tcb_caps(s, &[Some(prepared?)])
}
