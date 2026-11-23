/// A revoke may retire CNodes and TCBs that contain caps outside the MDB subtree. Plan those
/// finalizers before the first deletion, so a refused VT-d mapping never loses its owner.
struct RevokeProjection {
    cnode_removed: [u32; KernelState::cnode_pool_count()],
    cnode_self: [u32; KernelState::cnode_pool_count()],
    cnode_self_removed: [u32; KernelState::cnode_pool_count()],
    thread_removed: [u32; crate::tcb::MAX_TCBS],
    final_cnodes: [bool; KernelState::cnode_pool_count()],
    final_threads: [bool; crate::tcb::MAX_TCBS],
    retiring: bool,
}

impl RevokeProjection {
    const fn new() -> Self {
        Self {
            cnode_removed: [0; KernelState::cnode_pool_count()],
            cnode_self: [0; KernelState::cnode_pool_count()],
            cnode_self_removed: [0; KernelState::cnode_pool_count()],
            thread_removed: [0; crate::tcb::MAX_TCBS],
            final_cnodes: [false; KernelState::cnode_pool_count()],
            final_threads: [false; crate::tcb::MAX_TCBS],
            retiring: false,
        }
    }

    fn reset_counts(&mut self) {
        self.cnode_removed.fill(0);
        self.cnode_self.fill(0);
        self.cnode_self_removed.fill(0);
        self.thread_removed.fill(0);
    }

    fn reset(&mut self) {
        self.reset_counts();
        self.final_cnodes.fill(false);
        self.final_threads.fill(false);
    }
}

struct RevokeProjectionCell(core::cell::UnsafeCell<RevokeProjection>);
unsafe impl Sync for RevokeProjectionCell {}
static REVOKE_PROJECTION: RevokeProjectionCell =
    RevokeProjectionCell(core::cell::UnsafeCell::new(RevokeProjection::new()));

fn revoke_removes(id: MdbId, source: MdbId, source_removed: bool, epoch: u32, s: &KernelState) -> bool {
    (id != source || source_removed) && cte_revoke_marked(s, id, epoch)
}

/// Close the planned deletion set over the owned slots of every object whose last external
/// capability will disappear. The epoch lives in each CTE, so no slot-sized side array is needed.
unsafe fn project_revoke_finalizers(
    s: &mut KernelState, source: MdbId, epoch: u32, initially_removed: bool,
) -> bool {
    let plan = &mut *REVOKE_PROJECTION.0.get();
    plan.reset();
    let mut source_removed = initially_removed;
    loop {
        plan.reset_counts();
        let mut cursor = CteCursor::new();
        while let Some(id) = cursor.next(s) {
            let Some(cap) = s.cte(id).map(|slot| slot.cap()) else { continue };
            let removed = revoke_removes(id, source, source_removed, epoch, s);
            match cap {
                Cap::CNode { ptr, .. } => {
                    let vi = KernelState::cnode_index(ptr);
                    if vi >= plan.cnode_removed.len() { continue; }
                    let self_ref = id.tcb_slot().is_none() && id.cnode_idx() as usize == vi;
                    plan.cnode_self[vi] += u32::from(self_ref);
                    if removed {
                        plan.cnode_removed[vi] += 1;
                        plan.cnode_self_removed[vi] += u32::from(self_ref);
                    }
                }
                Cap::Thread { tcb } => {
                    let ti = tcb.addr() as usize;
                    if removed && ti < plan.thread_removed.len() { plan.thread_removed[ti] += 1; }
                }
                _ => {}
            }
        }
        let mut changed = false;
        let mut cursor = CteCursor::new();
        while let Some(id) = cursor.next(s) {
            if !revoke_removes(id, source, source_removed, epoch, s) { continue; }
            match s.cte(id).unwrap().cap() {
                Cap::CNode { ptr, .. } => {
                    let vi = KernelState::cnode_index(ptr);
                    if vi >= plan.final_cnodes.len() || plan.final_cnodes[vi] { continue; }
                    let remaining = crate::kernel::cap_refcount(&s.cte(id).unwrap().cap())
                        .checked_sub(plan.cnode_removed[vi]);
                    let remaining_self = plan.cnode_self[vi]
                        .checked_sub(plan.cnode_self_removed[vi]);
                    if remaining.is_none() || remaining != remaining_self { continue; }
                    let Some(slots) = s.cnode_slots_at(vi) else { continue };
                    let count = slots.len();
                    plan.final_cnodes[vi] = true;
                    changed = true;
                    for si in 0..count {
                        s.cnode_slot_mut(vi, si).unwrap().set_revoke_epoch(epoch);
                    }
                    if source.tcb_slot().is_none() && source.cnode_idx() as usize == vi {
                        source_removed = true;
                    }
                }
                Cap::Thread { tcb } => {
                    let ti = tcb.addr() as usize;
                    if ti >= plan.final_threads.len() || plan.final_threads[ti] { continue; }
                    if crate::kernel::thread_cap_refcount(TcbId(ti as u16))
                        != plan.thread_removed[ti] { continue; }
                    plan.final_threads[ti] = true;
                    changed = true;
                    for slot in crate::cte::TcbSlot::ALL {
                        if let Some(entry) = s.cte_mut(MdbId::tcb(TcbId(ti as u16), slot)) {
                            entry.set_revoke_epoch(epoch);
                        }
                    }
                    if source.tcb_slot().is_some_and(|(thread, _)| thread.0 as usize == ti) {
                        source_removed = true;
                    }
                }
                _ => {}
            }
        }
        if !changed { break; }
    }
    source_removed
}

unsafe fn projected_cnode_finalizes(vi: usize) -> bool {
    (*REVOKE_PROJECTION.0.get()).final_cnodes.get(vi).copied().unwrap_or(false)
}

unsafe fn revoke_retirement_active() -> bool {
    (*REVOKE_PROJECTION.0.get()).retiring
}

unsafe fn set_revoke_retirement_active(active: bool) {
    (*REVOKE_PROJECTION.0.get()).retiring = active;
}

/// Always clears the BKL-scoped retirement state, including a no-effect preflight refusal.
struct RevokeRetirementReset;

impl Drop for RevokeRetirementReset {
    fn drop(&mut self) {
        unsafe { set_revoke_retirement_active(false); }
    }
}

/// Deleting the last externally held CNode or Thread cap invokes a finalizer that owns further
/// CTEs. Admit the complete finalizer closure while that outer cap is still reachable.
unsafe fn direct_finalizer_is_last(s: &KernelState, id: MdbId, cap: &Cap) -> bool {
    match *cap {
        Cap::CNode { ptr, .. } => {
            let vi = KernelState::cnode_index(ptr);
            let Some(slots) = s.cnode_slots_at(vi) else { return false };
            let self_refs = slots.iter().filter(|slot| matches!(slot.cap(),
                Cap::CNode { ptr: inner, .. } if inner.addr() == ptr.addr())).count() as u32;
            let self_cap = id.tcb_slot().is_none() && id.cnode_idx() as usize == vi;
            matches!(
                (crate::kernel::cap_refcount(cap).checked_sub(1),
                    self_refs.checked_sub(u32::from(self_cap))),
                (Some(remaining), Some(remaining_self)) if remaining == remaining_self
            )
        }
        Cap::Thread { tcb } => crate::kernel::thread_cap_refcount(TcbId(tcb.addr() as u16)) == 1,
        _ => false,
    }
}

fn has_dma_mapping(cap: Cap) -> bool {
    matches!(cap,
        Cap::Frame { mapped: Some(_), map_type: crate::cap::FrameMapType::IoSpace, .. }
        | Cap::IoPageTable { is_mapped: true, .. })
}

/// A common Thread teardown owns only an ordinary CSpace cap and endpoint slots. Avoid a
/// registry-wide projection unless its finalizer can reach a DMA mapping. A nested Thread cap is
/// conservatively admitted to the full plan, which then decides whether that TCB really retires.
unsafe fn direct_finalizer_may_own_dma(s: &KernelState, cap: &Cap) -> bool {
    let work = cnode_worklist();
    match *cap {
        Cap::CNode { ptr, .. } => {
            if !work.push(KernelState::cnode_index(ptr)) { return true; }
        }
        Cap::Thread { tcb } => {
            let thread = TcbId(tcb.addr() as u16);
            for slot in crate::cte::TcbSlot::ALL {
                let inner_id = MdbId::tcb(thread, slot);
                let Some(inner) = s.cte(inner_id).map(|entry| entry.cap()) else { continue };
                if has_dma_mapping(inner) { return true; }
                if let Cap::CNode { ptr, .. } = inner {
                    if direct_finalizer_is_last(s, inner_id, &inner) {
                        if !work.push(KernelState::cnode_index(ptr)) { return true; }
                    }
                }
            }
        }
        _ => return false,
    }
    while let Some(vi) = work.pop() {
        let Some(slots) = s.cnode_slots_at(vi) else { return true };
        for slot in slots {
            let inner = slot.cap();
            if has_dma_mapping(inner) || matches!(inner, Cap::Thread { .. }) { return true; }
            if let Cap::CNode { ptr, .. } = inner {
                if !work.push(KernelState::cnode_index(ptr)) { return true; }
            }
        }
    }
    false
}

unsafe fn preflight_direct_finalizer(s: &mut KernelState, id: MdbId) -> KResult<()> {
    let epoch = begin_revoke_epoch(s);
    s.cte_mut(id).unwrap().set_revoke_epoch(epoch);
    project_revoke_finalizers(s, id, epoch, true);
    let mut cursor = CteCursor::new();
    while let Some(slot_id) = cursor.next(s) {
        if !cte_revoke_marked(s, slot_id, epoch) { continue; }
        let cap = s.cte(slot_id).unwrap().cap();
        if let Cap::CNode { ptr, .. } = cap {
            let vi = KernelState::cnode_index(ptr);
            let valid = if projected_cnode_finalizes(vi) {
                cnode_tree_registered(s, &cap)
            } else {
                let (refs, self_refs) = revoke_cnode_clear_counts(s, vi, epoch, id, true);
                cnode_release_mappings_valid(s, &cap, refs, self_refs)
            };
            if !valid { return Err(revoke_error(seL4_Error::seL4_IllegalOperation)); }
        }
    }
    preflight_revoke_dma(s, id, true, epoch)?;
    // Finalizers can be nested and CSpace order does not describe the VT-d page-table tree.
    // Retire every projected mapping while the outer owner is still present, leaves first.
    let levels = crate::arch::x86_64::iommu::num_iopt_levels() as u8;
    set_revoke_retirement_active(true);
    for phase in 0..=levels {
        let mut cursor = CteCursor::new();
        while let Some(slot_id) = cursor.next(s) {
            if slot_id == id || !cte_revoke_marked(s, slot_id, epoch) { continue; }
            let selected = match s.cte(slot_id).unwrap().cap() {
                Cap::Frame { mapped: Some(_), map_type: crate::cap::FrameMapType::IoSpace, .. } =>
                    crate::arch::x86_64::iommu::dma_retirement_phase(
                        crate::arch::x86_64::iommu::DmaRetirementKind::Frame, levels) == Some(phase),
                Cap::IoPageTable { is_mapped: true, level, .. } =>
                    crate::arch::x86_64::iommu::dma_retirement_phase(
                        crate::arch::x86_64::iommu::DmaRetirementKind::Table(level), levels) == Some(phase),
                _ => false,
            };
            if selected {
                delete_cap_slot(s, slot_id)
                    .expect("prevalidated nested DMA cap remains finalizable under BKL");
            }
        }
    }
    Ok(())
}

fn revoke_error(code: seL4_Error) -> KException {
    KException::SyscallError(SyscallError::new(code))
}

unsafe fn preflight_revoke_dma(
    s: &KernelState, source: MdbId, source_removed: bool, epoch: u32,
) -> KResult<()> {
    use crate::arch::x86_64::iommu;
    let mut cursor = CteCursor::new();
    while let Some(id) = cursor.next(s) {
        if !revoke_removes(id, source, source_removed, epoch, s) { continue; }
        let Some(cap) = s.cte(id).map(|slot| slot.cap()) else { continue };
        match cap {
            Cap::Frame { ptr, mapped: Some(address), asid,
                map_type: crate::cap::FrameMapType::IoSpace, .. } => {
                let ctx = iommu::lookup_vtd_context_slot(asid, false)
                    .filter(|ctx| ctx.present())
                    .ok_or_else(|| revoke_error(seL4_Error::seL4_InvalidCapability))?;
                let lu = iommu::lookup_iopt_slot(ctx.asr(), address);
                if !lu.ok || lu.level != 0 || iommu::slot_addr(lu.slot) != ptr.addr() {
                    return Err(revoke_error(seL4_Error::seL4_InvalidCapability));
                }
            }
            Cap::IoPageTable { ptr, is_mapped: true, level, mapped_address, ioasid } => {
                // Another live mapped alias keeps the hardware mapping after this revoke.
                let mut external_alias = false;
                let mut descendants_outside = false;
                let mut other = CteCursor::new();
                while let Some(other_id) = other.next(s) {
                    if revoke_removes(other_id, source, source_removed, epoch, s) { continue; }
                    let Some(other_cap) = s.cte(other_id).map(|slot| slot.cap()) else { continue };
                    match other_cap {
                        Cap::IoPageTable { ptr: alias, is_mapped: true, ioasid: rid, .. }
                            if alias.addr() == ptr.addr() && rid == ioasid => external_alias = true,
                        Cap::Frame { mapped: Some(address), asid: rid,
                            map_type: crate::cap::FrameMapType::IoSpace, .. }
                            if rid == ioasid && iommu::iopt_contains_address(level, mapped_address, address) =>
                                descendants_outside = true,
                        Cap::IoPageTable { ptr: child, is_mapped: true, level: child_level,
                            mapped_address: child_address, ioasid: rid }
                            if rid == ioasid && child.addr() != ptr.addr() && child_level > level
                                && iommu::iopt_contains_address(level, mapped_address, child_address) =>
                                    descendants_outside = true,
                        _ => {}
                    }
                }
                if external_alias { continue; }
                if descendants_outside { return Err(revoke_error(seL4_Error::seL4_DeleteFirst)); }
                let ctx = iommu::lookup_vtd_context_slot(ioasid, false)
                    .filter(|ctx| ctx.present())
                    .ok_or_else(|| revoke_error(seL4_Error::seL4_InvalidCapability))?;
                let top = ctx.asr();
                let owned = if level == 0 { top == ptr.addr() } else {
                    let lu = iommu::lookup_iopt_slot_levels(top,
                        mapped_address >> iommu::PAGE_BITS, (level - 1) as u64,
                        (level - 1) as u64);
                    lu.ok && lu.level == 0 && iommu::slot_addr(lu.slot) == ptr.addr()
                };
                if !owned { return Err(revoke_error(seL4_Error::seL4_InvalidCapability)); }
            }
            _ => {}
        }
    }
    Ok(())
}
