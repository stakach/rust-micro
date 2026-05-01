//! Phase 16 — invocation dispatcher.
//!
//! Mirrors `seL4/src/object/objecttype.c::decodeInvocation`. When
//! a `SysSend` / `SysCall` lands on a non-Endpoint cap, this is
//! where we go to dispatch on the cap type + invocation label.
//!
//! Each cap type owns the decoding of its own invocation methods.
//! For now we wire up:
//!   * `Cap::Untyped`   → UntypedRetype (the allocator)
//!   * `Cap::CNode`     → Copy / Mint / Move / Mutate / Delete
//!   * `Cap::Thread`    → Suspend / Resume / SetPriority
//!
//! Invocation label decoding follows seL4's convention: the first
//! word of the IPC MessageInfo carries the label in its high bits.
//! We expose helpers on the generated `InvocationLabel` enum.

use crate::cap::{Cap, CNodeStorage, PPtr};
use crate::cspace::lookup_cap;
use crate::cte::Cte;
use crate::error::{KException, KResult, SyscallError};
use crate::kernel::{KernelState, KERNEL};
use crate::object_type::ObjectType;
use crate::syscall_handler::SyscallArgs;
use crate::syscalls::InvocationLabel;
use crate::tcb::TcbId;
use crate::types::{seL4_Error, seL4_Word as Word};

/// Decode an invocation against a non-Endpoint cap. Called from
/// the IPC dispatcher when SysSend/SysCall targets a non-IPC cap.
pub fn decode_invocation(
    target: Cap,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    // Decode the invocation label from MessageInfo.
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let label = info.label();
    let label = InvocationLabel::from_u64(label).ok_or_else(|| {
        KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidArgument,
        ))
    })?;
    match target {
        Cap::Untyped { .. } => decode_untyped(target, label, args, invoker),
        Cap::CNode { .. } => decode_cnode(target, label, args, invoker),
        Cap::Thread { .. } => decode_tcb(target, label, args, invoker),
        Cap::IrqControl => decode_irq_control(label, args, invoker),
        Cap::IrqHandler { irq } => decode_irq_handler(irq, label, args, invoker),
        Cap::Frame { .. } => decode_frame(target, label, args, invoker),
        Cap::PageTable { .. } => decode_page_table(target, label, args, invoker),
        Cap::PageDirectory { .. } => decode_page_directory(target, label, args, invoker),
        Cap::Pdpt { .. } => decode_pdpt(target, label, args, invoker),
        Cap::AsidControl => decode_asid_control(label, args, invoker),
        Cap::AsidPool { .. } => decode_asid_pool(target, label, args, invoker),
        Cap::SchedContext { .. } => decode_sched_context(target, label, args, invoker),
        Cap::SchedControl { .. } => decode_sched_control(label, args, invoker),
        Cap::Null => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidCapability,
        ))),
        // Other cap types not yet wired — surface InvalidCapability
        // so user code spots the gap rather than silently no-op.
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

// ---------------------------------------------------------------------------
// Frame invocations (Phase 19).
// ---------------------------------------------------------------------------

fn decode_frame(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::X86PageMap => decode_frame_map(target, args, invoker),
        InvocationLabel::X86PageUnmap => decode_frame_unmap(target, args, invoker),
        InvocationLabel::X86PageGetAddress => decode_frame_get_address(target, args, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// `X86Page::Map(vspace, vaddr, rights)` — install the frame at
/// `vaddr` in the invoker's vspace. We only handle 4 KiB pages
/// today; large/huge fall through with InvalidArgument.
///
/// ABI: a2 = vaddr, a3 = rights word (FrameRights encoding).
fn decode_frame_map(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    use crate::arch::x86_64::usermode;
    let (paddr, size, _device, current_mapped) = match target {
        Cap::Frame { ptr, size, is_device, mapped, .. } => (ptr.addr(), size, is_device, mapped),
        _ => unreachable!(),
    };
    if !matches!(size, crate::cap::FrameSize::Small) {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidArgument,
        )));
    }
    if current_mapped.is_some() {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_DeleteFirst,
        )));
    }
    let vaddr = args.a2;
    let rights = crate::cap::FrameRights::from_word(args.a3);
    let writable = matches!(rights, crate::cap::FrameRights::ReadWrite);

    if vaddr & 0xFFF != 0 {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_AlignmentError,
        )));
    }

    // Install via the same low-level page-table helper userspace
    // pages use. We don't have per-thread CR3 yet so this maps
    // into the shared kernel page tables — fine for the demo.
    unsafe {
        usermode::map_user_4k_public(vaddr, paddr, writable);
    }

    // Update the cap to reflect the mapping. We need to find the
    // source slot that holds this Frame cap and rewrite it. Walk
    // the invoker's CSpace.
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let cnode_ptr = match cspace_root {
            Cap::CNode { ptr, .. } => ptr,
            _ => return Ok(()),
        };
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        for slot in s.cnodes[cnode_idx].0.iter_mut() {
            if let Cap::Frame { ptr, .. } = slot.cap() {
                if ptr.addr() == paddr {
                    let updated = Cap::Frame {
                        ptr,
                        size,
                        rights,
                        mapped: Some(vaddr),
                        asid: 0,
                        is_device: _device,
                    };
                    slot.set_cap(&updated);
                    break;
                }
            }
        }
    }
    Ok(())
}

fn decode_frame_unmap(target: Cap, _args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let (paddr, mapped_vaddr) = match target {
        Cap::Frame { ptr, mapped, .. } => (ptr.addr(), mapped),
        _ => unreachable!(),
    };

    // Phase 28g — actually clear the PTE in the live page tables
    // and fan a TLB shootdown to other CPUs. Outside spec mode the
    // cap chain backs real mappings; spec mode synthesizes caps
    // without a populated PML4, so we skip the hardware step there.
    #[cfg(all(not(feature = "spec"), target_arch = "x86_64"))]
    if let Some(vaddr) = mapped_vaddr {
        unsafe {
            crate::arch::x86_64::usermode::unmap_user_4k_public(vaddr);
            crate::smp::shootdown_tlb(vaddr);
        }
    }
    #[cfg(any(feature = "spec", not(target_arch = "x86_64")))]
    let _ = mapped_vaddr;

    // Walk the CSpace and zero the mapping in the matching cap.
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let cnode_ptr = match cspace_root {
            Cap::CNode { ptr, .. } => ptr,
            _ => return Ok(()),
        };
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        for slot in s.cnodes[cnode_idx].0.iter_mut() {
            if let Cap::Frame { ptr, size, rights, is_device, .. } = slot.cap() {
                if ptr.addr() == paddr {
                    slot.set_cap(&Cap::Frame {
                        ptr,
                        size,
                        rights,
                        mapped: None,
                        asid: 0,
                        is_device,
                    });
                    break;
                }
            }
        }
    }
    Ok(())
}

/// `X86Page::GetAddress` — return the frame's physical address in
/// the caller's `msg_regs[0]`. The syscall return path fans this
/// out to user-mode `rdx` (Phase 15a).
fn decode_frame_get_address(
    target: Cap,
    _args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    let paddr = match target {
        Cap::Frame { ptr, .. } => ptr.addr(),
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let tcb = s.scheduler.slab.get_mut(invoker);
        tcb.msg_regs[0] = paddr;
        tcb.ipc_length = 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 26 — PT / PD / PDPT invocations.
//
// Each Map(vaddr) installs the cap into the parent paging structure
// at the matching index in the *invoker's vspace* (today: live CR3).
// Unmap clears the mapped flag in the cap; we don't yet tear down
// the hardware entry — the slot will get overwritten when the cap is
// re-mapped or freed.
//
// Layering reminder:
//   Cap::Pdpt        Map → installs at PML4[idx]   level=3
//   Cap::PageDirectory Map → installs at PDPT[idx] level=2
//   Cap::PageTable   Map → installs at PD[idx]     level=1
// ---------------------------------------------------------------------------

fn decode_page_table(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::X86PageTableMap => decode_pt_map(target, args, invoker),
        InvocationLabel::X86PageTableUnmap => decode_pt_unmap(target, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

fn decode_page_directory(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::X86PageDirectoryMap => decode_pd_map(target, args, invoker),
        InvocationLabel::X86PageDirectoryUnmap => decode_pd_unmap(target, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

fn decode_pdpt(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::X86PDPTMap => decode_pdpt_map(target, args, invoker),
        InvocationLabel::X86PDPTUnmap => decode_pdpt_unmap(target, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// Common shape: write a paging-structure cap into the parent table
/// at the appropriate level, then update the source slot's cap to
/// record the mapped vaddr.
fn map_paging_struct(
    target: Cap,
    args: &SyscallArgs,
    invoker: TcbId,
    level: u32,
) -> KResult<()> {
    use crate::arch::x86_64::usermode;
    let (paddr, current_mapped) = paging_struct_state(&target);
    if current_mapped.is_some() {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_DeleteFirst,
        )));
    }
    let vaddr = args.a2;
    if vaddr & 0xFFF != 0 {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_AlignmentError,
        )));
    }

    // Outside spec mode, install the entry into the live PML4.
    // Spec mode runs without a real page-table tree, so we skip
    // the hardware install and only update the cap shadow.
    #[cfg(not(feature = "spec"))]
    {
        let installed = unsafe { usermode::install_user_table(level, vaddr, paddr) };
        if !installed {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
    }
    #[cfg(feature = "spec")]
    let _ = (level, usermode::install_user_table); // silence unused-function warning under spec

    rewrite_paging_cap_in_cspace(invoker, &target, Some(vaddr));
    Ok(())
}

fn unmap_paging_struct(target: Cap, invoker: TcbId) -> KResult<()> {
    rewrite_paging_cap_in_cspace(invoker, &target, None);
    Ok(())
}

fn paging_struct_state(cap: &Cap) -> (u64, Option<u64>) {
    match *cap {
        Cap::PageTable { ptr, mapped, .. } => (ptr.addr(), mapped),
        Cap::PageDirectory { ptr, mapped, .. } => (ptr.addr(), mapped),
        Cap::Pdpt { ptr, mapped, .. } => (ptr.addr(), mapped),
        _ => unreachable!(),
    }
}

fn rewrite_paging_cap_in_cspace(invoker: TcbId, cap: &Cap, new_mapped: Option<u64>) {
    let target_paddr = paging_struct_state(cap).0;
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let cnode_ptr = match cspace_root {
            Cap::CNode { ptr, .. } => ptr,
            _ => return,
        };
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        for slot in s.cnodes[cnode_idx].0.iter_mut() {
            let updated = match slot.cap() {
                Cap::PageTable { ptr, asid, .. } if ptr.addr() == target_paddr => {
                    Some(Cap::PageTable { ptr, mapped: new_mapped, asid })
                }
                Cap::PageDirectory { ptr, asid, .. } if ptr.addr() == target_paddr => {
                    Some(Cap::PageDirectory { ptr, mapped: new_mapped, asid })
                }
                Cap::Pdpt { ptr, asid, .. } if ptr.addr() == target_paddr => {
                    Some(Cap::Pdpt { ptr, mapped: new_mapped, asid })
                }
                _ => None,
            };
            if let Some(cap) = updated {
                slot.set_cap(&cap);
                break;
            }
        }
    }
}

fn decode_pt_map(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    map_paging_struct(target, args, invoker, 1)
}
fn decode_pd_map(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    map_paging_struct(target, args, invoker, 2)
}
fn decode_pdpt_map(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    map_paging_struct(target, args, invoker, 3)
}
fn decode_pt_unmap(target: Cap, invoker: TcbId) -> KResult<()> {
    unmap_paging_struct(target, invoker)
}
fn decode_pd_unmap(target: Cap, invoker: TcbId) -> KResult<()> {
    unmap_paging_struct(target, invoker)
}
fn decode_pdpt_unmap(target: Cap, invoker: TcbId) -> KResult<()> {
    unmap_paging_struct(target, invoker)
}

// ---------------------------------------------------------------------------
// Phase 31 — ASID Control / ASID Pool invocations.
//
// `Cap::AsidControl` is the singleton root cap for ASID
// management. Its only operation is `MakePool`, which carves a
// fresh `Cap::AsidPool` out of an Untyped (4 KiB of pool storage)
// and tags it with a unique `asid_base`. The kernel keeps a
// monotonic counter (one ASID pool covers 2^9 = 512 ASIDs).
//
// `Cap::AsidPool` lets userspace assign an ASID to a `Cap::PML4`
// (the vspace root). For Phase 31 the assignment is purely
// bookkeeping — we set `Cap::PML4 { asid }` to the next ASID in
// the pool. Hardware PCID integration (CR4.PCIDE + low-12-bits
// of CR3) is a follow-up.
// ---------------------------------------------------------------------------

/// Counter for the next pool's `asid_base`. Each MakePool bumps
/// by 512 (one pool's worth of ASIDs).
static NEXT_ASID_BASE: core::sync::atomic::AtomicU16 =
    core::sync::atomic::AtomicU16::new(0);

fn decode_asid_control(
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    use core::sync::atomic::Ordering;
    match label {
        InvocationLabel::X86ASIDControlMakePool => {
            // ABI:
            //   a2 = Untyped cap_ptr (source of pool storage)
            //   a3 = dest CNode cap_ptr (in invoker's CSpace)
            //   a4 = dest slot index in that CNode
            // We don't yet support per-cap-target CNode selection
            // (the rootserver always retypes into its own CNode);
            // a3 is currently ignored — we use the invoker's CSpace.
            let untyped_cptr = args.a2;
            let _ = args.a3;
            let dest_offset = args.a4 as usize;

            unsafe {
                let s = KERNEL.get();
                let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let untyped = crate::cspace::lookup_cap(s, &invoker_cspace, untyped_cptr)?;
                let mut state = match crate::untyped::UntypedState::from_cap(&untyped) {
                    Some(s) => s,
                    None => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };

                let cnode_ptr = match invoker_cspace {
                    Cap::CNode { ptr, .. } => ptr,
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                let cnode_idx = KernelState::cnode_index(cnode_ptr);
                let slots = &mut s.cnodes[cnode_idx].0;
                if dest_offset >= slots.len() || !slots[dest_offset].cap().is_null() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst)));
                }

                // Carve 4 KiB out of the Untyped for the pool storage.
                // Manual carve (mirrors what `retype()` does for one
                // child of size 2^12 = 4 KiB).
                let aligned = (state.free_index_bytes + 0xFFF) & !0xFFF;
                let block_total = 1u64 << state.block_bits;
                if aligned + 0x1000 > block_total {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_NotEnoughMemory)));
                }
                let pool_paddr = state.base + aligned;
                state.free_index_bytes = aligned + 0x1000;
                let asid_base = NEXT_ASID_BASE.fetch_add(512, Ordering::Relaxed);

                let pool_cap = Cap::AsidPool {
                    ptr: PPtr::<crate::cap::AsidPoolStorage>::new(pool_paddr)
                        .ok_or_else(|| KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidArgument)))?,
                    asid_base,
                };
                slots[dest_offset].set_cap(&pool_cap);
                // Phase 30 — record the new pool's MDB parent as
                // the source Untyped's slot.
                let parent_id = crate::cte::MdbId::pack(
                    cnode_idx as u8,
                    untyped_cptr as u16,
                );
                slots[dest_offset].set_parent(Some(parent_id));

                // Commit the bumped Untyped state back into its slot.
                for slot in slots.iter_mut() {
                    if let Cap::Untyped { ptr, .. } = slot.cap() {
                        if ptr.addr() == state.base {
                            slot.set_cap(&state.to_cap());
                            break;
                        }
                    }
                }
            }
            Ok(())
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

fn decode_asid_pool(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    let asid_base = match target {
        Cap::AsidPool { asid_base, .. } => asid_base,
        _ => unreachable!(),
    };
    match label {
        InvocationLabel::X86ASIDPoolAssign => {
            // ABI: a2 = vspace cap_ptr (must be Cap::PML4).
            let vspace_cptr = args.a2;
            unsafe {
                let s = KERNEL.get();
                let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let cnode_ptr = match invoker_cspace {
                    Cap::CNode { ptr, .. } => ptr,
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                let cnode_idx = KernelState::cnode_index(cnode_ptr);
                let slot_idx = vspace_cptr as usize;
                let slots = &mut s.cnodes[cnode_idx].0;
                if slot_idx >= slots.len() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_RangeError)));
                }
                match slots[slot_idx].cap() {
                    Cap::PML4 { ptr, mapped, asid: 0 } => {
                        // Allocate the next ASID in this pool. We use
                        // `asid_base + (low 9 bits of NEXT_ASID_OFFSET)`,
                        // bumped per assignment within the pool. Phase 31
                        // is a coarse first cut — proper allocation
                        // tracking lives in the AsidPool storage page
                        // (asid_map[]) once we plumb it.
                        let assigned = asid_base.saturating_add(
                            (NEXT_ASID_OFFSET.fetch_add(1, core::sync::atomic::Ordering::Relaxed) & 0x1FF) as u16,
                        );
                        slots[slot_idx].set_cap(&Cap::PML4 {
                            ptr,
                            mapped,
                            asid: assigned,
                        });
                        Ok(())
                    }
                    Cap::PML4 { .. } => Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst))),
                    _ => Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                }
            }
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// Per-pool offset bumper. Coarse — Phase 31+ replaces with a
/// proper per-pool free-bitmap living in the AsidPool storage page.
static NEXT_ASID_OFFSET: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

// ---------------------------------------------------------------------------
// Phase 32c — SchedContext invocations.
//
// `SchedContextBind(target_tcb_or_ntfn)` ties the SC to a thread
// (TCB cap arg) so its refill schedule controls that thread's CPU
// allocation. `SchedContextUnbind` reverses the link.
//
// `SchedControl::Configure` (for setting period + budget) lives on
// the seL4_SchedControl cap, not the SC cap, and is Phase 32d. The
// kernel-side SchedControl singleton isn't typed yet.
// ---------------------------------------------------------------------------

fn decode_sched_context(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    let sc_id = match target {
        Cap::SchedContext { ptr, .. } => {
            KernelState::sched_context_index(ptr) as u16
        }
        _ => unreachable!(),
    };
    match label {
        InvocationLabel::SchedContextBind => {
            // a2 = TCB cap_ptr in invoker's CSpace. (seL4 also
            // accepts Notification caps; we only handle the TCB
            // case for now.)
            let tcb_cptr = args.a2;
            unsafe {
                let s = KERNEL.get();
                let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let tcb_cap = crate::cspace::lookup_cap(s, &invoker_cspace, tcb_cptr)?;
                let tcb_id = match tcb_cap {
                    Cap::Thread { tcb } => crate::tcb::TcbId(tcb.addr() as u16),
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                // Refuse double-bind in either direction.
                if s.scheduler.slab.get(tcb_id).sc.is_some() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst)));
                }
                if s.sched_contexts[sc_id as usize].bound_tcb.is_some() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst)));
                }
                s.scheduler.slab.get_mut(tcb_id).sc = Some(sc_id);
                s.sched_contexts[sc_id as usize].bound_tcb = Some(tcb_id);
            }
            Ok(())
        }
        InvocationLabel::SchedContextUnbind => {
            unsafe {
                let s = KERNEL.get();
                if let Some(tcb_id) = s.sched_contexts[sc_id as usize].bound_tcb {
                    s.scheduler.slab.get_mut(tcb_id).sc = None;
                    s.sched_contexts[sc_id as usize].bound_tcb = None;
                }
            }
            Ok(())
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

// ---------------------------------------------------------------------------
// Phase 32d — SchedControl invocations.
//
// `SchedControlConfigureFlags(target_sc, budget, period, extra_refills, badge, flags)`
// programs the named SchedContext's refill schedule. seL4's
// signature ABI:
//   a2 = budget    (ticks)
//   a3 = period    (ticks)
//   a4 = extra_refills (count, currently unused — we keep
//        MAX_REFILLS fixed)
//   a5 = badge / flags (we ignore for now)
//   a0 = target SC cap_ptr (the rest go via SyscallArgs above).
//
// The kernel resets the SC's refill schedule to a single
// pending-refill record (release_time=0, amount=budget); seL4's
// real implementation builds a queue of replenishments. Our
// simple version is sufficient for Phase 32e's mixed-criticality
// demo.
// ---------------------------------------------------------------------------

fn decode_sched_control(
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::SchedControlConfigureFlags => {
            let target_cptr = args.a0;
            let budget = args.a2;
            let period = args.a3;
            // a4 (extra refills) and a5 (flags) ignored for now.

            unsafe {
                let s = KERNEL.get();
                let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let target = crate::cspace::lookup_cap(s, &invoker_cspace, target_cptr)?;
                let sc_idx = match target {
                    Cap::SchedContext { ptr, .. } => {
                        KernelState::sched_context_index(ptr)
                    }
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                if budget == 0 || period == 0 || budget > period {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_RangeError)));
                }
                let sc = &mut s.sched_contexts[sc_idx];
                *sc = crate::sched_context::SchedContext::new(period, budget);
                // Seed one ready refill so a freshly-configured SC
                // can be charged immediately.
                sc.refills[0] = crate::sched_context::Refill {
                    release_time: 0,
                    amount: budget,
                };
                sc.head = 0;
                sc.count = 1;
            }
            Ok(())
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

// ---------------------------------------------------------------------------
// IRQ invocations.
// ---------------------------------------------------------------------------

fn decode_irq_control(
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::IRQIssueIRQHandler => {
            // a2 = IRQ number, a3 = dest slot index
            let irq = args.a2 as u16;
            let dest_index = args.a3 as usize;
            unsafe {
                let s = KERNEL.get();
                let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
                let cnode_ptr = match cspace_root {
                    Cap::CNode { ptr, .. } => ptr,
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    ))),
                };
                let cnode_idx = KernelState::cnode_index(cnode_ptr);
                let slots = &mut s.cnodes[cnode_idx].0;
                if dest_index >= slots.len() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_RangeError,
                    )));
                }
                if !slots[dest_index].cap().is_null() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst,
                    )));
                }
                slots[dest_index].set_cap(&Cap::IrqHandler { irq });
            }
            Ok(())
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

fn decode_irq_handler(
    irq: u16,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    unsafe {
        let s = KERNEL.get();
        match label {
            InvocationLabel::IRQAckIRQ => {
                crate::interrupt::ack_irq(&mut s.irqs, irq).map_err(|_|
                    KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability)))
            }
            InvocationLabel::IRQSetIRQHandler => {
                // a2 = CPtr to a Notification cap to bind.
                let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
                let ntfn_cap = crate::cspace::lookup_cap(s, &cspace_root, args.a2)?;
                let ntfn_ptr = match ntfn_cap {
                    Cap::Notification { ptr, .. } => ptr,
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                let ntfn_idx = KernelState::ntfn_index(ntfn_ptr) as u16;
                // Replace any existing handler binding and install
                // the new one.
                let _ = crate::interrupt::clear_handler(&mut s.irqs, irq);
                crate::interrupt::set_notification(&mut s.irqs, irq, ntfn_idx)
                    .map_err(|_| KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability)))
            }
            InvocationLabel::IRQClearIRQHandler => {
                crate::interrupt::clear_handler(&mut s.irqs, irq)
                    .map_err(|_| KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability)))
            }
            _ => Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation))),
        }
    }
}

// ---------------------------------------------------------------------------
// Untyped invocations.
// ---------------------------------------------------------------------------

fn decode_untyped(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::UntypedRetype => decode_untyped_retype(target, args, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// `Untyped::Retype(type, size_bits, dest_root, dest_index, dest_depth,
/// dest_offset, num_objects)`. We use a compressed ABI suited to our
/// 6-register SyscallArgs (no IPC buffer yet):
///
///   a0 (= invoker's cap to untyped)        — selected by handle_send
///   a1 = MessageInfo (label = UntypedRetype, ignored here)
///   a2 = object_type word
///   a3 = (size_bits << 32) | num_objects
///   a4 = dest_offset (slot index in invoker's CSpace root CNode)
///   a5 = (unused for now — Phase 16d will add a destination root
///         cap-ptr for cross-CNode retype)
fn decode_untyped_retype(
    target: Cap,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    let object_type = ObjectType::from_word(args.a2);
    let size_bits = (args.a3 >> 32) as u32;
    let num_objects = args.a3 & 0xFFFF_FFFF;
    let dest_offset = args.a4 as usize;

    let mut state = match crate::untyped::UntypedState::from_cap(&target) {
        Some(s) => s,
        None => {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
    };

    // Resolve the destination CNode page from the invoker's CSpace
    // root.
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let cnode_ptr = match cspace_root {
            Cap::CNode { ptr, .. } => ptr,
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )));
            }
        };
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        let cnode_slots = &mut s.cnodes[cnode_idx].0;

        // Verify the destination range is empty — Retype refuses
        // to overwrite caps.
        let upper = dest_offset + num_objects as usize;
        if upper > cnode_slots.len() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        for i in dest_offset..upper {
            if !cnode_slots[i].cap().is_null() {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_DeleteFirst,
                )));
            }
        }

        // Carve children. The closure runs once per child; we
        // place the cap into the destination slot at the matching
        // offset.
        //
        // Phase 29h — for `Cap::Thread`, the raw retype path emits
        // a PPtr keyed off the Untyped's physical address, but
        // `decode_tcb` recovers the TcbId via `tcb_ptr.addr() as u16`.
        // Re-encode by admitting a fresh `Tcb::default()` into the
        // slab and storing the TcbId in the cap.
        let mut emit_idx = dest_offset;
        // We can't borrow `s.scheduler.slab` inside the closure
        // because `cnode_slots` already holds a mutable borrow of
        // a sibling field of `*s`. Use a raw pointer to bypass
        // the aliasing check; the BKL guarantees we're the only
        // writer.
        let scheduler_ptr: *mut crate::scheduler::Scheduler =
            &raw mut s.scheduler;
        // Need a mutable handle on `s` to allocate from the
        // endpoint / notification / cnode pools too. We reborrow
        // via `KERNEL.get()` to avoid the existing `&mut s.cnodes`
        // borrow's aliasing constraint.
        let s_ptr: *mut crate::kernel::KernelState = KERNEL.get();
        // Phase 30 — record each carved child's parent CTE in the
        // MDB. The source untyped lives at slot `args.a0` of the
        // invoker's CSpace (we use a0 directly because our flat
        // radix-5 CNode + guard_size=59 makes cptr == slot).
        let parent_id = crate::cte::MdbId::pack(
            cnode_idx as u8,
            args.a0 as u16,
        );
        let result = crate::untyped::retype(
            &mut state, object_type, size_bits, num_objects,
            |cap| {
                let cap_to_store = match cap {
                    Cap::Thread { .. } => {
                        let id = (*scheduler_ptr).admit(crate::tcb::Tcb {
                            state: crate::tcb::ThreadStateType::Inactive,
                            priority: 0,
                            ..Default::default()
                        });
                        Cap::Thread {
                            tcb: PPtr::<crate::cap::Tcb>::new(id.0 as u64)
                                .expect("nonzero tcb id"),
                        }
                    }
                    Cap::Endpoint { badge, rights, .. } => {
                        let i = (*s_ptr).alloc_endpoint()
                            .expect("endpoint pool exhausted");
                        Cap::Endpoint {
                            ptr: KernelState::endpoint_ptr(i),
                            badge,
                            rights,
                        }
                    }
                    Cap::Notification { badge, rights, .. } => {
                        let i = (*s_ptr).alloc_notification()
                            .expect("notification pool exhausted");
                        Cap::Notification {
                            ptr: KernelState::ntfn_ptr(i),
                            badge,
                            rights,
                        }
                    }
                    Cap::CNode { radix, guard_size, guard, .. } => {
                        let i = (*s_ptr).alloc_cnode()
                            .expect("cnode pool exhausted");
                        Cap::CNode {
                            ptr: KernelState::cnode_ptr(i),
                            radix,
                            guard_size,
                            guard,
                        }
                    }
                    Cap::SchedContext { size_bits, .. } => {
                        let i = (*s_ptr).alloc_sched_context()
                            .expect("sched_context pool exhausted");
                        Cap::SchedContext {
                            ptr: KernelState::sched_context_ptr(i),
                            size_bits,
                        }
                    }
                    other => other,
                };
                cnode_slots[emit_idx].set_cap(&cap_to_store);
                cnode_slots[emit_idx].set_parent(Some(parent_id));
                emit_idx += 1;
            },
        );
        result?;

        // Commit the updated UntypedState back into the cap stored
        // somewhere in the invoker's CSpace. We don't know exactly
        // which slot the original cap lives in — for now we store
        // the new cap in slot 0 of the invoker's cnode if slot 0
        // happens to hold the matching untyped. Real seL4 locates
        // the source slot via the in-flight `CapRegister` saved
        // before lookup. Phase 16b adds that.
        for slot in cnode_slots.iter_mut() {
            if let Cap::Untyped { ptr, .. } = slot.cap() {
                if ptr.addr() == state.base {
                    slot.set_cap(&state.to_cap());
                    break;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CNode invocations.
// ---------------------------------------------------------------------------

fn decode_cnode(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    match label {
        InvocationLabel::CNodeCopy => cnode_copy_or_mint(target, args, invoker, /* mint */ false),
        InvocationLabel::CNodeMint => cnode_copy_or_mint(target, args, invoker, /* mint */ true),
        InvocationLabel::CNodeMove => cnode_move(target, args, invoker, /* mutate */ false),
        InvocationLabel::CNodeMutate => cnode_move(target, args, invoker, /* mutate */ true),
        InvocationLabel::CNodeDelete => cnode_delete(target, args, invoker),
        InvocationLabel::CNodeRevoke => cnode_revoke(target, args, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// CNode::Revoke — Phase 30. Delete every cap whose MDB-parent
/// chain leads back to `(target_cnode, src_index)`. We track each
/// CTE's parent in `Cte::set_parent` (recorded by `Untyped::Retype`
/// + `CNode::Copy/Mint`); the walk is a fixed-point pass that
/// repeatedly clears CTEs whose parent has already been
/// revoked-or-source. The source slot itself is left intact —
/// Revoke deletes the children only; callers use CNodeDelete to
/// remove the source.
fn cnode_revoke(target: Cap, args: &SyscallArgs, _invoker: TcbId) -> KResult<()> {
    let src_index = args.a2 as usize;
    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        if src_index >= s.cnodes[cnode_idx].0.len() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        let source_id = crate::cte::MdbId::pack(cnode_idx as u8, src_index as u16);

        // Tombstone bitmap: bit set means "this CTE has been
        // revoked-or-is-source". Sized to MAX_CNODES * 32 (radix-5
        // CNode = 32 slots). We assume each CNode uses 32 slots.
        const SLOTS_PER_NODE: usize = 32;
        let mut revoked: [[bool; SLOTS_PER_NODE]; crate::kernel::MAX_CNODES] =
            [[false; SLOTS_PER_NODE]; crate::kernel::MAX_CNODES];
        revoked[cnode_idx][src_index] = true;

        // Iterate to fixed point: any CTE whose parent is revoked
        // gets revoked too. Capacity-bounded — at most
        // `MAX_CNODES * 32` CTEs to mark, so this loop is bounded.
        let mut progress = true;
        while progress {
            progress = false;
            for ci in 0..s.cnodes.len() {
                for si in 0..SLOTS_PER_NODE.min(s.cnodes[ci].0.len()) {
                    if revoked[ci][si] {
                        continue;
                    }
                    if let Some(p) = s.cnodes[ci].0[si].parent() {
                        let pi = p.cnode_idx() as usize;
                        let ps = p.slot() as usize;
                        if pi < crate::kernel::MAX_CNODES
                            && ps < SLOTS_PER_NODE
                            && revoked[pi][ps]
                        {
                            revoked[ci][si] = true;
                            progress = true;
                        }
                    }
                }
            }
        }

        // Clear every revoked slot except the source itself.
        for ci in 0..s.cnodes.len() {
            for si in 0..SLOTS_PER_NODE.min(s.cnodes[ci].0.len()) {
                if revoked[ci][si]
                    && !(ci == cnode_idx && si == src_index)
                {
                    s.cnodes[ci].0[si].set_cap(&Cap::Null);
                    s.cnodes[ci].0[si].set_parent(None);
                }
            }
        }

        // Silence unused: the structural fallback used to live
        // here. Keep `is_derived_from` available for any code that
        // still wants the structural check (none does today).
        let _ = source_id;
    }
    Ok(())
}

/// "child is derived from parent" — without an MDB, we approximate
/// the relationship structurally. Simple but adequate for the
/// common cases:
///   * Untyped parent → any cap whose object lives inside the
///     untyped's physical range
///   * Endpoint/Notification/CNode/Thread parent → any cap with
///     the same ptr (Mint and Copy produce children with the same
///     ptr but possibly different badges/rights)
fn is_derived_from(child: &Cap, parent: &Cap) -> bool {
    use Cap::*;
    match parent {
        Untyped { ptr, block_bits, .. } => {
            let base = ptr.addr();
            let end = base.saturating_add(1u64 << block_bits);
            let inside = |addr: u64| addr >= base && addr < end;
            match child {
                Endpoint { ptr, .. } => inside(ptr.addr()),
                Notification { ptr, .. } => inside(ptr.addr()),
                CNode { ptr, .. } => inside(ptr.addr()),
                Thread { tcb } => inside(tcb.addr()),
                Untyped { ptr, .. } => inside(ptr.addr()) && ptr.addr() != base,
                Reply { ptr, .. } => inside(ptr.addr()),
                Frame { ptr, .. } => inside(ptr.addr()),
                PageTable { ptr, .. } => inside(ptr.addr()),
                PageDirectory { ptr, .. } => inside(ptr.addr()),
                Pdpt { ptr, .. } => inside(ptr.addr()),
                PML4 { ptr, .. } => inside(ptr.addr()),
                _ => false,
            }
        }
        Endpoint { ptr: pp, .. } => matches!(child, Endpoint { ptr: cp, .. } if cp.addr() == pp.addr()),
        Notification { ptr: pp, .. } => matches!(child, Notification { ptr: cp, .. } if cp.addr() == pp.addr()),
        CNode { ptr: pp, .. } => matches!(child, CNode { ptr: cp, .. } if cp.addr() == pp.addr()),
        Thread { tcb: pp } => matches!(child, Thread { tcb: cp } if cp.addr() == pp.addr()),
        _ => false,
    }
}

fn cnode_copy_or_mint(
    target: Cap,
    args: &SyscallArgs,
    _invoker: TcbId,
    mint: bool,
) -> KResult<()> {
    let dest_index = args.a2 as usize;
    let src_index = args.a3 as usize;
    let _badge_or_rights = args.a4;

    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let idx = KernelState::cnode_index(cnode_ptr);
        let slots = &mut s.cnodes[idx].0;
        if dest_index >= slots.len() || src_index >= slots.len() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        if !slots[dest_index].cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        let mut copy = slots[src_index].cap();
        if mint {
            // Mint can re-badge an Endpoint/Notification cap.
            if let Cap::Endpoint { ref mut badge, .. } = copy {
                *badge = crate::cap::Badge(_badge_or_rights);
            }
            if let Cap::Notification { ref mut badge, .. } = copy {
                *badge = crate::cap::Badge(_badge_or_rights);
            }
        }
        slots[dest_index].set_cap(&copy);
        // Phase 30 — the new cap is derived from the source slot;
        // its MDB parent is the source CTE.
        let src_id = crate::cte::MdbId::pack(idx as u8, src_index as u16);
        slots[dest_index].set_parent(Some(src_id));
    }
    Ok(())
}

fn cnode_move(
    target: Cap,
    args: &SyscallArgs,
    _invoker: TcbId,
    _mutate: bool,
) -> KResult<()> {
    let dest_index = args.a2 as usize;
    let src_index = args.a3 as usize;
    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let idx = KernelState::cnode_index(cnode_ptr);
        let slots = &mut s.cnodes[idx].0;
        if dest_index >= slots.len() || src_index >= slots.len() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        if !slots[dest_index].cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        let cap = slots[src_index].cap();
        slots[dest_index].set_cap(&cap);
        slots[src_index].set_cap(&Cap::Null);
    }
    Ok(())
}

fn cnode_delete(target: Cap, args: &SyscallArgs, _invoker: TcbId) -> KResult<()> {
    let index = args.a2 as usize;
    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let idx = KernelState::cnode_index(cnode_ptr);
        let slots = &mut s.cnodes[idx].0;
        if index >= slots.len() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        slots[index].set_cap(&Cap::Null);
        // Phase 30 — also clear the MDB edge so children of the
        // deleted slot become orphaned (revoking the deleted slot
        // can't reach them, which matches seL4's "delete unlinks
        // but doesn't recursively delete" semantics).
        slots[index].set_parent(None);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TCB invocations.
// ---------------------------------------------------------------------------

fn decode_tcb(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    let tcb_ptr = match target {
        Cap::Thread { tcb } => tcb,
        _ => unreachable!(),
    };
    // Our TcbId pool indexes 0..MAX_TCBS; the cap's PPtr addr
    // doubles as the slab index for now. See KernelState::endpoint
    // convention.
    let id = TcbId(tcb_ptr.addr() as u16);
    unsafe {
        let s = KERNEL.get();
        match label {
            InvocationLabel::TCBSuspend => {
                s.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
                Ok(())
            }
            InvocationLabel::TCBResume => {
                s.scheduler.make_runnable(id);
                Ok(())
            }
            InvocationLabel::TCBSetPriority => {
                let prio = args.a2 as u8;
                s.scheduler.slab.get_mut(id).priority = prio;
                Ok(())
            }
            InvocationLabel::TCBWriteRegisters => {
                // a2 = rip, a3 = rsp, a4 = arg0 (rdi).
                let t = s.scheduler.slab.get_mut(id);
                #[cfg(target_arch = "x86_64")]
                {
                    t.user_context.rcx = args.a2;
                    t.user_context.rsp = args.a3;
                    t.user_context.rdi = args.a4;
                    // Default user RFLAGS — IF=1, bit 1 reserved=1.
                    t.user_context.r11 = 0x202;
                }
                Ok(())
            }
            InvocationLabel::TCBReadRegisters => {
                // Fan target's saved regs into invoker's msg_regs
                // so the syscall return path delivers them.
                let target_state = {
                    let t = s.scheduler.slab.get(id);
                    #[cfg(target_arch = "x86_64")]
                    {
                        (t.user_context.rcx, t.user_context.rsp, t.user_context.rax)
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    { (0u64, 0u64, 0u64) }
                };
                let inv = s.scheduler.slab.get_mut(invoker);
                inv.msg_regs[0] = target_state.0;
                inv.msg_regs[1] = target_state.1;
                inv.msg_regs[2] = target_state.2;
                inv.ipc_length = 3;
                Ok(())
            }
            InvocationLabel::TCBSetSpace => {
                // a2 = fault_ep_cptr, a3 = cnode_cptr, a4 = vspace_cptr.
                // Look up cnode and vspace caps in invoker's CSpace.
                let inv_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let cnode_cap = if args.a3 != 0 {
                    Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a3)?)
                } else { None };
                let vspace_cap = if args.a4 != 0 {
                    Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a4)?)
                } else { None };
                let t = s.scheduler.slab.get_mut(id);
                t.fault_handler = args.a2;
                if let Some(c) = cnode_cap {
                    if !matches!(c, Cap::CNode { .. }) {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    t.cspace_root = c;
                }
                if let Some(c) = vspace_cap {
                    // Phase 27: a typed PML4 cap pins the target's
                    // CR3 — the syscall return path consumes
                    // `cpu_context.cr3` before sysretq. Refuse any
                    // non-PML4 cap so userspace can't smuggle a
                    // bogus root into a TCB.
                    match c {
                        Cap::PML4 { ptr, .. } => {
                            t.cpu_context.cr3 = ptr.addr();
                        }
                        Cap::Null => {}
                        _ => return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability))),
                    }
                    t.vspace_root = c;
                }
                Ok(())
            }
            InvocationLabel::TCBBindNotification => {
                // a2 = ntfn_cptr.
                let inv_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let ntfn_cap = crate::cspace::lookup_cap(s, &inv_cspace, args.a2)?;
                let ntfn_idx = match ntfn_cap {
                    Cap::Notification { ptr, .. } => {
                        KernelState::ntfn_index(ptr) as u16
                    }
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                // Refuse double-bind (matches seL4's behaviour).
                let t = s.scheduler.slab.get_mut(id);
                if t.bound_notification.is_some() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst)));
                }
                t.bound_notification = Some(ntfn_idx);
                Ok(())
            }
            InvocationLabel::TCBUnbindNotification => {
                s.scheduler.slab.get_mut(id).bound_notification = None;
                Ok(())
            }
            _ => Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation,
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::cap::{Badge, Cap, EndpointObj, EndpointRights, PPtr};

    pub fn test_invocation() {
        arch::log("Running invocation tests...\n");
        untyped_retype_via_invocation();
        cnode_copy_via_invocation();
        cnode_move_clears_source();
        cnode_revoke_zaps_descendants();
        mdb_records_retype_parent_link();
        mdb_revoke_walks_grandchildren();
        irq_control_issues_handler_cap();
        irq_handler_set_clear_ack();
        frame_map_unmap_get_address();
        page_table_map_unmap();
        tcb_write_read_registers();
        tcb_set_space_and_bind_notification();
        tcb_set_space_pml4_pins_cr3();
        asid_control_make_pool_then_assign();
        sched_context_bind_unbind();
        sched_control_configure_sets_period_budget();
        unsupported_label_returns_illegal();
        arch::log("Invocation tests completed\n");
    }

    /// Phase 31 — exercise the ASID path end-to-end:
    ///   1. Drop an AsidControl + Untyped + PML4 cap into the
    ///      invoker's CSpace.
    ///   2. Invoke `AsidControl::MakePool` to carve a fresh
    ///      AsidPool out of the Untyped.
    ///   3. Invoke `AsidPool::Assign` on the PML4 cap. The cap's
    ///      `asid` field should become non-zero (and within the
    ///      pool's range).
    #[inline(never)]
    fn asid_control_make_pool_then_assign() {
        use crate::cap::{AsidPoolStorage, Pml4Storage, UntypedStorage};

        let invoker = setup_invoker(0);

        // Slot 4: AsidControl singleton.
        unsafe {
            KERNEL.get().cnodes[0].0[4] = Cte::with_cap(&Cap::AsidControl);
        }
        // Slot 5: Untyped (16 KiB) for pool storage.
        unsafe {
            KERNEL.get().cnodes[0].0[5] = Cte::with_cap(&Cap::Untyped {
                ptr: PPtr::<UntypedStorage>::new(0x0050_0000).unwrap(),
                block_bits: 14,
                free_index: 0,
                is_device: false,
            });
        }
        // Slot 6: A PML4 cap with asid=0 (unassigned).
        let pml4_cap = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(0x0050_8000).unwrap(),
            mapped: true,
            asid: 0,
        };
        unsafe { KERNEL.get().cnodes[0].0[6] = Cte::with_cap(&pml4_cap); }

        // AsidControl::MakePool — pool lands in slot 7.
        let args = SyscallArgs {
            a1: (InvocationLabel::X86ASIDControlMakePool as u64) << 12,
            a2: 5, // Untyped cap_ptr
            a3: 0, // dest_cnode (ignored — we use invoker's CSpace)
            a4: 7, // dest slot
            ..Default::default()
        };
        decode_invocation(Cap::AsidControl, &args, invoker)
            .expect("MakePool ok");
        let pool = unsafe { KERNEL.get().cnodes[0].0[7].cap() };
        let (pool_ptr, pool_base) = match pool {
            Cap::AsidPool { ptr, asid_base } => (ptr, asid_base),
            other => panic!("expected Cap::AsidPool at slot 7, got {:?}", other),
        };
        let _: PPtr<AsidPoolStorage> = pool_ptr; // type assertion

        // AsidPool::Assign — give the PML4 in slot 6 an ASID.
        let args = SyscallArgs {
            a1: (InvocationLabel::X86ASIDPoolAssign as u64) << 12,
            a2: 6, // vspace cap_ptr
            ..Default::default()
        };
        decode_invocation(pool, &args, invoker).expect("Assign ok");
        unsafe {
            match KERNEL.get().cnodes[0].0[6].cap() {
                Cap::PML4 { asid, .. } => {
                    assert!(asid != 0,
                        "Assign should set a non-zero ASID, got {asid}");
                    assert!(asid >= pool_base && asid < pool_base + 512,
                        "ASID {asid} should be within pool [{pool_base}, {pool_base}+512)");
                }
                other => panic!("expected Cap::PML4, got {:?}", other),
            }
        }

        // Re-assigning a PML4 that already has an ASID surfaces
        // DeleteFirst.
        let r = decode_invocation(pool, &args, invoker);
        assert!(matches!(r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_DeleteFirst }))),
            "second Assign on a non-zero-ASID PML4 should DeleteFirst");

        teardown_invoker(invoker);
        arch::log("  ✓ AsidControl::MakePool + AsidPool::Assign\n");
    }

    /// Phase 30 — every cap retyped from an Untyped should record
    /// that Untyped's CTE as its MDB parent.
    #[inline(never)]
    fn mdb_records_retype_parent_link() {
        let invoker = setup_invoker(0);
        let ut_cap = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(0x0080_0000).unwrap(),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            KERNEL.get().cnodes[0].0[0] = Cte::with_cap(&ut_cap);
        }
        // Retype 3 endpoints into slots 4..6.
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: crate::object_type::ObjectType::Endpoint.to_word(),
            a3: 3,
            a4: 4,
            ..Default::default()
        };
        decode_invocation(ut_cap, &args, invoker).expect("retype");

        unsafe {
            let s = KERNEL.get();
            let expected = crate::cte::MdbId::pack(0, 0);
            for i in 4..7 {
                let p = s.cnodes[0].0[i].parent();
                assert_eq!(p, Some(expected),
                    "slot {i}'s MDB parent should be (0, 0)");
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Untyped::Retype records each child's MDB parent\n");
    }

    /// Phase 30 — Revoke walks the derivation graph transitively.
    /// Retype an Untyped → 1 endpoint, Copy that endpoint into a
    /// new slot, then revoke the Untyped. Both the original AND
    /// the copy must be cleared.
    #[inline(never)]
    fn mdb_revoke_walks_grandchildren() {
        let invoker = setup_invoker(0);
        let ut_cap = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(0x0090_0000).unwrap(),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            KERNEL.get().cnodes[0].0[0] = Cte::with_cap(&ut_cap);
        }
        // Retype Endpoint at slot 4.
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: crate::object_type::ObjectType::Endpoint.to_word(),
            a3: 1,
            a4: 4,
            ..Default::default()
        };
        decode_invocation(ut_cap, &args, invoker).expect("retype");

        // Copy the endpoint at slot 4 → slot 5.
        let cnode_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeCopy as u64) << 12,
            a2: 5, a3: 4,
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("copy");
        unsafe {
            let s = KERNEL.get();
            let original = crate::cte::MdbId::pack(0, 4);
            assert_eq!(s.cnodes[0].0[5].parent(), Some(original),
                "copy's MDB parent should be the original at slot 4");
        }

        // Revoke the Untyped at slot 0 — should walk transitively
        // and clear both slot 4 (direct child) and slot 5 (grandchild
        // via Copy).
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: 0,
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("revoke");
        unsafe {
            let s = KERNEL.get();
            assert!(matches!(s.cnodes[0].0[0].cap(), Cap::Untyped { .. }),
                "source Untyped should remain after revoke");
            assert!(s.cnodes[0].0[4].cap().is_null(),
                "direct child should be revoked");
            assert!(s.cnodes[0].0[5].cap().is_null(),
                "grandchild via Copy should be revoked transitively");
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Revoke walks derivation graph transitively (MDB)\n");
    }

    /// Phase 26d — `Cap::PageTable` `Map` / `Unmap` round-trip.
    /// Installs a PT cap, records the mapped vaddr, then unmaps.
    /// We don't verify the hardware install here — the spec build
    /// stubs that out (no live PD to walk in this fixture).
    #[inline(never)]
    fn page_table_map_unmap() {
        use crate::cap::{PageTableStorage};
        let invoker = setup_invoker(0);
        let pt_paddr = 0x0000_0000_00B0_0000u64;
        let pt_cap = Cap::PageTable {
            ptr: PPtr::<PageTableStorage>::new(pt_paddr).unwrap(),
            mapped: None,
            asid: 0,
        };
        unsafe { KERNEL.get().cnodes[0].0[2] = Cte::with_cap(&pt_cap); }

        // Map at a 2 MiB-aligned vaddr (PD-entry granularity).
        let vaddr = 0x0000_0100_0080_0000u64;
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageTableMap as u64) << 12,
            a2: vaddr,
            ..Default::default()
        };
        decode_invocation(pt_cap, &args, invoker).expect("PT map ok");

        unsafe {
            match KERNEL.get().cnodes[0].0[2].cap() {
                Cap::PageTable { mapped: Some(v), .. } if v == vaddr => {}
                other => panic!("expected mapped PT, got {:?}", other),
            }
        }

        // Re-map → DeleteFirst.
        let stored = unsafe { KERNEL.get().cnodes[0].0[2].cap() };
        let r = decode_invocation(stored, &args, invoker);
        assert!(matches!(r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_DeleteFirst }))));

        // Unmap clears the mapping.
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageTableUnmap as u64) << 12,
            ..Default::default()
        };
        decode_invocation(stored, &args, invoker).expect("PT unmap ok");
        unsafe {
            match KERNEL.get().cnodes[0].0[2].cap() {
                Cap::PageTable { mapped: None, .. } => {}
                other => panic!("expected unmapped PT, got {:?}", other),
            }
        }

        teardown_invoker(invoker);
        arch::log("  ✓ Cap::PageTable Map / Unmap updates cap shadow\n");
    }

    /// Build a fresh state for one test: invoker TCB id, and a
    /// CNode page wired up with the caps we want.
    fn setup_invoker(cnode_idx: usize) -> TcbId {
        unsafe {
            let s = KERNEL.get();
            let mut t = crate::tcb::Tcb::default();
            t.priority = 50;
            t.state = crate::tcb::ThreadStateType::Running;
            t.cspace_root = Cap::CNode {
                ptr: KernelState::cnode_ptr(cnode_idx),
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            // Wipe the cnode in case earlier specs left state.
            for slot in s.cnodes[cnode_idx].0.iter_mut() {
                slot.set_cap(&Cap::Null);
            }
            s.scheduler.admit(t)
        }
    }

    fn teardown_invoker(id: TcbId) {
        unsafe {
            let s = KERNEL.get();
            s.scheduler.slab.free(id);
        }
    }

    #[inline(never)]
    fn untyped_retype_via_invocation() {
        let invoker = setup_invoker(0);
        // Plant an Untyped cap of size 16 KiB at slot 0.
        let untyped_base = 0x0010_0000u64;
        let ut_cap = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(untyped_base).unwrap(),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[0] = Cte::with_cap(&ut_cap);
        }

        // Invoke UntypedRetype to make 4 endpoints in slots 4..7.
        // ABI:
        //   a2 = ObjectType::Endpoint = 2
        //   a3 = (size_bits << 32) | num_objects = (0 << 32) | 4 = 4
        //   a4 = dest_offset = 4
        let args = SyscallArgs {
            a0: 0,                        // unused at this layer
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: ObjectType::Endpoint.to_word(),
            a3: 4,
            a4: 4,
            a5: 0,
        };
        decode_invocation(ut_cap, &args, invoker).expect("retype ok");

        // Slots 4..7 each hold an Endpoint cap. Phase 29h's pool
        // remap made `ptr.addr()` an index-into-`endpoints[]+1` (so
        // `decode_endpoint` can route to the kernel pool); we just
        // verify each slot is a non-null Endpoint with a unique
        // pool index.
        unsafe {
            let s = KERNEL.get();
            let mut seen_indices = [false; crate::kernel::MAX_ENDPOINTS];
            for i in 4..8 {
                match s.cnodes[0].0[i].cap() {
                    Cap::Endpoint { ptr, .. } => {
                        let idx = (ptr.addr() - 1) as usize;
                        assert!(idx < crate::kernel::MAX_ENDPOINTS,
                            "ep index out of range: {}", idx);
                        assert!(!seen_indices[idx], "duplicate ep index");
                        seen_indices[idx] = true;
                    }
                    other => panic!("expected endpoint at {i}, got {:?}", other),
                }
            }
            // The Untyped's free_index advanced (4 endpoints × 16 bytes).
            match s.cnodes[0].0[0].cap() {
                Cap::Untyped { free_index, .. } => assert_eq!(free_index, 64),
                other => panic!("expected updated untyped, got {:?}", other),
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Untyped::Retype invocation creates child caps\n");
    }

    #[inline(never)]
    fn cnode_copy_via_invocation() {
        let invoker = setup_invoker(0);
        unsafe {
            let s = KERNEL.get();
            // Plant an endpoint cap at slot 1.
            s.cnodes[0].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: PPtr::<EndpointObj>::new(0x123).unwrap(),
                badge: Badge(0xAA),
                rights: EndpointRights {
                    can_send: true, can_receive: false,
                    can_grant: false, can_grant_reply: false,
                },
            });
        }

        let cnode_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeCopy as u64) << 12,
            a2: 2, // dest slot
            a3: 1, // src slot
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("copy ok");
        unsafe {
            let s = KERNEL.get();
            // Both slot 1 and slot 2 hold the same endpoint cap now.
            assert!(matches!(s.cnodes[0].0[1].cap(), Cap::Endpoint { .. }));
            assert!(matches!(s.cnodes[0].0[2].cap(), Cap::Endpoint { .. }));
        }
        teardown_invoker(invoker);
        arch::log("  ✓ CNode::Copy duplicates a cap to a new slot\n");
    }

    #[inline(never)]
    fn cnode_move_clears_source() {
        let invoker = setup_invoker(0);
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: PPtr::<EndpointObj>::new(0x456).unwrap(),
                badge: Badge(0),
                rights: EndpointRights::default(),
            });
        }
        let cnode_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeMove as u64) << 12,
            a2: 3, // dest
            a3: 1, // src
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("move ok");
        unsafe {
            let s = KERNEL.get();
            assert!(s.cnodes[0].0[1].cap().is_null());
            assert!(matches!(s.cnodes[0].0[3].cap(), Cap::Endpoint { .. }));
        }
        teardown_invoker(invoker);
        arch::log("  ✓ CNode::Move transfers cap and zeroes source\n");
    }

    /// Revoke walks the cap tree and zeroes every derived cap.
    /// Source untyped is left intact; its children are deleted.
    #[inline(never)]
    fn cnode_revoke_zaps_descendants() {
        let invoker = setup_invoker(0);
        let untyped_base = 0x0080_0000u64;
        let ut_cap = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(untyped_base).unwrap(),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe { KERNEL.get().cnodes[0].0[0] = Cte::with_cap(&ut_cap); }

        // Retype 4 Endpoints into slots 4..7. Phase 30 — the MDB
        // tree records each child's parent CTE, so Revoke walks
        // descendants regardless of whether the cap's PPtr lies
        // inside the Untyped's physical range. (The pool-allocated
        // Endpoint caps would have failed structural Revoke before
        // Phase 30; that's the bug the MDB walk fixes.)
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: crate::object_type::ObjectType::Endpoint.to_word(),
            a3: 4,
            a4: 4,
            ..Default::default()
        };
        decode_invocation(ut_cap, &args, invoker).expect("retype");

        // Verify children present.
        unsafe {
            let s = KERNEL.get();
            for i in 4..8 {
                assert!(matches!(s.cnodes[0].0[i].cap(), Cap::Endpoint { .. }));
            }
        }

        // Revoke the untyped at slot 0 — should zero all 4
        // descendants but leave the untyped intact.
        let cnode_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: 0, // src slot = the untyped
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("revoke");

        unsafe {
            let s = KERNEL.get();
            // Source untyped still present.
            assert!(matches!(s.cnodes[0].0[0].cap(), Cap::Untyped { .. }));
            // Children gone.
            for i in 4..8 {
                assert!(s.cnodes[0].0[i].cap().is_null(),
                    "slot {i} should have been revoked");
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ CNode::Revoke clears Untyped descendants\n");
    }

    #[inline(never)]
    fn irq_control_issues_handler_cap() {
        let invoker = setup_invoker(0);
        // Invoke IRQControl::IssueIRQHandler with IRQ=7,
        // dest_slot=2.
        let args = SyscallArgs {
            a1: (InvocationLabel::IRQIssueIRQHandler as u64) << 12,
            a2: 7,
            a3: 2,
            ..Default::default()
        };
        decode_invocation(Cap::IrqControl, &args, invoker)
            .expect("issue handler ok");
        unsafe {
            let s = KERNEL.get();
            match s.cnodes[0].0[2].cap() {
                Cap::IrqHandler { irq: 7 } => {}
                other => panic!("expected IrqHandler{{7}}, got {:?}", other),
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ IRQControl::IssueIRQHandler issues a handler cap\n");
    }

    #[inline(never)]
    fn irq_handler_set_clear_ack() {
        let invoker = setup_invoker(0);
        // Stage a notification cap at slot 5 in CNode 0.
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[5] = Cte::with_cap(&Cap::Notification {
                ptr: KernelState::ntfn_ptr(3),
                badge: crate::cap::Badge(0),
                rights: crate::cap::NotificationRights {
                    can_send: true, can_receive: true,
                },
            });
        }

        // SetNotification: bind IRQ 9 to the ntfn cap at slot 5.
        let args = SyscallArgs {
            a1: (InvocationLabel::IRQSetIRQHandler as u64) << 12,
            a2: 5, // CPtr to ntfn cap
            ..Default::default()
        };
        decode_invocation(Cap::IrqHandler { irq: 9 }, &args, invoker)
            .expect("set notification ok");
        unsafe {
            let s = KERNEL.get();
            let entry = s.irqs.get(9).unwrap();
            assert_eq!(entry.state, crate::interrupt::IrqState::Signal);
            assert_eq!(entry.notification, Some(3));
        }

        // Simulate the IRQ firing — pending should go true.
        unsafe {
            let s = KERNEL.get();
            crate::interrupt::handle_interrupt(
                &mut s.irqs,
                &mut s.notifications,
                &mut s.scheduler,
                9,
            );
            assert!(s.irqs.get(9).unwrap().pending);
        }

        // Ack via invocation.
        let args = SyscallArgs {
            a1: (InvocationLabel::IRQAckIRQ as u64) << 12,
            ..Default::default()
        };
        decode_invocation(Cap::IrqHandler { irq: 9 }, &args, invoker)
            .expect("ack ok");
        unsafe {
            let s = KERNEL.get();
            assert!(!s.irqs.get(9).unwrap().pending);
        }

        // Clear via invocation.
        let args = SyscallArgs {
            a1: (InvocationLabel::IRQClearIRQHandler as u64) << 12,
            ..Default::default()
        };
        decode_invocation(Cap::IrqHandler { irq: 9 }, &args, invoker)
            .expect("clear ok");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.irqs.get(9).unwrap().state,
                crate::interrupt::IrqState::Inactive);
        }

        teardown_invoker(invoker);
        arch::log("  ✓ IRQHandler::Set/Ack/Clear cycle\n");
    }

    #[inline(never)]
    fn frame_map_unmap_get_address() {
        use crate::cap::{FrameRights, FrameSize, FrameStorage};

        let invoker = setup_invoker(0);
        // Plant a Frame cap at slot 1 of CNode 0. Pick a paddr
        // safely past BOOTBOOT's identity range so map_user_4k
        // doesn't clash with the loader's 1 GiB pages, and a
        // vaddr in PML4[2] (= same place the user-mode demo uses).
        let paddr = 0x0000_0000_0090_0000u64;
        let frame_cap = Cap::Frame {
            ptr: PPtr::<FrameStorage>::new(paddr).unwrap(),
            size: FrameSize::Small,
            rights: FrameRights::ReadWrite,
            mapped: None,
            asid: 0,
            is_device: false,
        };
        unsafe { KERNEL.get().cnodes[0].0[1] = Cte::with_cap(&frame_cap); }

        // Invoke X86PageGetAddress — kernel writes paddr into the
        // invoker's msg_regs[0].
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageGetAddress as u64) << 12,
            ..Default::default()
        };
        decode_invocation(frame_cap, &args, invoker).expect("get address ok");
        unsafe {
            assert_eq!(KERNEL.get().scheduler.slab.get(invoker).msg_regs[0], paddr);
        }

        // Invoke X86PageMap — install at vaddr 0x100_0040_0000.
        let vaddr = 0x0000_0100_0040_0000u64;
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: vaddr,
            a3: FrameRights::ReadWrite.to_word(),
            ..Default::default()
        };
        decode_invocation(frame_cap, &args, invoker).expect("map ok");

        // Cap state was updated to record the mapping.
        unsafe {
            match KERNEL.get().cnodes[0].0[1].cap() {
                Cap::Frame { mapped: Some(v), rights: FrameRights::ReadWrite, .. }
                    if v == vaddr => {}
                other => panic!("expected mapped frame, got {:?}", other),
            }
        }

        // Verify the PTE actually went in by walking the live
        // page tables.
        let translated = crate::arch::x86_64::paging::live_virt_to_phys(vaddr);
        assert_eq!(translated, Some(paddr));

        // Re-mapping the same frame surfaces DeleteFirst.
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: vaddr,
            a3: FrameRights::ReadWrite.to_word(),
            ..Default::default()
        };
        // Use the freshly-stored cap (which has mapped=Some).
        let now_cap = unsafe { KERNEL.get().cnodes[0].0[1].cap() };
        let r = decode_invocation(now_cap, &args, invoker);
        assert!(matches!(r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_DeleteFirst })))
        );

        // Unmap clears the mapping in the cap.
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageUnmap as u64) << 12,
            ..Default::default()
        };
        decode_invocation(now_cap, &args, invoker).expect("unmap ok");
        unsafe {
            match KERNEL.get().cnodes[0].0[1].cap() {
                Cap::Frame { mapped: None, .. } => {}
                other => panic!("expected unmapped frame, got {:?}", other),
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Frame::Map / Unmap / GetAddress round-trip\n");
    }

    #[inline(never)]
    fn tcb_write_read_registers() {
        let invoker = setup_invoker(0);
        // Allocate a target TCB to manipulate.
        let target = unsafe {
            let mut t = crate::tcb::Tcb::default();
            t.priority = 100;
            KERNEL.get().scheduler.admit(t)
        };
        let target_cap = Cap::Thread {
            tcb: crate::cap::PPtr::<crate::cap::Tcb>::new(target.0 as u64).unwrap(),
        };

        // WriteRegisters: rip = 0xCAFE_F00D, rsp = 0x100_4000, arg0 = 7.
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBWriteRegisters as u64) << 12,
            a2: 0xCAFE_F00D,
            a3: 0x0010_4000,
            a4: 7,
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("write regs");
        unsafe {
            let s = KERNEL.get();
            let t = s.scheduler.slab.get(target);
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(t.user_context.rcx, 0xCAFE_F00D);
                assert_eq!(t.user_context.rsp, 0x0010_4000);
                assert_eq!(t.user_context.rdi, 7);
            }
        }

        // ReadRegisters: target's saved regs go into invoker's
        // msg_regs.
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBReadRegisters as u64) << 12,
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("read regs");
        unsafe {
            let s = KERNEL.get();
            let inv = s.scheduler.slab.get(invoker);
            assert_eq!(inv.msg_regs[0], 0xCAFE_F00D);
            assert_eq!(inv.msg_regs[1], 0x0010_4000);
            assert_eq!(inv.ipc_length, 3);
            s.scheduler.slab.free(target);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ TCB::Write/ReadRegisters round-trip\n");
    }

    #[inline(never)]
    fn tcb_set_space_and_bind_notification() {
        let invoker = setup_invoker(0);
        let target = unsafe {
            let t = crate::tcb::Tcb::default();
            KERNEL.get().scheduler.admit(t)
        };
        let target_cap = Cap::Thread {
            tcb: crate::cap::PPtr::<crate::cap::Tcb>::new(target.0 as u64).unwrap(),
        };

        // Plant caps in invoker's CSpace:
        //   slot 1: a CNode cap (target's new cspace_root)
        //   slot 2: a Notification cap (for BindNotification)
        unsafe {
            let s = KERNEL.get();
            // Use cnode index 1 as the *target's* cspace_root.
            let new_cnode_cap = Cap::CNode {
                ptr: KernelState::cnode_ptr(1),
                radix: 5, guard_size: 59, guard: 0,
            };
            s.cnodes[0].0[1] = Cte::with_cap(&new_cnode_cap);
            s.cnodes[0].0[2] = Cte::with_cap(&Cap::Notification {
                ptr: KernelState::ntfn_ptr(5),
                badge: crate::cap::Badge(0),
                rights: crate::cap::NotificationRights {
                    can_send: true, can_receive: true,
                },
            });
        }

        // SetSpace(fault_ep=0, cnode_cptr=1, vspace_cptr=0)
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBSetSpace as u64) << 12,
            a2: 0,
            a3: 1,
            a4: 0,
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("set space");
        unsafe {
            let t = KERNEL.get().scheduler.slab.get(target);
            match t.cspace_root {
                Cap::CNode { ptr, .. } if ptr == KernelState::cnode_ptr(1) => {}
                other => panic!("expected new cspace, got {:?}", other),
            }
        }

        // BindNotification(ntfn_cptr=2)
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBBindNotification as u64) << 12,
            a2: 2,
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("bind ntfn");
        unsafe {
            let t = KERNEL.get().scheduler.slab.get(target);
            assert_eq!(t.bound_notification, Some(5));
        }

        // Double-bind rejected.
        let r = decode_invocation(target_cap, &args, invoker);
        assert!(matches!(r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_DeleteFirst })))
        );

        // Unbind clears the slot.
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBUnbindNotification as u64) << 12,
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("unbind");
        unsafe {
            let t = KERNEL.get().scheduler.slab.get(target);
            assert_eq!(t.bound_notification, None);
            KERNEL.get().scheduler.slab.free(target);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ TCB::SetSpace + Bind/UnbindNotification\n");
    }

    /// Phase 27 — `TCB::SetSpace` with a typed `Cap::PML4` writes the
    /// PML4's physical address into the target TCB's `cpu_context.cr3`.
    /// The syscall return path uses that as CR3 on resume.
    #[inline(never)]
    fn tcb_set_space_pml4_pins_cr3() {
        use crate::cap::{Pml4Storage};

        let invoker = setup_invoker(0);
        let target = unsafe {
            let mut t = crate::tcb::Tcb::default();
            t.priority = 80;
            KERNEL.get().scheduler.admit(t)
        };
        let target_cap = Cap::Thread {
            tcb: PPtr::<crate::cap::Tcb>::new(target.0 as u64).unwrap(),
        };

        // Plant a PML4 cap at slot 3 of the invoker's CNode.
        let pml4_paddr = 0x0000_0000_00C0_0000u64;
        let pml4_cap = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(pml4_paddr).unwrap(),
            mapped: true,
            asid: 0,
        };
        unsafe { KERNEL.get().cnodes[0].0[3] = Cte::with_cap(&pml4_cap); }

        // SetSpace(fault_ep=0, cnode_cptr=0, vspace_cptr=3)
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBSetSpace as u64) << 12,
            a2: 0, a3: 0, a4: 3,
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("set vspace");
        unsafe {
            let t = KERNEL.get().scheduler.slab.get(target);
            assert_eq!(t.cpu_context.cr3, pml4_paddr);
            assert!(matches!(t.vspace_root, Cap::PML4 { .. }));
        }

        // SetSpace with a non-PML4 vspace cap (a CNode) is rejected.
        unsafe {
            KERNEL.get().cnodes[0].0[4] = Cte::with_cap(&Cap::CNode {
                ptr: KernelState::cnode_ptr(1),
                radix: 5, guard_size: 59, guard: 0,
            });
        }
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBSetSpace as u64) << 12,
            a2: 0, a3: 0, a4: 4,
            ..Default::default()
        };
        let r = decode_invocation(target_cap, &args, invoker);
        assert!(matches!(r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_InvalidCapability }))));
        // CR3 unchanged.
        unsafe {
            let t = KERNEL.get().scheduler.slab.get(target);
            assert_eq!(t.cpu_context.cr3, pml4_paddr);
            KERNEL.get().scheduler.slab.free(target);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ TCB::SetSpace pins CR3 from a Cap::PML4\n");
    }

    /// Phase 32c — bind a SchedContext to a TCB.
    ///   1. Retype an Untyped → SchedContext (slot 7).
    ///   2. Plant a TCB cap (slot 8) referring to a freshly admitted
    ///      Tcb in the slab.
    ///   3. Invoke `SchedContextBind(target=SC slot 7, tcb=slot 8)`.
    ///   4. Verify the TCB's `.sc` is Some(idx) and the SC's
    ///      `bound_tcb` is the TCB id.
    ///   5. `Unbind` clears both sides.
    #[inline(never)]
    fn sched_context_bind_unbind() {
        use crate::cap::{SchedContextStorage, UntypedStorage};

        let invoker = setup_invoker(0);

        // Plant an Untyped at slot 0 (radix-5 CNode covers ample
        // space for one SchedContext).
        unsafe {
            KERNEL.get().cnodes[0].0[0] = Cte::with_cap(&Cap::Untyped {
                ptr: PPtr::<UntypedStorage>::new(0x0060_0000).unwrap(),
                block_bits: 14,
                free_index: 0,
                is_device: false,
            });
        }

        // Retype Untyped → SchedContext at slot 7.
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: crate::object_type::ObjectType::SchedContext.to_word(),
            a3: ((crate::object_type::MIN_SCHED_CONTEXT_BITS as u64) << 32) | 1,
            a4: 7,
            ..Default::default()
        };
        let ut_cap = unsafe { KERNEL.get().cnodes[0].0[0].cap() };
        decode_invocation(ut_cap, &args, invoker).expect("retype SC");
        let sc_cap = unsafe { KERNEL.get().cnodes[0].0[7].cap() };
        let sc_idx = match sc_cap {
            Cap::SchedContext { ptr, .. } => {
                let _: PPtr<SchedContextStorage> = ptr;
                KernelState::sched_context_index(ptr)
            }
            other => panic!("expected Cap::SchedContext, got {:?}", other),
        };

        // Admit a target TCB and stash its cap at slot 8.
        let target_tcb = unsafe {
            let mut t = crate::tcb::Tcb::default();
            t.priority = 50;
            KERNEL.get().scheduler.admit(t)
        };
        unsafe {
            KERNEL.get().cnodes[0].0[8] = Cte::with_cap(&Cap::Thread {
                tcb: PPtr::<crate::cap::Tcb>::new(target_tcb.0 as u64).unwrap(),
            });
        }

        // SchedContextBind(target_sc=slot 7, tcb=slot 8).
        let args = SyscallArgs {
            a1: (InvocationLabel::SchedContextBind as u64) << 12,
            a2: 8, // tcb cap_ptr
            ..Default::default()
        };
        decode_invocation(sc_cap, &args, invoker).expect("bind ok");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(target_tcb).sc, Some(sc_idx as u16));
            assert_eq!(s.sched_contexts[sc_idx].bound_tcb, Some(target_tcb));
        }

        // Re-binding the SC (or another SC to this TCB) → DeleteFirst.
        let r = decode_invocation(sc_cap, &args, invoker);
        assert!(matches!(r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_DeleteFirst }))));

        // Unbind clears both sides.
        let args = SyscallArgs {
            a1: (InvocationLabel::SchedContextUnbind as u64) << 12,
            ..Default::default()
        };
        decode_invocation(sc_cap, &args, invoker).expect("unbind ok");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.scheduler.slab.get(target_tcb).sc, None);
            assert_eq!(s.sched_contexts[sc_idx].bound_tcb, None);
            // Clean up.
            s.scheduler.slab.free(target_tcb);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ SchedContextBind / Unbind\n");
    }

    /// Phase 32d — SchedControl::Configure programs an SC's
    /// period+budget. We retype an SC, plant a SchedControl cap
    /// in slot 9, then invoke Configure to set period=100 ms,
    /// budget=20 ms; the SC's fields should reflect the values
    /// and a single ready refill should be queued.
    #[inline(never)]
    fn sched_control_configure_sets_period_budget() {
        use crate::cap::UntypedStorage;

        let invoker = setup_invoker(0);

        // Plant Untyped at slot 0 + retype to SchedContext at slot 7.
        unsafe {
            KERNEL.get().cnodes[0].0[0] = Cte::with_cap(&Cap::Untyped {
                ptr: PPtr::<UntypedStorage>::new(0x0070_0000).unwrap(),
                block_bits: 14,
                free_index: 0,
                is_device: false,
            });
        }
        let ut_cap = unsafe { KERNEL.get().cnodes[0].0[0].cap() };
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: crate::object_type::ObjectType::SchedContext.to_word(),
            a3: ((crate::object_type::MIN_SCHED_CONTEXT_BITS as u64) << 32) | 1,
            a4: 7,
            ..Default::default()
        };
        decode_invocation(ut_cap, &args, invoker).expect("retype SC");

        // Plant a SchedControl singleton cap at slot 9.
        unsafe {
            KERNEL.get().cnodes[0].0[9] =
                Cte::with_cap(&Cap::SchedControl { core: 0 });
        }
        let sched_control = Cap::SchedControl { core: 0 };

        // Invoke Configure(target=slot 7, budget=20, period=100).
        let args = SyscallArgs {
            a0: 7, // target SC cap_ptr
            a1: (InvocationLabel::SchedControlConfigureFlags as u64) << 12,
            a2: 20,  // budget
            a3: 100, // period
            ..Default::default()
        };
        decode_invocation(sched_control, &args, invoker).expect("configure ok");

        // Verify the SC got reprogrammed.
        let sc_idx = match unsafe { KERNEL.get().cnodes[0].0[7].cap() } {
            Cap::SchedContext { ptr, .. } => {
                KernelState::sched_context_index(ptr)
            }
            _ => panic!("expected SchedContext at slot 7"),
        };
        unsafe {
            let sc = &KERNEL.get().sched_contexts[sc_idx];
            assert_eq!(sc.budget, 20);
            assert_eq!(sc.period, 100);
            assert_eq!(sc.count, 1, "should have one ready refill");
            assert_eq!(sc.refills[0].amount, 20);
            assert_eq!(sc.refills[0].release_time, 0);
        }

        // budget > period is rejected as RangeError.
        let args = SyscallArgs {
            a0: 7,
            a1: (InvocationLabel::SchedControlConfigureFlags as u64) << 12,
            a2: 200, // budget
            a3: 100, // period
            ..Default::default()
        };
        let r = decode_invocation(sched_control, &args, invoker);
        assert!(matches!(r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_RangeError }))));

        teardown_invoker(invoker);
        arch::log("  ✓ SchedControl::ConfigureFlags sets period/budget\n");
    }

    #[inline(never)]
    fn unsupported_label_returns_illegal() {
        let invoker = setup_invoker(0);
        let cnode_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        // Pick a cap-type-irrelevant label (UntypedRetype on a CNode).
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            ..Default::default()
        };
        let r = decode_invocation(cnode_cap, &args, invoker);
        match r {
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_IllegalOperation,
            })) => {}
            other => panic!("expected IllegalOperation, got {:?}", other),
        }
        teardown_invoker(invoker);
        arch::log("  ✓ unsupported invocation surfaces IllegalOperation\n");
    }
}
