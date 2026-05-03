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

/// Single-letter tag for the cap kind — used by `inv_log` so the
/// trace fits on one line and is easy to grep for. Keep in sync
/// with the `decode_invocation` match arms.
fn inv_cap_tag(c: &Cap) -> &'static str {
    match c {
        Cap::Untyped { .. }       => "Ut",
        Cap::CNode { .. }         => "Cn",
        Cap::Thread { .. }        => "Tcb",
        Cap::IrqControl           => "IrC",
        Cap::IrqHandler { .. }    => "IrH",
        Cap::Frame { .. }         => "Fr",
        Cap::PageTable { .. }     => "PT",
        Cap::PageDirectory { .. } => "PD",
        Cap::Pdpt { .. }          => "PDPT",
        Cap::PML4 { .. }          => "PML4",
        Cap::AsidControl          => "AsC",
        Cap::AsidPool { .. }      => "AsP",
        Cap::SchedContext { .. }  => "SC",
        Cap::SchedControl { .. }  => "SCtl",
        Cap::Reply { .. }         => "Rep",
        Cap::Endpoint { .. }      => "Ep",
        Cap::Notification { .. }  => "Ntfn",
        Cap::IOPort { .. }        => "IoP",
        Cap::IOPortControl        => "IoPC",
        Cap::Null                 => "Null",
        _                         => "??",
    }
}

/// Print a small u64 in decimal via `crate::arch::log`. Avoids
/// pulling in `format!` in #[no_std].
fn log_dec(mut v: u64) {
    if v == 0 { crate::arch::log("0"); return; }
    let mut buf = [b'0'; 8];
    let mut i = 8;
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

/// One-line trace for an invocation entry — emits e.g.
/// `<inv cap=Ut label=1 xc=0>`. Disabled by default; flip the const
/// to true to enable while diagnosing sel4test failures.
const INV_TRACE: bool = false;

fn inv_log_entry(target: &Cap, label_n: u64, xc: u8) {
    if !INV_TRACE { return; }
    crate::arch::log("<inv cap=");
    crate::arch::log(inv_cap_tag(target));
    crate::arch::log(" label=");
    log_dec(label_n);
    crate::arch::log(" xc=");
    log_dec(xc as u64);
    crate::arch::log(">\n");
}

fn inv_log_exit(result: &KResult<()>) {
    if !INV_TRACE { return; }
    match result {
        Ok(()) => crate::arch::log("<inv ok>\n"),
        Err(KException::SyscallError(SyscallError { code })) => {
            crate::arch::log("<inv ERR=");
            log_dec(*code as u64);
            crate::arch::log(">\n");
        }
        Err(_) => crate::arch::log("<inv ERR=?>\n"),
    }
}

/// Hook called from `handle_send` so SysSend/SysCall entries are
/// visible even when target lookup fails (which short-circuits
/// `decode_invocation`'s own tracing).
pub fn handle_send_log_entry(cptr: u64, mi_word: u64, call: bool) {
    if !INV_TRACE { return; }
    crate::arch::log(if call { "<send call cptr=" } else { "<send cptr=" });
    log_hex(cptr);
    let info = crate::types::seL4_MessageInfo_t { words: [mi_word] };
    crate::arch::log(" label=");
    log_dec(info.label());
    crate::arch::log(" len=");
    log_dec(info.length() as u64);
    crate::arch::log(" xc=");
    log_dec(info.extra_caps() as u64);
    crate::arch::log(">\n");
}

pub fn handle_send_log_lookup_err(e: &KException) {
    if !INV_TRACE { return; }
    match e {
        KException::SyscallError(SyscallError { code }) => {
            crate::arch::log("<send-lookup-ERR=");
            log_dec(*code as u64);
            crate::arch::log(">\n");
        }
        _ => crate::arch::log("<send-lookup-ERR=?>\n"),
    }
}

fn log_hex(mut v: u64) {
    crate::arch::log("0x");
    if v == 0 { crate::arch::log("0"); return; }
    let mut buf = [b'0'; 16];
    let mut i = 16;
    while v > 0 && i > 0 {
        i -= 1;
        let nib = (v & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        v >>= 4;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

/// Like `log_hex` but without the `0x` prefix — for inline use.
pub fn log_hex_u64(mut v: u64) {
    if v == 0 { crate::arch::log("0"); return; }
    let mut buf = [b'0'; 16];
    let mut i = 16;
    while v > 0 && i > 0 {
        i -= 1;
        let nib = (v & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        v >>= 4;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

/// Decode an invocation against a non-Endpoint cap. Called from
/// the IPC dispatcher when SysSend/SysCall targets a non-IPC cap.
pub fn decode_invocation(
    target: Cap,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    // Decode the invocation label from MessageInfo.
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let label_n = info.label();
    let xc_count = unsafe {
        KERNEL.get().scheduler.slab.get(invoker).pending_extra_caps_count
    };
    inv_log_entry(&target, label_n, xc_count);

    let label = match InvocationLabel::from_u64(label_n) {
        Some(l) => l,
        None => {
            let r = Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidArgument)));
            inv_log_exit(&r);
            return r;
        }
    };
    let result = match target {
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
        Cap::Reply { .. } => decode_reply(target, args, invoker),
        Cap::IOPort { first_port, last_port } => {
            decode_io_port(first_port, last_port, label, args, invoker)
        }
        Cap::IOPortControl => decode_io_port_control(label, args, invoker),
        Cap::Null => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidCapability,
        ))),
        // Other cap types not yet wired — surface InvalidCapability
        // so user code spots the gap rather than silently no-op.
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    };
    inv_log_exit(&result);
    result
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

/// `X86Page::Map(vaddr, rights, [vspace_cptr])` — install the frame
/// at `vaddr` in a vspace. We only handle 4 KiB pages today;
/// large/huge fall through with InvalidArgument.
///
/// ABI: a2 = vaddr, a3 = rights word (FrameRights encoding),
/// a4 = vspace cap_ptr (0 = current CR3 — backward-compatible
/// default; non-zero = invoker-owned PML4 cap to map the frame
/// into, used by the Phase 33d multi-vspace path).
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
    let vaddr = args.a2;
    if let Some(prev) = current_mapped {
        // Upstream `decodeX86FrameMapInvocation` allows re-mapping a
        // Frame cap at the *same* vaddr as a no-op. Different vaddr
        // requires Unmap first.
        if prev == vaddr {
            return Ok(());
        }
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_DeleteFirst,
        )));
    }
    let rights = crate::cap::FrameRights::from_word(args.a3);
    let writable = matches!(rights, crate::cap::FrameRights::ReadWrite);

    // Two wire formats coexist:
    //   * Phase 33d (compressed, microtest): args.a4 = vspace_cptr.
    //     extra_caps == 0.
    //   * Phase 42 upstream (sel4test): vspace passed as extraCaps[0],
    //     args.a4 = attr (we ignore — caching not yet modelled).
    //     Distinguished by msginfo.extra_caps() > 0.
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let upstream = info.extra_caps() > 0;

    if vaddr & 0xFFF != 0 {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_AlignmentError,
        )));
    }

    unsafe {
        let pml4_paddr_opt: Option<u64> = if upstream {
            let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
            let count = inv_tcb.pending_extra_caps_count as usize;
            let cap = if count > 0 {
                Some(inv_tcb.pending_extra_caps[0])
            } else {
                None
            };
            inv_tcb.pending_extra_caps_count = 0;
            match cap {
                Some(Cap::PML4 { ptr, .. }) => Some(ptr.addr()),
                _ => return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability))),
            }
        } else if args.a4 != 0 {
            let cspace_root = KERNEL.get().scheduler.slab.get(invoker).cspace_root;
            let pml4_cap = crate::cspace::lookup_cap(KERNEL.get(), &cspace_root, args.a4)?;
            match pml4_cap {
                Cap::PML4 { ptr, .. } => Some(ptr.addr()),
                _ => return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability))),
            }
        } else {
            None
        };

        if let Some(pml4_paddr) = pml4_paddr_opt {
            if let Err(missing) = usermode::map_user_4k_into_foreign_pml4(
                pml4_paddr, vaddr, paddr, writable)
            {
                // map_user_4k_into_foreign_pml4 returns 1..4 for the
                // *level whose entry is empty*. The next-higher
                // table needs to be allocated + installed. Translate
                // to seL4_MappingFailedLookupLevel() bit-positions:
                //   missing=1 (PML4 entry empty)  → need PDPT (39)
                //   missing=2 (PDPT entry empty)  → need PD   (30)
                //   missing=3 (PD entry empty)    → need PT   (21)
                //   missing=4 (PT slot busy)      → DeleteFirst.
                if missing == 4 {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst)));
                }
                let level: u64 = match missing {
                    1 => 39, // PML4 entry empty → need PDPT
                    2 => 30, // PDPT entry empty → need PD
                    _ => 21, // PD entry empty   → need PT
                };
                let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
                inv_tcb.msg_regs[2] = level;
                // Must encompass mr2, so length >= 3.
                inv_tcb.ipc_length = 3;
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_FailedLookup)));
            }
        } else {
            usermode::map_user_4k_public(vaddr, paddr, writable);
        }
    }

    // Update the cap to reflect the mapping. We need to find the
    // source slot that holds this Frame cap and rewrite it. Walk
    // the invoker's CSpace, matching paddr AND `mapped == None` so
    // we update the FRESH (just-being-mapped) cap rather than a
    // sibling like a userImageFrame that already has its own
    // mapped vaddr — same hazard as in `decode_frame_unmap`.
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let cnode_ptr = match cspace_root {
            Cap::CNode { ptr, .. } => ptr,
            _ => return Ok(()),
        };
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        for slot in s.cnodes[cnode_idx].0.iter_mut() {
            if let Cap::Frame { ptr, mapped: None, .. } = slot.cap() {
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

    // Phase 28g / 42 — actually clear the PTE in the live page
    // tables and fan a TLB shootdown to other CPUs.
    // `unmap_user_4k_public` walks page tables via the linear map
    // and silently no-ops if any intermediate level is missing
    // (which is the spec-test case where the cap chain doesn't
    // back a real mapping), so we no longer need the spec gate
    // we previously had — and skipping the hardware step in spec
    // mode meant sel4test's Frame_Unmap left stale PTEs that the
    // next allocator-recycled Frame_Map then tripped over with
    // DeleteFirst.
    #[cfg(target_arch = "x86_64")]
    if let Some(vaddr) = mapped_vaddr {
        unsafe {
            crate::arch::x86_64::usermode::unmap_user_4k_public(vaddr);
            crate::smp::shootdown_tlb(vaddr);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = mapped_vaddr;

    // Walk the CSpace and zero the mapping in the matching cap.
    // Match BOTH paddr AND mapped-vaddr — multiple caps in the same
    // CSpace can share a paddr (e.g. a userImageFrame at one vaddr +
    // a sel4test-allocated copy at a different vaddr), and we need
    // to clear the specific cap the user invoked, not the first one
    // we trip over while iterating. Without the mapped-vaddr match,
    // sel4test's ELF loader Unmap would clear a userImageFrame's
    // mapping while leaving the loader_frame_cap stuck on its old
    // vaddr, and the next iteration's Map would reject with
    // DeleteFirst.
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let cnode_ptr = match cspace_root {
            Cap::CNode { ptr, .. } => ptr,
            _ => return Ok(()),
        };
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        for slot in s.cnodes[cnode_idx].0.iter_mut() {
            if let Cap::Frame { ptr, size, rights, is_device, mapped, .. } = slot.cap() {
                if ptr.addr() == paddr && mapped == mapped_vaddr {
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
///
/// ABI: a2 = vaddr, a3 = vspace cap_ptr (0 = current CR3 —
/// backward-compatible default; non-zero = invoker-owned PML4 cap
/// added by Phase 33d for multi-vspace setup).
fn map_paging_struct(
    target: Cap,
    args: &SyscallArgs,
    invoker: TcbId,
    level: u32,
) -> KResult<()> {
    use crate::arch::x86_64::usermode;
    let (paddr, current_mapped) = paging_struct_state(&target);
    if current_mapped.is_some() {
        if INV_TRACE {
            crate::arch::log("[map.lvl=");
            log_dec(level as u64);
            crate::arch::log(" cap-already-mapped@0x");
            log_hex_u64(current_mapped.unwrap());
            crate::arch::log("]\n");
        }
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

    // Two wire formats coexist:
    //   * Phase 33d compressed (microtest): args.a3 = vspace_cptr,
    //     extra_caps == 0.
    //   * Phase 42 upstream (sel4test): vspace via extraCaps[0],
    //     args.a3 = attrs (ignored — caching not yet modelled).
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let upstream = info.extra_caps() > 0;

    let installed = unsafe {
        let pml4_paddr_opt: Option<u64> = if upstream {
            let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
            let count = inv_tcb.pending_extra_caps_count as usize;
            let cap = if count > 0 {
                Some(inv_tcb.pending_extra_caps[0])
            } else {
                None
            };
            inv_tcb.pending_extra_caps_count = 0;
            match cap {
                Some(Cap::PML4 { ptr, .. }) => Some(ptr.addr()),
                _ => return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability))),
            }
        } else if args.a3 != 0 {
            let cspace_root = KERNEL.get().scheduler.slab.get(invoker).cspace_root;
            let pml4_cap = crate::cspace::lookup_cap(
                KERNEL.get(), &cspace_root, args.a3)?;
            match pml4_cap {
                Cap::PML4 { ptr, .. } => Some(ptr.addr()),
                _ => return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability))),
            }
        } else {
            None
        };

        if let Some(pml4_paddr) = pml4_paddr_opt {
            usermode::install_user_table_in_paddr(pml4_paddr, level, vaddr, paddr)
        } else {
            #[cfg(not(feature = "spec"))]
            { usermode::install_user_table(level, vaddr, paddr) }
            #[cfg(feature = "spec")]
            { let _ = (level, vaddr, paddr); Ok(()) }
        }
    };
    if let Err(missing_level) = installed {
        if missing_level == 0 {
            // Either the level is bogus or the target slot is
            // already populated.
            if INV_TRACE {
                crate::arch::log("[map.lvl=");
                log_dec(level as u64);
                crate::arch::log(" pd-slot-busy vaddr=0x");
                log_hex_u64(vaddr);
                crate::arch::log("]\n");
            }
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        // Stage missing-level for seL4_MappingFailedLookupLevel.
        unsafe {
            let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
            inv_tcb.msg_regs[2] = missing_level as u64;
            inv_tcb.ipc_length = 3;
        }
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_FailedLookup,
        )));
    }

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
/// by 512 (one pool's worth of ASIDs). Phase 37a reserves bases
/// 0..511 for the rootserver's pre-allocated `InitThreadASIDPool`
/// at slot 6, so the first runtime MakePool returns base 512.
static NEXT_ASID_BASE: core::sync::atomic::AtomicU16 =
    core::sync::atomic::AtomicU16::new(512);

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
            // Two ABI shapes coexist:
            //   * Upstream (libsel4 stub `seL4_X86_ASIDPool_Assign`):
            //     vspace cap passed as `extraCaps[0]`. Tag carries
            //     `extra_caps=1`. The cptr the sender used appears
            //     in the IPC buffer at `caps_or_badges_offset[0]`.
            //   * Legacy (internal specs): vspace cap_ptr in `a2`.
            //     No extra caps.
            let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
            let upstream = info.extra_caps() > 0;
            unsafe {
                let s = KERNEL.get();
                let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let (slot_cnode_idx, slot_idx, vspace_cap) = if upstream {
                    let inv_tcb = s.scheduler.slab.get(invoker);
                    if inv_tcb.pending_extra_caps_count == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    let cap = inv_tcb.pending_extra_caps[0];
                    let buf_paddr = inv_tcb.ipc_buffer_paddr;
                    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
                    if buf_paddr == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    let buf = crate::arch::x86_64::paging::phys_to_lin(buf_paddr)
                        as *const u64;
                    let cptr = core::ptr::read_volatile(
                        buf.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET));
                    let res = crate::cspace::resolve_address_bits(
                        s, &invoker_cspace, cptr, 64)?;
                    if res.bits_remaining != 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_FailedLookup)));
                    }
                    (KernelState::cnode_index(res.slot_ptr), res.slot_index, cap)
                } else {
                    let cnode_ptr = match invoker_cspace {
                        Cap::CNode { ptr, .. } => ptr,
                        _ => return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability))),
                    };
                    let cnode_idx = KernelState::cnode_index(cnode_ptr);
                    let slot_idx = args.a2 as usize;
                    let slots = &s.cnodes[cnode_idx].0;
                    if slot_idx >= slots.len() {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_RangeError)));
                    }
                    (cnode_idx, slot_idx, slots[slot_idx].cap())
                };
                let (ptr, mapped) = match vspace_cap {
                    Cap::PML4 { ptr, mapped, asid: 0 } => (ptr, mapped),
                    Cap::PML4 { .. } => return Err(KException::SyscallError(
                        SyscallError::new(seL4_Error::seL4_DeleteFirst))),
                    _ => return Err(KException::SyscallError(
                        SyscallError::new(seL4_Error::seL4_InvalidCapability))),
                };
                // Allocate the next ASID in this pool. Phase 31 is a
                // coarse first cut — proper allocation tracking lives
                // in the AsidPool storage page (asid_map[]) once we
                // plumb it.
                let assigned = asid_base.saturating_add(
                    (NEXT_ASID_OFFSET.fetch_add(
                        1, core::sync::atomic::Ordering::Relaxed,
                    ) & 0x1FF) as u16,
                );
                let slot = &mut s.cnodes[slot_cnode_idx].0[slot_idx];
                slot.set_cap(&Cap::PML4 { ptr, mapped, asid: assigned });
                Ok(())
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
// Phase 36d — Reply cap invocations. Send on a Cap::Reply wakes
// the TCB the kernel bound to it during the originating Call. The
// reply message rides in args.a2..a5 (and the IPC buffer for
// length > 4). Mirrors seL4 MCS's `seL4_Send(replyCap, msginfo)`.
// ---------------------------------------------------------------------------

fn decode_reply(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let reply_ptr = match target {
        Cap::Reply { ptr, .. } => ptr,
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let idx = KernelState::reply_index(reply_ptr);
        let caller = match s.replies[idx].bound_tcb {
            Some(c) => c,
            None => return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability))),
        };
        // Stage the reply message on the invoker so the existing
        // transfer machinery (used by handle_reply too) sees the
        // right msg_regs. Then route through `do_reply_transfer`.
        let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
        {
            let me = s.scheduler.slab.get_mut(invoker);
            me.ipc_label = info.label();
            me.ipc_length = info.length() as u32;
            me.msg_regs[0] = args.a2;
            me.msg_regs[1] = args.a3;
            me.msg_regs[2] = args.a4;
            me.msg_regs[3] = args.a5;
        }
        // Read words 4..length from the invoker's IPC buffer if
        // the message is longer than the register fast-path.
        {
            let me = s.scheduler.slab.get_mut(invoker);
            let length = me.ipc_length as usize;
            if length > 4 && me.ipc_buffer_paddr != 0 {
                let buf = (crate::arch::x86_64::paging::phys_to_lin(
                    me.ipc_buffer_paddr) as *const u64).wrapping_add(1);
                let max = length.min(me.msg_regs.len());
                for i in 4..max {
                    me.msg_regs[i] = core::ptr::read_volatile(buf.add(i));
                }
            }
        }
        // Transfer payload caller-ward and wake them.
        let (label, length, regs) = {
            let me = s.scheduler.slab.get(invoker);
            (me.ipc_label, me.ipc_length, me.msg_regs)
        };
        {
            let r = s.scheduler.slab.get_mut(caller);
            r.ipc_label = label;
            r.ipc_length = length;
            r.ipc_badge = 0;
            let n = (length as usize).min(r.msg_regs.len());
            r.msg_regs[..n].copy_from_slice(&regs[..n]);
            // Mirror words 4..length into the caller's IPC buffer.
            if length > 4 && r.ipc_buffer_paddr != 0 {
                let buf = (crate::arch::x86_64::paging::phys_to_lin(
                    r.ipc_buffer_paddr) as *mut u64).wrapping_add(1);
                let max = (length as usize).min(regs.len());
                for i in 4..max {
                    core::ptr::write_volatile(buf.add(i), regs[i]);
                }
            }
            // Fan the reply into the caller's saved user_context
            // so its blocked SysCall returns with the right
            // register values. Mirrors the receive-side fan-in
            // that `endpoint::transfer` does for SysRecv.
            #[cfg(target_arch = "x86_64")]
            {
                let mi = (label << 12) | (length as crate::types::seL4_Word & 0x7F);
                // Phase 38c-followup — rax is preserved across
                // SYSCALL (matches upstream). Reply success is
                // signalled via the IPC label, not via rax.
                r.user_context.rsi = mi;
                r.user_context.rdi = 0;
                // Upstream seL4 IPC return ABI: msg_regs -> r10/r8/r9/r15.
                r.user_context.r10 = r.msg_regs[0];
                r.user_context.r8  = r.msg_regs[1];
                r.user_context.r9  = r.msg_regs[2];
                r.user_context.r15 = r.msg_regs[3];
            }
        }
        debug_assert!(matches!(
            s.scheduler.slab.get(caller).state,
            crate::tcb::ThreadStateType::BlockedOnReply
        ));
        // Phase 33c — return the donated SC.
        s.scheduler.slab.get_mut(invoker).active_sc = None;
        s.scheduler.make_runnable(caller);
        // Clear the reply binding — the slot is reusable for the
        // next Call once the receiver Recv's on the same Reply
        // cap (or a different one).
        s.replies[idx].bound_tcb = None;
        // Also clear the legacy stash so a stale `reply_to`
        // doesn't double-wake.
        s.scheduler.slab.get_mut(invoker).reply_to = None;
        Ok(())
    }
}

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
            // Two ABI shapes:
            //   * Upstream (libsel4 stub): TCB cap via extraCaps[0].
            //   * Legacy: a2 = TCB cap_ptr in invoker's CSpace.
            let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
            let upstream = info.extra_caps() > 0;
            unsafe {
                let s = KERNEL.get();
                let tcb_cap = if upstream {
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    if inv_tcb.pending_extra_caps_count == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    let c = inv_tcb.pending_extra_caps[0];
                    inv_tcb.pending_extra_caps_count = 0;
                    c
                } else {
                    let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
                    crate::cspace::lookup_cap(s, &invoker_cspace, args.a2)?
                };
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
// programs the named SchedContext's refill schedule. The SysSend
// ABI puts the SchedControl cap itself in `a0` (the cap whose
// invocation we're decoding), so the target SC cptr has to ride
// along in a different slot:
//   a0 = invoking SchedControl cap_ptr (consumed by handle_send)
//   a2 = target SC cap_ptr
//   a3 = budget    (ticks)
//   a4 = period    (ticks)
// Real seL4 hands the SC over via the message's extra-caps area,
// but we don't model extra caps yet — this in-line layout is the
// minimum needed for the rootserver demo.
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
            // Two ABI shapes coexist:
            //   * Upstream (libsel4 stub `seL4_SchedControl_ConfigureFlags`):
            //       mr0=budget, mr1=period, mr2=extra_refills,
            //       mr3=badge, mr4=flags, extraCaps[0]=SchedContext.
            //   * Legacy (microtest):
            //       a2 = SC cap_ptr, a3 = budget, a4 = period.
            let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
            let upstream = info.extra_caps() > 0;
            let (sc_cap_opt, budget, period) = if upstream {
                unsafe {
                    let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
                    let cap = if inv_tcb.pending_extra_caps_count > 0 {
                        Some(inv_tcb.pending_extra_caps[0])
                    } else { None };
                    inv_tcb.pending_extra_caps_count = 0;
                    (cap, args.a2, args.a3)
                }
            } else {
                unsafe {
                    let s = KERNEL.get();
                    let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
                    let cap = crate::cspace::lookup_cap(s, &invoker_cspace, args.a2)?;
                    (Some(cap), args.a3, args.a4)
                }
            };
            unsafe {
                let s = KERNEL.get();
                let sc_idx = match sc_cap_opt {
                    Some(Cap::SchedContext { ptr, .. }) => {
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
        // Phase 42 — sel4test on x86 only uses the platform-specific
        // IRQControl variants (the generic IRQIssueIRQHandler is for
        // ARM/RISC-V). GetIOAPIC takes 7 message words plus the dest
        // root cap as extraCap[0]:
        //   msg_regs[0] = index (cptr to dest slot)
        //   msg_regs[1] = depth (bits to resolve under root)
        //   msg_regs[2] = ioapic id (ignored for now)
        //   msg_regs[3] = pin       (ignored — we don't program IOAPIC
        //                            redirection from this path yet;
        //                            the kernel's existing PIT/PIC
        //                            wiring delivers IRQs at fixed
        //                            vectors)
        //   msg_regs[4] = level     (ignored)
        //   msg_regs[5] = polarity  (ignored)
        //   msg_regs[6] = vector    — the IRQ number sel4test will
        //                            ack/wait on; matches the kernel's
        //                            internal `irq` numbering.
        InvocationLabel::X86IRQIssueIRQHandlerIOAPIC => {
            issue_x86_irq_handler(args, invoker, /* msi */ false)
        }
        InvocationLabel::X86IRQIssueIRQHandlerMSI => {
            // MSI variant — same dest-cap wiring, ignore PCI fields.
            // msg_regs[6] is also the vector here (MSI handler-vector
            // semantics differ from IOAPIC routing but the cap is
            // analogous).
            issue_x86_irq_handler(args, invoker, /* msi */ true)
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// Common worker for `X86IRQIssueIRQHandlerIOAPIC` /
/// `X86IRQIssueIRQHandlerMSI`. Resolves the destination slot via
/// `extraCaps[0]` + `(index, depth)` and stamps a fresh
/// `Cap::IrqHandler` at that slot. For the IOAPIC variant, also
/// programs the IOAPIC redirection-table entry so the requested
/// pin actually delivers `vector` to the BSP (otherwise the line
/// stays masked and the user's handler never fires).
fn issue_x86_irq_handler(
    args: &SyscallArgs,
    invoker: TcbId,
    msi: bool,
) -> KResult<()> {
    unsafe {
        let s = KERNEL.get();
        let inv_tcb = s.scheduler.slab.get_mut(invoker);
        let dest_cptr = inv_tcb.msg_regs[0];
        let depth = inv_tcb.msg_regs[1] as u32;
        let _ioapic_id = inv_tcb.msg_regs[2];
        let pin = inv_tcb.msg_regs[3];
        let level = inv_tcb.msg_regs[4];
        let polarity = inv_tcb.msg_regs[5];
        let vector = inv_tcb.msg_regs[6];
        let dest_root = if inv_tcb.pending_extra_caps_count > 0 {
            inv_tcb.pending_extra_caps[0]
        } else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability)));
        };
        inv_tcb.pending_extra_caps_count = 0;

        if !matches!(dest_root, Cap::CNode { .. }) {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability)));
        }
        let res = crate::cspace::resolve_address_bits(s, &dest_root, dest_cptr, depth)?;
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        let slot = &mut s.cnodes[cnode_idx].0[res.slot_index];
        if !slot.cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst)));
        }
        // Phase 42 — store the user-visible "vector" as the IRQ
        // table index in the cap. seL4_IRQHandler_Ack /
        // SetNotification will resolve the same index against
        // KernelState.irqs, and our generic IRQ ISR (irq{N}_entry →
        // irq_dispatch) calls handle_interrupt with this index.
        slot.set_cap(&Cap::IrqHandler { irq: vector as u16 });

        // Program the hardware so the line actually fires.
        //
        // Upstream seL4 maps the user-visible vector to a CPU IDT
        // vector via `cpu_vec = irq + IRQ_INT_OFFSET`; we mirror
        // that with `cpu_vec = vector + PIC1_VECTOR_BASE` so the
        // IOAPIC delivers to one of our `irq{N}_entry` stubs at
        // IDT[0x20 + N], which routes through `irq_dispatch(_, N)`.
        // Without this translation we'd write the raw user value
        // (e.g. 2 for the PIT-via-IOAPIC pin 2) into the redirection
        // table and the CPU would receive vector 2 (NMI).
        // MSI variant goes through PCI config space — TODO.
        if !msi {
            #[cfg(target_arch = "x86_64")]
            {
                let cpu_vec = (vector as u32)
                    + crate::arch::x86_64::pic::PIC1_VECTOR_BASE as u32;
                crate::arch::x86_64::ioapic::program_redirection(
                    pin as u32, cpu_vec, level as u32, polarity as u32,
                );
            }
        }
        let _ = (pin, level, polarity);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// X86 I/O port invocations.
//
// Each `Cap::IOPort` carries an inclusive `[first, last]` port window.
// In*/Out* invocations check the requested port against that window
// and then issue the actual `in`/`out` instruction in kernel mode.
// `seL4_X86_IOPortControl_Issue` mints a fresh `Cap::IOPort` with
// caller-supplied `(first, last)` from the singleton control cap.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn io_in8(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v,
        options(nomem, nostack, preserves_flags));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_in16(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", in("dx") port, out("ax") v,
        options(nomem, nostack, preserves_flags));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_in32(port: u16) -> u32 {
    let v: u32;
    core::arch::asm!("in eax, dx", in("dx") port, out("eax") v,
        options(nomem, nostack, preserves_flags));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_out8(port: u16, v: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") v,
        options(nomem, nostack, preserves_flags));
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_out16(port: u16, v: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") v,
        options(nomem, nostack, preserves_flags));
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_out32(port: u16, v: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") v,
        options(nomem, nostack, preserves_flags));
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_in8(_p: u16) -> u8 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_in16(_p: u16) -> u16 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_in32(_p: u16) -> u32 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_out8(_p: u16, _v: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_out16(_p: u16, _v: u16) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_out32(_p: u16, _v: u32) {}

fn decode_io_port(
    first_port: u16,
    last_port: u16,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    // ABI for In/Out:
    //   a2 (mr0) = port number (low 16 bits)
    //   a3 (mr1) = value to write (Out only)
    // In ops return the read value via msg_regs[0] (and the SysCall
    // reply path in handle_send fans it back into r10 + IPC buffer).
    let port = (args.a2 & 0xFFFF) as u16;
    if port < first_port || port > last_port {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_RangeError)));
    }
    unsafe {
        let s = KERNEL.get();
        match label {
            InvocationLabel::X86IOPortIn8 => {
                let v = io_in8(port) as u64;
                let inv_tcb = s.scheduler.slab.get_mut(invoker);
                inv_tcb.msg_regs[0] = v;
                inv_tcb.ipc_length = 1;
            }
            InvocationLabel::X86IOPortIn16 => {
                let v = io_in16(port) as u64;
                let inv_tcb = s.scheduler.slab.get_mut(invoker);
                inv_tcb.msg_regs[0] = v;
                inv_tcb.ipc_length = 1;
            }
            InvocationLabel::X86IOPortIn32 => {
                let v = io_in32(port) as u64;
                let inv_tcb = s.scheduler.slab.get_mut(invoker);
                inv_tcb.msg_regs[0] = v;
                inv_tcb.ipc_length = 1;
            }
            InvocationLabel::X86IOPortOut8 => {
                io_out8(port, args.a3 as u8);
            }
            InvocationLabel::X86IOPortOut16 => {
                io_out16(port, args.a3 as u16);
            }
            InvocationLabel::X86IOPortOut32 => {
                io_out32(port, args.a3 as u32);
            }
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_IllegalOperation)));
            }
        }
    }
    Ok(())
}

fn decode_io_port_control(
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    if !matches!(label, InvocationLabel::X86IOPortControlIssue) {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation)));
    }
    // Upstream `seL4_X86_IOPortControl_Issue` ABI:
    //   a2 (mr0) = first_port
    //   a3 (mr1) = last_port
    //   extraCaps[0] = dest root cap (CNode under which the issued
    //                  IOPort cap lands)
    //   mr2 = dest_index, mr3 = dest_depth
    let first = (args.a2 & 0xFFFF) as u16;
    let last = (args.a3 & 0xFFFF) as u16;
    if first > last {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidArgument)));
    }
    unsafe {
        let s = KERNEL.get();
        let inv_tcb = s.scheduler.slab.get_mut(invoker);
        let dest_index = inv_tcb.msg_regs[2];
        let depth = inv_tcb.msg_regs[3] as u32;
        let dest_root = if inv_tcb.pending_extra_caps_count > 0 {
            let c = inv_tcb.pending_extra_caps[0];
            inv_tcb.pending_extra_caps_count = 0;
            c
        } else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability)));
        };
        if !matches!(dest_root, Cap::CNode { .. }) {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability)));
        }
        let res = crate::cspace::resolve_address_bits(s, &dest_root, dest_index, depth)?;
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        let slot = &mut s.cnodes[cnode_idx].0[res.slot_index];
        if !slot.cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst)));
        }
        slot.set_cap(&Cap::IOPort { first_port: first, last_port: last });
    }
    Ok(())
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
                // Two ABI shapes:
                //   * legacy (microtest): a2 = cptr to Notification
                //     in invoker's CSpace.
                //   * upstream (sel4test): notification passed as
                //     extraCaps[0]; no message words.
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                let upstream = info.extra_caps() > 0;
                let inv_tcb = s.scheduler.slab.get_mut(invoker);
                let ntfn_cap = if upstream {
                    if inv_tcb.pending_extra_caps_count == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    let c = inv_tcb.pending_extra_caps[0];
                    inv_tcb.pending_extra_caps_count = 0;
                    c
                } else {
                    let cspace_root = inv_tcb.cspace_root;
                    crate::cspace::lookup_cap(s, &cspace_root, args.a2)?
                };
                let (ntfn_ptr, ntfn_badge) = match ntfn_cap {
                    Cap::Notification { ptr, badge, .. } => (ptr, badge.0),
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                let ntfn_idx = KernelState::ntfn_index(ntfn_ptr) as u16;
                // Replace any existing handler binding and install
                // the new one. The badge from the badged cap is
                // recorded on the IRQ entry so handle_interrupt can
                // signal with it (sel4test minted BIT(N) per timer).
                let _ = crate::interrupt::clear_handler(&mut s.irqs, irq);
                crate::interrupt::set_notification(&mut s.irqs, irq, ntfn_idx, ntfn_badge)
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
/// dest_offset, num_objects)`. Two wire formats coexist:
///
///   * Legacy compressed (Phase 16, microtest + early kernel specs;
///     msginfo.extra_caps == 0):
///       a2 = object_type word
///       a3 = (size_bits << 32) | num_objects
///       a4 = dest_offset
///       (root defaults to invoker's CSpace root CNode)
///
///   * Phase 42 upstream (sel4test via libsel4; msginfo.extra_caps == 1):
///       a2 (= mr0) = type
///       a3 (= mr1) = size_bits
///       a4 (= mr2) = node_index (offset within root cap)
///       a5 (= mr3) = node_depth (radix bits to walk root)
///       ipc_buf[4] = node_offset (slot offset of first child)
///       ipc_buf[5] = num_objects
///       extraCaps[0] = root (the destination CNode cap)
fn decode_untyped_retype(
    target: Cap,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let upstream = info.extra_caps() > 0;

    if upstream && INV_TRACE {
        let inv_tcb = unsafe { KERNEL.get().scheduler.slab.get(invoker) };
        crate::arch::log("[ut t=");
        log_dec(args.a2);
        crate::arch::log(" sb=");
        log_dec(args.a3);
        crate::arch::log(" off=");
        log_dec(inv_tcb.msg_regs[4]);
        crate::arch::log(" n=");
        log_dec(inv_tcb.msg_regs[5]);
        crate::arch::log(" base=0x");
        log_hex_u64(unsafe {
            crate::untyped::UntypedState::from_cap(&target).map(|s| s.base).unwrap_or(0)
        });
        crate::arch::log(" fi=0x");
        log_hex_u64(unsafe {
            crate::untyped::UntypedState::from_cap(&target).map(|s| s.free_index_bytes).unwrap_or(0)
        });
        crate::arch::log(" bb=");
        log_dec(unsafe {
            crate::untyped::UntypedState::from_cap(&target).map(|s| s.block_bits as u64).unwrap_or(0)
        });
        crate::arch::log("]\n");
    }

    // Phase 42 — full upstream ABI for the destination cap layout:
    //   extraCaps[0] = root cap (dest CSpace root)
    //   args.a4 (mr2) = node_index — cptr to dest CNode under root
    //   args.a5 (mr3) = node_depth — bits to walk for node_index
    //   msg_regs[4]   = node_offset — offset within dest CNode
    //   msg_regs[5]   = num_objects
    // When node_depth == 0, the root cap itself is the dest CNode.
    // Without this, sel4test's allocman (which carves through a
    // sub-CNode it built for its bookkeeping) would have all its
    // children land in the rootserver's flat root CNode, colliding
    // with later device-UT bisects targeting the same offsets.
    let (object_type, size_bits, num_objects, node_index, node_depth, node_offset, root_cap_opt) =
        if upstream {
            let invoker_tcb = unsafe {
                KERNEL.get().scheduler.slab.get(invoker)
            };
            let node_offset = invoker_tcb.msg_regs[4] as usize;
            let num = invoker_tcb.msg_regs[5];
            let root_cap = if invoker_tcb.pending_extra_caps_count > 0 {
                Some(invoker_tcb.pending_extra_caps[0])
            } else {
                None
            };
            (
                ObjectType::from_word(args.a2),
                args.a3 as u32,
                num,
                args.a4,
                args.a5 as u32,
                node_offset,
                root_cap,
            )
        } else {
            (
                ObjectType::from_word(args.a2),
                (args.a3 >> 32) as u32,
                args.a3 & 0xFFFF_FFFF,
                0,
                0,
                args.a4 as usize,
                None,
            )
        };
    // Drain pending_extra_caps so they don't leak into the next IPC.
    unsafe {
        KERNEL.get().scheduler.slab.get_mut(invoker)
            .pending_extra_caps_count = 0;
    }

    let mut state = match crate::untyped::UntypedState::from_cap(&target) {
        Some(s) => s,
        None => {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
    };

    let dest_offset = node_offset;

    // Resolve the destination CNode. When extraCaps[0] is provided
    // (upstream path), walk it with node_depth bits to land on the
    // actual dest CNode. Otherwise fall back to the invoker's
    // cspace_root — keeps the legacy microtest path working.
    unsafe {
        let s = KERNEL.get();
        let dest_cnode_cap: Cap = if let Some(root_cap) = root_cap_opt {
            if node_depth == 0 {
                // Per upstream: depth=0 means use root cap directly
                // as the destination CNode.
                root_cap
            } else {
                let res = crate::cspace::resolve_address_bits(
                    s, &root_cap, node_index, node_depth)?;
                if res.bits_remaining != 0 {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_FailedLookup)));
                }
                let cnode_idx = KernelState::cnode_index(res.slot_ptr);
                s.cnodes[cnode_idx].0[res.slot_index].cap()
            }
        } else {
            s.scheduler.slab.get(invoker).cspace_root
        };
        let cnode_ptr = match dest_cnode_cap {
            Cap::CNode { ptr, .. } => ptr,
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )));
            }
        };
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        if INV_TRACE {
            crate::arch::log("[ut.dst cn=");
            log_dec(cnode_idx as u64);
            crate::arch::log(" sl=");
            log_dec(dest_offset as u64);
            crate::arch::log(" ni=0x");
            log_hex_u64(node_index);
            crate::arch::log(" nd=");
            log_dec(node_depth as u64);
            crate::arch::log("]\n");
        }
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
                    Cap::Reply { can_grant, .. } => {
                        let i = (*s_ptr).alloc_reply()
                            .expect("reply pool exhausted");
                        Cap::Reply {
                            ptr: KernelState::reply_ptr(i),
                            can_grant,
                        }
                    }
                    // Phase 33d — when the rootserver retypes a fresh
                    // PML4, copy the live PML4's entries into it so
                    // the new vspace has the kernel half mapped. Any
                    // thread we later dispatch with this PML4 needs
                    // those entries to enter the kernel from SYSCALL
                    // (gs:-relative loads of PER_CPU_SYSCALL hit the
                    // kernel half) and to take page faults.
                    #[cfg(target_arch = "x86_64")]
                    Cap::PML4 { ptr, mapped, asid } => {
                        let new_paddr = ptr.addr();
                        crate::arch::x86_64::paging::clone_live_pml4_to_paddr(new_paddr);
                        Cap::PML4 { ptr, mapped, asid }
                    }
                    other => other,
                };
                // Phase 42 — seL4 zeroes the underlying memory of
                // every newly-retyped object (other than Untyped, which
                // doesn't expose its bytes). For paging structs this
                // is load-bearing: a fresh PD whose bytes look like
                // valid PTE_PRESENT entries makes the page-table walk
                // descend into garbage and the leaf Map then returns
                // DeleteFirst. Frames are zeroed for the usual
                // security reason.
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::cap::FrameSize;
                    let zero_range: Option<(u64, u64)> = match cap_to_store {
                        Cap::PageTable { ptr, .. } => Some((ptr.addr(), 4096)),
                        Cap::PageDirectory { ptr, .. } => Some((ptr.addr(), 4096)),
                        Cap::Pdpt { ptr, .. } => Some((ptr.addr(), 4096)),
                        // Phase 42 — only zero RAM-backed frames.
                        // Device frames cover MMIO regions or ACPI/BIOS
                        // tables; zeroing them would either trigger
                        // side effects or destroy data the user just
                        // wanted to read.
                        Cap::Frame { ptr, size, is_device: false, .. } => {
                            let n: u64 = match size {
                                FrameSize::Small => 4096,
                                FrameSize::Large => 2 * 1024 * 1024,
                                FrameSize::Huge => 1024 * 1024 * 1024,
                            };
                            Some((ptr.addr(), n))
                        }
                        _ => None,
                    };
                    if let Some((paddr, len)) = zero_range {
                        // Reach the page through the kernel-half
                        // linear map (PML4[256+]) — keeps the
                        // rootserver's PML4[0] free for user mappings.
                        let dst = crate::arch::x86_64::paging::phys_to_lin(paddr)
                            as *mut u8;
                        core::ptr::write_bytes(dst, 0, len as usize);
                    }
                }
                cnode_slots[emit_idx].set_cap(&cap_to_store);
                cnode_slots[emit_idx].set_parent(Some(parent_id));
                emit_idx += 1;
            },
        );
        result?;

        // Commit the updated UntypedState back into the SOURCE slot.
        // Phase 42 — re-resolve the source cptr (args.a0) against the
        // invoker's CSpace to find the exact slot. Walking the CNode
        // looking for `ptr.addr() == state.base` is broken when the
        // child untyped is the leftmost descendant of its parent —
        // both share the same base paddr and the search hits the
        // parent first, leaving the source slot's free_index stale
        // and causing the next retype to re-allocate the same memory.
        let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;
        let source_resolved = crate::cspace::resolve_address_bits(
            s, &invoker_cspace, args.a0, crate::cspace::WORD_BITS);
        if let Ok(res) = source_resolved {
            if res.bits_remaining == 0 {
                let src_idx = KernelState::cnode_index(res.slot_ptr);
                s.cnodes[src_idx].0[res.slot_index].set_cap(&state.to_cap());
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
    invoker: TcbId,
    mint: bool,
) -> KResult<()> {
    // Two ABI shapes coexist:
    //   * Phase 16 legacy (microtest, extra_caps == 0):
    //       a2 = dest_index, a3 = src_index (same CNode = `target`),
    //       a4 = badge_or_rights (Mint only).
    //       depth defaults to WORD_BITS, src_root = target.
    //   * Phase 42 upstream (sel4test, extra_caps > 0):
    //       a2 = dest_index, a3 = dest_depth,
    //       a4 = src_index,  a5 = src_depth,
    //       extraCaps[0] = src_root,
    //       msg_regs[4] = rights, msg_regs[5] = badge (Mint).
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let upstream = info.extra_caps() > 0;
    let (dest_index, dest_depth, src_index, src_depth, badge) = if upstream {
        let inv_tcb = unsafe { KERNEL.get().scheduler.slab.get(invoker) };
        let b = inv_tcb.msg_regs[5];
        (args.a2, args.a3 as u32, args.a4, args.a5 as u32, b)
    } else {
        (args.a2, crate::cspace::WORD_BITS,
         args.a3, crate::cspace::WORD_BITS, args.a4)
    };
    let dest_root = target;
    unsafe {
        let s = KERNEL.get();
        let inv_tcb = s.scheduler.slab.get_mut(invoker);
        let src_root = if upstream && inv_tcb.pending_extra_caps_count > 0 {
            let c = inv_tcb.pending_extra_caps[0];
            inv_tcb.pending_extra_caps_count = 0;
            c
        } else {
            inv_tcb.cspace_root
        };

        let dest_res = crate::cspace::resolve_address_bits(
            s, &dest_root, dest_index, dest_depth)?;
        if dest_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let dest_cnode_idx = KernelState::cnode_index(dest_res.slot_ptr);

        let src_res = crate::cspace::resolve_address_bits(
            s, &src_root, src_index, src_depth)?;
        if src_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let src_cnode_idx = KernelState::cnode_index(src_res.slot_ptr);

        let mut copy = s.cnodes[src_cnode_idx].0[src_res.slot_index].cap();
        if !s.cnodes[dest_cnode_idx].0[dest_res.slot_index].cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst)));
        }
        // Mirror upstream `Arch_deriveCap` for x86 paging-structure
        // caps: the derived (copied/minted) cap starts with mapped
        // state cleared. The original cap retains its mapping; its
        // copies are independent and must be Map'd before use. Without
        // this, sel4test's allocman recycles slots, copies frame caps
        // to new slots, then tries to map them — and the kernel
        // returns DeleteFirst because the source cap's stale mapped
        // vaddr propagates through the copy.
        match &mut copy {
            Cap::Frame { mapped, asid, .. } => {
                *mapped = None;
                *asid = 0;
            }
            Cap::PageTable { mapped, asid, .. } => {
                *mapped = None;
                *asid = 0;
            }
            Cap::PageDirectory { mapped, asid, .. } => {
                *mapped = None;
                *asid = 0;
            }
            Cap::Pdpt { mapped, asid, .. } => {
                *mapped = None;
                *asid = 0;
            }
            _ => {}
        }
        if mint {
            // Mirrors upstream `updateCapData(false, badge, cap)`:
            // for Endpoint/Notification, `badge` is the badge value;
            // for CNode caps, `badge` is the seL4_CNode_CapData
            // encoding of (guard, guardSize) which the kernel applies
            // to the derived cap so it walks the new CSpace at the
            // expected depth. Without this, sel4test's
            // create_cspace mints the new CNode cap into its own
            // slot 1 expecting guard_size=47 (skipping the high
            // 47 bits of any cptr lookup) and our resolve falls 47
            // bits short → FailedLookup on every cnode_move/mint
            // through that cap.
            match &mut copy {
                Cap::Endpoint { badge: b, .. } => {
                    *b = crate::cap::Badge(badge);
                }
                Cap::Notification { badge: b, .. } => {
                    *b = crate::cap::Badge(badge);
                }
                Cap::CNode { ptr, radix, guard_size, guard } => {
                    if badge != 0 {
                        let new_guard_size = (badge & 0x3F) as u8;
                        let new_guard_raw = badge >> 6;
                        if (new_guard_size as u32) + (*radix as u32) <= 64 {
                            let mask = if new_guard_size == 0 {
                                0
                            } else {
                                (1u64 << new_guard_size) - 1
                            };
                            *guard_size = new_guard_size;
                            *guard = new_guard_raw & mask;
                        }
                        let _ = ptr;
                    }
                }
                _ => {}
            }
        }
        s.cnodes[dest_cnode_idx].0[dest_res.slot_index].set_cap(&copy);
        // Phase 30 — the new cap is derived from the source slot;
        // its MDB parent is the source CTE.
        let src_id = crate::cte::MdbId::pack(
            src_cnode_idx as u8, src_res.slot_index as u16);
        s.cnodes[dest_cnode_idx].0[dest_res.slot_index].set_parent(Some(src_id));
    }
    Ok(())
}

fn cnode_move(
    target: Cap,
    args: &SyscallArgs,
    invoker: TcbId,
    _mutate: bool,
) -> KResult<()> {
    // Two ABI shapes coexist (mirrors `cnode_copy_or_mint`):
    //   * legacy (microtest): a2 = dest, a3 = src, both in `target`'s
    //     CNode, depth = WORD_BITS.
    //   * upstream (sel4test): a2/a3 = dest_idx/dest_depth, a4/a5 =
    //     src_idx/src_depth, extraCaps[0] = src_root.
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let upstream = info.extra_caps() > 0;
    let (dest_index, dest_depth, src_index, src_depth) = if upstream {
        (args.a2, args.a3 as u32, args.a4, args.a5 as u32)
    } else {
        (args.a2, crate::cspace::WORD_BITS,
         args.a3, crate::cspace::WORD_BITS)
    };
    let dest_root = target;
    unsafe {
        let s = KERNEL.get();
        let inv_tcb = s.scheduler.slab.get_mut(invoker);
        let src_root = if upstream && inv_tcb.pending_extra_caps_count > 0 {
            let c = inv_tcb.pending_extra_caps[0];
            inv_tcb.pending_extra_caps_count = 0;
            c
        } else {
            inv_tcb.cspace_root
        };

        // Resolve dest slot via the dest_root cap.
        let dest_res = crate::cspace::resolve_address_bits(
            s, &dest_root, dest_index, dest_depth)?;
        if dest_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let dest_cnode_idx = KernelState::cnode_index(dest_res.slot_ptr);

        let src_res = crate::cspace::resolve_address_bits(
            s, &src_root, src_index, src_depth)?;
        if src_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let src_cnode_idx = KernelState::cnode_index(src_res.slot_ptr);

        if INV_TRACE {
            crate::arch::log("[mov src=cn");
            log_dec(src_cnode_idx as u64);
            crate::arch::log("/sl");
            log_dec(src_res.slot_index as u64);
            crate::arch::log(" dst=cn");
            log_dec(dest_cnode_idx as u64);
            crate::arch::log("/sl");
            log_dec(dest_res.slot_index as u64);
            crate::arch::log("]\n");
        }
        // Snapshot src cap before mutating either slot — both might
        // be in the same CNode, in which case the borrow checker
        // would object to two simultaneous &mut on the same array.
        let src_cap = s.cnodes[src_cnode_idx].0[src_res.slot_index].cap();
        if !s.cnodes[dest_cnode_idx].0[dest_res.slot_index].cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst)));
        }
        s.cnodes[dest_cnode_idx].0[dest_res.slot_index].set_cap(&src_cap);
        s.cnodes[src_cnode_idx].0[src_res.slot_index].set_cap(&Cap::Null);
    }
    Ok(())
}

fn cnode_delete(target: Cap, args: &SyscallArgs, _invoker: TcbId) -> KResult<()> {
    // Upstream `seL4_CNode_Delete` ABI:
    //   target   = the CNode cap containing the slot to clear
    //   a2 (mr0) = index (cptr to slot under `target`)
    //   a3 (mr1) = depth (bits to walk for index)
    // Microtest legacy callers pass depth=WORD_BITS implicitly; the
    // resolve-with-depth path handles both.
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let depth = if info.length() >= 2 {
        args.a3 as u32
    } else {
        crate::cspace::WORD_BITS
    };
    if INV_TRACE {
        crate::arch::log("[del idx=0x");
        log_hex_u64(args.a2);
        crate::arch::log(" d=");
        log_dec(depth as u64);
        crate::arch::log("]\n");
    }
    unsafe {
        let s = KERNEL.get();
        let res = crate::cspace::resolve_address_bits(
            s, &target, args.a2, depth)?;
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        if INV_TRACE {
            crate::arch::log("[del -> cnode=");
            log_dec(cnode_idx as u64);
            crate::arch::log(" slot=");
            log_dec(res.slot_index as u64);
            crate::arch::log("]\n");
        }

        // Snapshot the cap + parent edge BEFORE clearing — the
        // Untyped reclaim below needs them to know what to give
        // back and to whom.
        let deleted_cap = s.cnodes[cnode_idx].0[res.slot_index].cap();
        let parent_id = s.cnodes[cnode_idx].0[res.slot_index].parent();

        s.cnodes[cnode_idx].0[res.slot_index].set_cap(&Cap::Null);
        s.cnodes[cnode_idx].0[res.slot_index].set_parent(None);

        // Phase 42 — Untyped reclaim. allocman's split allocator
        // calls CNode_Delete on bisect-ladder children and expects
        // the parent Untyped's `free_index` to roll back so the
        // memory becomes allocatable again. We approximate the
        // upstream MDB-driven cleanup by, on every Untyped delete,
        // walking up the parent chain and recomputing each parent's
        // `free_index` as `max(child.base + child.size) -
        // parent.base` over its surviving children. If no children
        // remain the parent is reset to fully-free.
        if matches!(deleted_cap, Cap::Untyped { .. }) {
            reclaim_untyped_chain(parent_id);
        }
    }
    Ok(())
}

/// Walk up the parent chain starting at `start`. For each parent
/// CTE that holds an Untyped cap, recompute its `free_index` as the
/// maximum end-paddr (`base + 2^block_bits`) over its surviving
/// children, minus its base. If no children remain, the free_index
/// drops to 0. Stops when a parent has surviving children whose
/// free_index doesn't change (no further reclaim is possible).
unsafe fn reclaim_untyped_chain(start: Option<crate::cte::MdbId>) {
    let s = KERNEL.get();
    let mut cursor = start;
    while let Some(pid) = cursor {
        let pcn = pid.cnode_idx() as usize;
        let psl = pid.slot() as usize;
        if pcn >= s.cnodes.len() || psl >= s.cnodes[pcn].0.len() {
            return;
        }
        let cap = s.cnodes[pcn].0[psl].cap();
        let (parent_base, parent_block_bits) = match cap {
            Cap::Untyped { ptr, block_bits, .. } => (ptr.addr(), block_bits as u32),
            _ => return,
        };
        let parent_total = 1u64 << parent_block_bits;
        let parent_end = parent_base + parent_total;

        // Find the highest end-paddr among surviving children of pid.
        let mut max_end: u64 = parent_base; // == "no children" sentinel
        for ci in 0..s.cnodes.len() {
            for si in 0..s.cnodes[ci].0.len() {
                let cte = &s.cnodes[ci].0[si];
                if cte.parent() != Some(pid) {
                    continue;
                }
                if let Cap::Untyped { ptr, block_bits, .. } = cte.cap() {
                    let end = ptr.addr() + (1u64 << block_bits);
                    if end > max_end {
                        max_end = end;
                    }
                }
            }
        }
        let new_fi = max_end - parent_base;
        // Read the live cap, write back with updated free_index.
        if let Cap::Untyped { ptr, block_bits, free_index, is_device } =
            s.cnodes[pcn].0[psl].cap()
        {
            if new_fi < free_index {
                let updated = Cap::Untyped {
                    ptr, block_bits, free_index: new_fi, is_device,
                };
                s.cnodes[pcn].0[psl].set_cap(&updated);
                // Continue up: maybe the parent's parent also has a
                // tail to reclaim now that this one shrank.
                cursor = s.cnodes[pcn].0[psl].parent();
                let _ = parent_end;
                continue;
            }
        }
        return;
    }
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
            // `seL4_TCB_Configure` — one-shot TCB setup. Two ABI
            // shapes coexist:
            //
            //   * Legacy (Phase 34b — extraCaps == 0):
            //       a2 = fault_ep cptr
            //       a3 = cspace_root cptr (looked up via CSpace)
            //       a4 = vspace_root cptr
            //       a5 = priority | (mcp << 8)
            //
            //   * Phase 37c — upstream (extraCaps > 0):
            //       a2 = fault_ep cptr
            //       a3 = cspace_root_data (guard config; ignored —
            //            our flat-radix CNodes don't reconfigure
            //            guards via Configure)
            //       a4 = vspace_root_data (ignored)
            //       a5 = ipc_buffer vaddr
            //       extraCaps[0] = cspace_root cap
            //       extraCaps[1] = vspace_root cap
            //       extraCaps[2] = ipc_buffer frame cap
            //
            //  Distinguish by `info.extra_caps()`. The microtest
            //  case (`tcb_configure`) and existing kernel spec use
            //  the legacy form; sel4test will use the upstream
            //  form via libsel4.
            InvocationLabel::TCBConfigure => {
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                let upstream = info.extra_caps() > 0;

                let inv_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let (cnode_cap, vspace_cap, ipcbuf_cap, ipc_buffer_vaddr) =
                    if upstream {
                        let staged = s.scheduler.slab.get(invoker)
                            .pending_extra_caps;
                        let count = s.scheduler.slab.get(invoker)
                            .pending_extra_caps_count as usize;
                        let cnode = if count > 0 { Some(staged[0]) } else { None };
                        let vspace = if count > 1 { Some(staged[1]) } else { None };
                        let ipcbuf = if count > 2 { Some(staged[2]) } else { None };
                        (cnode, vspace, ipcbuf, args.a5)
                    } else {
                        let cnode = if args.a3 != 0 {
                            Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a3)?)
                        } else { None };
                        let vspace = if args.a4 != 0 {
                            Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a4)?)
                        } else { None };
                        (cnode, vspace, None, 0)
                    };
                let t = s.scheduler.slab.get_mut(id);
                t.fault_handler = args.a2;
                if let Some(c) = cnode_cap {
                    if !matches!(c, Cap::CNode { .. } | Cap::Null) {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    if !matches!(c, Cap::Null) {
                        t.cspace_root = c;
                    }
                }
                if let Some(c) = vspace_cap {
                    match c {
                        Cap::PML4 { ptr, .. } => {
                            t.cpu_context.cr3 = ptr.addr();
                            t.vspace_root = c;
                        }
                        Cap::Null => {}
                        _ => return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability))),
                    }
                }
                if upstream {
                    if let Some(Cap::Frame { ptr, .. }) = ipcbuf_cap {
                        t.ipc_buffer = ipc_buffer_vaddr;
                        t.ipc_buffer_paddr = ptr.addr();
                    }
                } else {
                    let prio = args.a5 as u8;
                    let mcp = (args.a5 >> 8) as u8;
                    t.priority = prio;
                    if mcp != 0 {
                        t.mcp = mcp;
                    }
                }
                // Drain the staged caps regardless of which branch
                // we took, so they don't leak into a future IPC.
                s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
                Ok(())
            }
            InvocationLabel::TCBSetPriority => {
                let prio = args.a2 as u8;
                s.scheduler.slab.get_mut(id).priority = prio;
                Ok(())
            }
            InvocationLabel::TCBWriteRegisters => {
                // Two ABI shapes coexist:
                //   * Legacy (msginfo.length == 0):
                //       a2 = rip, a3 = rsp, a4 = arg0 (rdi).
                //   * Phase 36g — upstream `seL4_TCB_WriteRegisters`
                //     (msginfo.length > 0):
                //       a2 = resume_target (bool, ignored)
                //       a3 = arch_flags    (ignored)
                //       a4 = count
                //       msg_regs[3..3+count] = register values in
                //       seL4_UserContext order: rip, rsp, rflags,
                //       rax, rbx, rcx, rdx, rsi, rdi, rbp, r8, r9,
                //       r10, r11, r12, r13, r14, r15, fs_base,
                //       gs_base. We honour the first 18 (skipping
                //       fs/gs base — not modelled).
                #[cfg(target_arch = "x86_64")]
                {
                    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                    let length = info.length();
                    if length == 0 {
                        let t = s.scheduler.slab.get_mut(id);
                        t.user_context.rcx = args.a2;
                        t.user_context.rsp = args.a3;
                        t.user_context.rdi = args.a4;
                        t.user_context.r11 = 0x202;
                    } else {
                        // Upstream seL4_TCB_WriteRegisters wire layout
                        // (per libsel4 stub):
                        //   mr0 = (resume_target & 1) | (arch_flags << 8)
                        //   mr1 = count
                        //   mr2 = rip      (= regs[0])
                        //   mr3 = rsp      (= regs[1])
                        //   for i = 2..count: SetMR(i + 2, ...)
                        //     so msg[4..] = rflags, rax, rbx, rcx, rdx,
                        //                   rsi, rdi, rbp, r8, r9, r10,
                        //                   r11, r12, r13, r14, r15,
                        //                   fs_base, gs_base.
                        // Mapping into our SyscallArgs (a1=info, a2=mr0,
                        // a3=mr1, a4=mr2, a5=mr3) and msg_regs[4..].
                        let resume = (args.a2 & 1) != 0;
                        let count = args.a3 as usize;
                        let inv = s.scheduler.slab.get(invoker);
                        let mut regs: [u64; 20] = [0; 20];
                        // First two registers ride in args.a4 / args.a5.
                        if count > 0 { regs[0] = args.a4; }   // rip
                        if count > 1 { regs[1] = args.a5; }   // rsp
                        // Remaining registers come from msg word
                        // index 4 onwards (where SetMR(i+2, ...) for
                        // i=2 lands). Our msg_regs[4..] holds those
                        // (for indices < SCRATCH_MSG_LEN); past that
                        // we read from the IPC buffer at offset i+1
                        // (the +1 skips the tag word).
                        for i in 2..count.min(20) {
                            let msg_idx = i + 2;
                            if msg_idx < inv.msg_regs.len() {
                                regs[i] = inv.msg_regs[msg_idx];
                            } else if inv.ipc_buffer_paddr != 0 {
                                let buf = (crate::arch::x86_64::paging::phys_to_lin(
                                    inv.ipc_buffer_paddr) as *const u64)
                                    .wrapping_add(1);
                                regs[i] = core::ptr::read_volatile(buf.add(msg_idx));
                            }
                        }
                        let t = s.scheduler.slab.get_mut(id);
                        let n = count;
                        if n > 0  { t.user_context.rcx = regs[0]; }   // rip
                        if n > 1  { t.user_context.rsp = regs[1]; }
                        if n > 2  { t.user_context.r11 = regs[2]; }   // rflags
                        if n > 3  { t.user_context.rax = regs[3]; }
                        if n > 4  { t.user_context.rbx = regs[4]; }
                        // Slot 5 is "rcx" in the upstream userctx,
                        // but we already use TCB.user_context.rcx
                        // as the iretq RIP slot. The real rcx is
                        // unused at sysretq (= caller RIP); skip.
                        if n > 6  { t.user_context.rdx = regs[6]; }
                        if n > 7  { t.user_context.rsi = regs[7]; }
                        if n > 8  { t.user_context.rdi = regs[8]; }
                        if n > 9  { t.user_context.rbp = regs[9]; }
                        if n > 10 { t.user_context.r8  = regs[10]; }
                        if n > 11 { t.user_context.r9  = regs[11]; }
                        if n > 12 { t.user_context.r10 = regs[12]; }
                        // Slot 13 is "r11" in upstream — same slot
                        // as our rflags; would clobber if we wrote
                        // it. Skip.
                        if n > 14 { t.user_context.r12 = regs[14]; }
                        if n > 15 { t.user_context.r13 = regs[15]; }
                        if n > 16 { t.user_context.r14 = regs[16]; }
                        if n > 17 { t.user_context.r15 = regs[17]; }
                        // fs_base / gs_base (slots 18, 19) ignored.
                        if resume {
                            s.scheduler.make_runnable(id);
                        }
                    }
                }
                Ok(())
            }
            InvocationLabel::TCBReadRegisters => {
                // Two ABI shapes coexist (mirror of WriteRegisters):
                //   * Legacy (msginfo.length == 0):
                //       writes 3 words back: rcx (= rip), rsp, rax.
                //   * Phase 37d — upstream `seL4_TCB_ReadRegisters`
                //     (msginfo.length > 0):
                //       a2 = suspend_source (bool, ignored)
                //       a3 = arch_flags    (ignored)
                //       a4 = count
                //       writes `count` words back in seL4_UserContext
                //       order: rip, rsp, rflags, rax, rbx, rcx, rdx,
                //       rsi, rdi, rbp, r8..r15, fs_base, gs_base.
                //       Slots 5 (rcx) and 13 (r11) are zeroed in the
                //       output (those user_context fields double as
                //       our iretq RIP/RFLAGS holders); fs_base / gs
                //       _base also zero (not modelled).
                #[cfg(target_arch = "x86_64")]
                {
                    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                    let length = info.length();
                    let t = s.scheduler.slab.get(id);
                    if length == 0 {
                        let (rip, rsp, rax) = (
                            t.user_context.rcx,
                            t.user_context.rsp,
                            t.user_context.rax,
                        );
                        let inv = s.scheduler.slab.get_mut(invoker);
                        inv.msg_regs[0] = rip;
                        inv.msg_regs[1] = rsp;
                        inv.msg_regs[2] = rax;
                        inv.ipc_length = 3;
                    } else {
                        let regs: [u64; 20] = [
                            t.user_context.rcx,    // 0  rip
                            t.user_context.rsp,    // 1  rsp
                            t.user_context.r11,    // 2  rflags
                            t.user_context.rax,    // 3  rax
                            t.user_context.rbx,    // 4  rbx
                            0,                     // 5  rcx (held by iretq)
                            t.user_context.rdx,    // 6  rdx
                            t.user_context.rsi,    // 7  rsi
                            t.user_context.rdi,    // 8  rdi
                            t.user_context.rbp,    // 9  rbp
                            t.user_context.r8,     // 10 r8
                            t.user_context.r9,     // 11 r9
                            t.user_context.r10,    // 12 r10
                            0,                     // 13 r11 (held by iretq)
                            t.user_context.r12,    // 14 r12
                            t.user_context.r13,    // 15 r13
                            t.user_context.r14,    // 16 r14
                            t.user_context.r15,    // 17 r15
                            0,                     // 18 fs_base (not modelled)
                            0,                     // 19 gs_base (not modelled)
                        ];
                        let count = (args.a4 as usize).min(regs.len());
                        let ipc_paddr = s.scheduler.slab.get(invoker).ipc_buffer_paddr;
                        let inv = s.scheduler.slab.get_mut(invoker);
                        let in_regs = count.min(inv.msg_regs.len());
                        for i in 0..in_regs {
                            inv.msg_regs[i] = regs[i];
                        }
                        inv.ipc_length = count as u32;
                        // Spill words past msg_regs[] into the
                        // invoker's IPC buffer so userspace's
                        // libsel4 stub can read the whole array.
                        if count > inv.msg_regs.len() && ipc_paddr != 0 {
                            let buf = (crate::arch::x86_64::paging::phys_to_lin(
                                ipc_paddr) as *mut u64).wrapping_add(1);
                            for i in inv.msg_regs.len()..count {
                                core::ptr::write_volatile(buf.add(i), regs[i]);
                            }
                        }
                        // Phase 37d — fan the first 4 returned
                        // words into the invoker's user_context so
                        // the syscall return path delivers them
                        // via r10/r8/r9/r15 (upstream seL4 IPC
                        // return ABI) the way SysRecv does. SysSend
                        // doesn't normally fan in (it's a sender-
                        // side syscall), but ReadRegisters is one
                        // of the few invocations that produce a
                        // return message.
                        if count > 0 { inv.user_context.r10 = regs[0]; }
                        if count > 1 { inv.user_context.r8  = regs[1]; }
                        if count > 2 { inv.user_context.r9  = regs[2]; }
                        if count > 3 { inv.user_context.r15 = regs[3]; }
                        // Also pack the returned msginfo (length=
                        // count, label=0) into rsi so userspace
                        // can decode it with seL4_MessageInfo_get_*.
                        let mi = (count as u64) & 0x7F;
                        inv.user_context.rsi = mi;
                    }
                }
                Ok(())
            }
            InvocationLabel::TCBSetSpace => {
                // Two ABI shapes:
                //   * Upstream (sel4test): cspace + vspace via extraCaps[0..2].
                //     mr0=fault_ep, mr1=cspace_root_data, mr2=vspace_root_data.
                //   * Legacy (microtest): a3=cnode_cptr, a4=vspace_cptr.
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                let upstream = info.extra_caps() > 0;
                let inv_cspace = s.scheduler.slab.get(invoker).cspace_root;
                let (cnode_cap, vspace_cap) = if upstream {
                    // MCS variant of TCBSetSpace passes 3 extraCaps:
                    //   [0] = fault handler endpoint
                    //   [1] = cspace root
                    //   [2] = vspace root
                    // mr0 = cspace_root_data, mr1 = vspace_root_data
                    // (no fault_ep cptr in message words). We don't
                    // model fault handlers via cap yet — store the
                    // raw cptr in fault_handler the same way the
                    // legacy path did.
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    let count = inv_tcb.pending_extra_caps_count as usize;
                    let cnode = if count > 1 { Some(inv_tcb.pending_extra_caps[1]) } else { None };
                    let vspace = if count > 2 { Some(inv_tcb.pending_extra_caps[2]) } else { None };
                    inv_tcb.pending_extra_caps_count = 0;
                    (cnode, vspace)
                } else {
                    let cnode = if args.a3 != 0 {
                        Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a3)?)
                    } else { None };
                    let vspace = if args.a4 != 0 {
                        Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a4)?)
                    } else { None };
                    (cnode, vspace)
                };
                let t = s.scheduler.slab.get_mut(id);
                // Legacy path stores fault_ep cptr from a2; upstream
                // passes a fault-handler endpoint cap as extraCaps[0]
                // and uses a2 for cspace_root_data — we don't model
                // fault-handler caps yet, so skip the assignment.
                if !upstream {
                    t.fault_handler = args.a2;
                }
                if let Some(c) = cnode_cap {
                    if !matches!(c, Cap::CNode { .. }) {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    // Apply cspace_root_data (mr0 in upstream MCS layout
                    // = args.a2, mr1 in upstream non-MCS = args.a3,
                    // none in legacy). Encoding mirrors libsel4's
                    // `seL4_CNode_CapData`:
                    //   bits 0..6  = guardSize
                    //   bits 6..64 = guard
                    // Mirrors upstream `updateCapData` for cnode caps.
                    let cdata = if upstream { args.a2 } else { 0 };
                    let final_cnode = if cdata != 0 {
                        let new_guard_size = (cdata & 0x3F) as u8;
                        let new_guard = cdata >> 6;
                        if let Cap::CNode { ptr, radix, .. } = c {
                            if (new_guard_size as u32) + (radix as u32) > 64 {
                                return Err(KException::SyscallError(SyscallError::new(
                                    seL4_Error::seL4_RangeError)));
                            }
                            Cap::CNode {
                                ptr,
                                radix,
                                guard_size: new_guard_size,
                                guard: new_guard & ((1u64 << new_guard_size) - 1),
                            }
                        } else {
                            c
                        }
                    } else {
                        c
                    };
                    t.cspace_root = final_cnode;
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
            // Phase 34c — set the user-mode IPC buffer. ABI:
            //   a2 = vaddr the user mapped its IPC buffer at
            //   a3 = Frame cap_ptr backing that mapping; the
            //        kernel reads its paddr to access the buffer
            //        directly (BOOTBOOT 1 GiB identity map).
            InvocationLabel::TCBSetIPCBuffer => {
                // Two ABI shapes:
                //   * Upstream (sel4test): bufferFrame via extraCaps[0],
                //     mr0 = buffer (vaddr).
                //   * Legacy (microtest): a3 = frame_cptr.
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                let upstream = info.extra_caps() > 0;
                let vaddr = args.a2;
                let frame_cap = if upstream {
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    if inv_tcb.pending_extra_caps_count == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    let c = inv_tcb.pending_extra_caps[0];
                    inv_tcb.pending_extra_caps_count = 0;
                    c
                } else {
                    let inv_cspace = s.scheduler.slab.get(invoker).cspace_root;
                    crate::cspace::lookup_cap(s, &inv_cspace, args.a3)?
                };
                let paddr = match frame_cap {
                    Cap::Frame { ptr, .. } => ptr.addr(),
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
                let t = s.scheduler.slab.get_mut(id);
                t.ipc_buffer = vaddr;
                t.ipc_buffer_paddr = paddr;
                Ok(())
            }
            InvocationLabel::TCBBindNotification => {
                // Two ABI shapes:
                //   * legacy (microtest): a2 = ntfn_cptr in invoker's
                //     CSpace.
                //   * upstream (sel4test): notification passed as
                //     extraCaps[0]; no message words.
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                let upstream = info.extra_caps() > 0;
                let inv_tcb_mut = s.scheduler.slab.get_mut(invoker);
                let ntfn_cap = if upstream {
                    if inv_tcb_mut.pending_extra_caps_count == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability)));
                    }
                    let c = inv_tcb_mut.pending_extra_caps[0];
                    inv_tcb_mut.pending_extra_caps_count = 0;
                    c
                } else {
                    let cspace_root = inv_tcb_mut.cspace_root;
                    crate::cspace::lookup_cap(s, &cspace_root, args.a2)?
                };
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
            // MCS api_tcb_configure calls SetTimeoutEndpoint with the
            // timeout-handler endpoint cap (often seL4_CapNull). We
            // don't model timeout faults yet — accept the call as a
            // no-op so process spawn-up can proceed.
            InvocationLabel::TCBSetTimeoutEndpoint => Ok(()),
            // SetMCPriority sets the maximum-controllable-priority
            // bound. mr0 = mcp; extraCaps[0] = authority TCB (we
            // ignore — kernel-side checks haven't been wired yet).
            InvocationLabel::TCBSetMCPriority => {
                let mcp = args.a2 as u8;
                s.scheduler.slab.get_mut(id).mcp = mcp;
                let inv_tcb = s.scheduler.slab.get_mut(invoker);
                inv_tcb.pending_extra_caps_count = 0;
                Ok(())
            }
            // SetSchedParams (CPriority + MCP combined). Upstream
            // ABI: mr0=mcp, mr1=prio (or vice versa), extraCaps[0]
            // = authority. Set both.
            InvocationLabel::TCBSetSchedParams => {
                let mcp = args.a2 as u8;
                let prio = args.a3 as u8;
                let t = s.scheduler.slab.get_mut(id);
                t.mcp = mcp;
                t.priority = prio;
                let inv_tcb = s.scheduler.slab.get_mut(invoker);
                inv_tcb.pending_extra_caps_count = 0;
                Ok(())
            }
            // SetTLSBase via TCB invocation (vs the SysSetTLSBase
            // syscall which sets the *invoker's* TLS). a2 = base.
            // We don't model per-TCB TLS save/restore yet but accept
            // the call so sel4test's process bring-up proceeds.
            InvocationLabel::TCBSetTLSBase => Ok(()),
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
        tcb_configure_one_shot_setup();
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

        // Re-mapping at the SAME vaddr is a no-op (mirrors upstream
        // `decodeX86FrameMapInvocation`), so it should succeed.
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: vaddr,
            a3: FrameRights::ReadWrite.to_word(),
            ..Default::default()
        };
        let now_cap = unsafe { KERNEL.get().cnodes[0].0[1].cap() };
        decode_invocation(now_cap, &args, invoker).expect("remap same vaddr ok");

        // Re-mapping at a DIFFERENT vaddr is rejected with DeleteFirst —
        // userspace must Unmap first.
        let other_vaddr = vaddr + 0x1000;
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: other_vaddr,
            a3: FrameRights::ReadWrite.to_word(),
            ..Default::default()
        };
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

    /// Phase 34b — `seL4_TCB_Configure` packs SetSpace + priority
    /// into one invocation. Verify all fields land on the target.
    #[inline(never)]
    fn tcb_configure_one_shot_setup() {
        use crate::cap::Pml4Storage;
        let invoker = setup_invoker(0);
        let target = unsafe {
            let t = crate::tcb::Tcb::default();
            KERNEL.get().scheduler.admit(t)
        };
        let target_cap = Cap::Thread {
            tcb: PPtr::<crate::cap::Tcb>::new(target.0 as u64).unwrap(),
        };
        // Plant a CNode at slot 4 and a PML4 at slot 5 in the invoker.
        let cnode_cap = Cap::CNode {
            ptr: KernelState::cnode_ptr(2),
            radix: 5, guard_size: 59, guard: 0,
        };
        let pml4_paddr = 0x0000_0000_00DD_0000u64;
        let pml4_cap = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(pml4_paddr).unwrap(),
            mapped: true, asid: 0,
        };
        unsafe {
            KERNEL.get().cnodes[0].0[4] = Cte::with_cap(&cnode_cap);
            KERNEL.get().cnodes[0].0[5] = Cte::with_cap(&pml4_cap);
        }
        // Configure(target, fault_ep=0xCAFE, cspace=4, vspace=5,
        //           a5=prio 75 | mcp 200 << 8).
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBConfigure as u64) << 12,
            a2: 0xCAFE,
            a3: 4,
            a4: 5,
            a5: 75 | (200u64 << 8),
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("Configure");
        unsafe {
            let t = KERNEL.get().scheduler.slab.get(target);
            assert_eq!(t.fault_handler, 0xCAFE);
            assert!(matches!(t.cspace_root, Cap::CNode { .. }));
            assert_eq!(t.cpu_context.cr3, pml4_paddr);
            assert_eq!(t.priority, 75);
            assert_eq!(t.mcp, 200);
            KERNEL.get().scheduler.slab.free(target);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ TCB::Configure sets fault_ep + cspace + vspace + prio in one call\n");
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
        // ABI: a0 = invoking SchedControl cptr (looked up by
        // handle_send), a2 = target SC cptr, a3 = budget, a4 = period.
        let args = SyscallArgs {
            a1: (InvocationLabel::SchedControlConfigureFlags as u64) << 12,
            a2: 7,   // target SC cap_ptr
            a3: 20,  // budget
            a4: 100, // period
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
            a1: (InvocationLabel::SchedControlConfigureFlags as u64) << 12,
            a2: 7,
            a3: 200, // budget
            a4: 100, // period
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
