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
        Cap::Domain => decode_domain(label, args, invoker),
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

    // Per-size alignment. Small=4 KiB (12-bit), Large=2 MiB (21-bit),
    // Huge=1 GiB (30-bit). FRAMEEXPORTS0001 reserves a 1 GiB-aligned
    // vaddr range so all three sizes share the same base — only the
    // size_bits-derived stride between mappings matters.
    let align_bits: u32 = match size {
        crate::cap::FrameSize::Small => 12,
        crate::cap::FrameSize::Large => 21,
        crate::cap::FrameSize::Huge  => 30,
    };
    let align_mask = (1u64 << align_bits) - 1;
    if vaddr & align_mask != 0 {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_AlignmentError,
        )));
    }

    let asid_for_cap: u16;
    unsafe {
        // Track BOTH the PML4 paddr and the vspace's ASID so Unmap
        // can later walk this exact vspace by asid lookup.
        let pml4_info_opt: Option<(u64, u16)> = if upstream {
            let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
            let count = inv_tcb.pending_extra_caps_count as usize;
            let cap = if count > 0 {
                Some(inv_tcb.pending_extra_caps[0])
            } else {
                None
            };
            inv_tcb.pending_extra_caps_count = 0;
            match cap {
                Some(Cap::PML4 { ptr, asid, .. }) => Some((ptr.addr(), asid)),
                _ => return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability))),
            }
        } else if args.a4 != 0 {
            let cspace_root = KERNEL.get().scheduler.slab.get(invoker).cspace_root;
            let pml4_cap = crate::cspace::lookup_cap(KERNEL.get(), &cspace_root, args.a4)?;
            match pml4_cap {
                Cap::PML4 { ptr, asid, .. } => Some((ptr.addr(), asid)),
                _ => return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability))),
            }
        } else {
            None
        };
        let pml4_paddr_opt = pml4_info_opt.map(|(p, _)| p);
        asid_for_cap = pml4_info_opt.map(|(_, a)| a).unwrap_or(0);

        if let Some(pml4_paddr) = pml4_paddr_opt {
            // Dispatch to the right map helper for this Frame size.
            // Each helper returns the level-empty error code:
            //   missing=1: PML4 entry empty → need PDPT (level 39)
            //   missing=2: PDPT entry empty → need PD   (level 30)
            //   missing=3: PD entry empty   → need PT   (level 21)
            //   missing=4: leaf slot busy   → DeleteFirst
            let map_result = match size {
                crate::cap::FrameSize::Small => {
                    usermode::map_user_4k_into_foreign_pml4(
                        pml4_paddr, vaddr, paddr, writable)
                }
                crate::cap::FrameSize::Large => {
                    usermode::map_user_2m_into_foreign_pml4(
                        pml4_paddr, vaddr, paddr, writable)
                }
                crate::cap::FrameSize::Huge => {
                    usermode::map_user_1g_into_foreign_pml4(
                        pml4_paddr, vaddr, paddr, writable)
                }
            };
            if let Err(missing) = map_result {
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
        } else if matches!(size, crate::cap::FrameSize::Small) {
            usermode::map_user_4k_public(vaddr, paddr, writable);
        } else {
            // Legacy microtest path doesn't support Large/Huge.
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidArgument)));
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
        if let Some(slots) = s.cnode_slots_at_mut(cnode_idx) {
            for slot in slots.iter_mut() {
                if let Cap::Frame { ptr, mapped: None, .. } = slot.cap() {
                    if ptr.addr() == paddr {
                        let updated = Cap::Frame {
                            ptr,
                            size,
                            rights,
                            mapped: Some(vaddr),
                            asid: asid_for_cap,
                            is_device: _device,
                        };
                        slot.set_cap(&updated);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Phase 43 — find the PML4 paddr for a given ASID by scanning every
/// CNode for a `Cap::PML4` whose `asid` field matches. Returns 0 if
/// no match (caller should treat as a no-op).
///
/// Linear scan — fine for single-tenant sel4test where a handful of
/// PML4 caps exist. A proper ASID-pool lookup would be the upstream
/// way; deferring until we have multi-process workloads.
#[cfg(target_arch = "x86_64")]
fn pml4_paddr_for_asid(asid: u16) -> u64 {
    if asid == 0 { return 0; }
    unsafe {
        let s = KERNEL.get();
        for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
            let slots = match s.cnode_slots_at(ci) {
                Some(s) => s,
                None => continue,
            };
            for slot in slots.iter() {
                if let Cap::PML4 { ptr, asid: a, .. } = slot.cap() {
                    if a == asid {
                        return ptr.addr();
                    }
                }
            }
        }
    }
    0
}

fn decode_frame_unmap(target: Cap, _args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let (paddr, size, mapped_vaddr, asid) = match target {
        Cap::Frame { ptr, size, mapped, asid, .. } =>
            (ptr.addr(), size, mapped, asid),
        _ => unreachable!(),
    };

    // Phase 28g / 42 / 43 — clear the PTE in the live page tables
    // for the VSPACE the frame is mapped in (via asid → PML4) and
    // fan a TLB shootdown to other CPUs. The previous version walked
    // current CR3, which is wrong when the invoker's CSpace contains
    // a frame cap mapped in a *different* vspace (sel4test's driver
    // unmapping pages from the test process's vspace clobbered the
    // driver's own page tables at the same vaddr).
    #[cfg(target_arch = "x86_64")]
    if let Some(vaddr) = mapped_vaddr {
        unsafe {
            let pml4_paddr = pml4_paddr_for_asid(asid);
            if pml4_paddr != 0 {
                match size {
                    crate::cap::FrameSize::Small => {
                        crate::arch::x86_64::usermode::unmap_user_4k_in_pml4(
                            pml4_paddr, vaddr);
                    }
                    crate::cap::FrameSize::Large => {
                        crate::arch::x86_64::usermode::unmap_user_2m_in_pml4(
                            pml4_paddr, vaddr);
                    }
                    crate::cap::FrameSize::Huge => {
                        crate::arch::x86_64::usermode::unmap_user_1g_in_pml4(
                            pml4_paddr, vaddr);
                    }
                }
                crate::smp::shootdown_tlb(vaddr);
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = mapped_vaddr; let _ = size; }

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
        if let Some(slots) = s.cnode_slots_at_mut(cnode_idx) {
            for slot in slots.iter_mut() {
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
        let slots = match s.cnode_slots_at_mut(cnode_idx) {
            Some(s) => s,
            None => return,
        };
        for slot in slots.iter_mut() {
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
                let slots = match s.cnode_slots_at_mut(cnode_idx) {
                    Some(s) => s,
                    None => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                };
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
                child_count_inc(parent_id, 1);

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
                    let slots = match s.cnode_slots_at(cnode_idx) {
                        Some(s) => s,
                        None => return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability))),
                    };
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
                if let Some(slot) = s.cnode_slot_mut(slot_cnode_idx, slot_idx) {
                    slot.set_cap(&Cap::PML4 { ptr, mapped, asid: assigned });
                }
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
///
/// Phase 43 — starts at 2 so the first user-process assignment doesn't
/// collide with `ROOTSERVER_ASID = 1` (set in `rootserver::launch_rootserver`).
/// A duplicate ASID confuses `pml4_paddr_for_asid`'s linear scan: it
/// returns the first match, and a test-process Frame::Unmap could
/// land on the rootserver's PML4 instead of the test process's.
static NEXT_ASID_OFFSET: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(2);

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
                // Phase 43 — also accept Notification cap (passive
                // server pattern). Binding an SC to a notification
                // means: when the notification is signalled, the SC
                // donates its budget to the bound TCB so it can run.
                // BIND005 / BIND006 exercise this. We model it by
                // recording the SC on the notification, and on signal
                // we ensure the bound TCB has the SC.
                match tcb_cap {
                    Cap::Thread { tcb } => {
                        let tcb_id = crate::tcb::TcbId(tcb.addr() as u16);
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
                        // Phase 43 — BIND005 deferred wake. If a
                        // notification was signalled while this TCB
                        // had no SC, the badge is parked in the
                        // notification's Active state. Now that the
                        // TCB has an SC again, drain the pending
                        // badge into the TCB and wake it.
                        let bn = s.scheduler.slab.get(tcb_id).bound_notification;
                        if let Some(bn_idx) = bn {
                            let ntfn = &mut s.notifications[bn_idx as usize];
                            if matches!(ntfn.state,
                                crate::notification::NtfnState::Active)
                            {
                                let badge = ntfn.pending_badge;
                                ntfn.pending_badge = 0;
                                ntfn.state =
                                    crate::notification::NtfnState::Idle;
                                let was_blocked_recv = matches!(
                                    s.scheduler.slab.get(tcb_id).state,
                                    crate::tcb::ThreadStateType::BlockedOnReceive);
                                if was_blocked_recv {
                                    crate::endpoint::cancel_ipc_anywhere(
                                        &mut s.scheduler, tcb_id);
                                }
                                let tcb_t = s.scheduler.slab.get_mut(tcb_id);
                                tcb_t.ipc_badge = badge;
                                #[cfg(target_arch = "x86_64")]
                                {
                                    tcb_t.user_context.rdi = badge;
                                    tcb_t.user_context.rsi = 0;
                                }
                                s.scheduler.make_runnable(tcb_id);
                            }
                        }
                    }
                    Cap::Notification { ptr, .. } => {
                        let ntfn_idx = KernelState::ntfn_index(ptr);
                        let ntfn = &mut s.notifications[ntfn_idx];
                        // Bind SC to this notification so future
                        // signal()s donate budget to the bound TCB.
                        // Record the SC on the notification AND on the
                        // bound TCB so signal() can find both.
                        if let Some(bt) = ntfn.bound_tcb {
                            let tcb = s.scheduler.slab.get_mut(bt);
                            if tcb.sc.is_none() {
                                tcb.sc = Some(sc_id);
                                s.sched_contexts[sc_id as usize]
                                    .bound_tcb = Some(bt);
                            }
                        }
                        // Mark the SC as bound to the notification so
                        // unbind can find it.
                        ntfn.bound_sc = Some(sc_id);
                    }
                    _ => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability))),
                }
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
                // Phase 43 — also clear notification binding if any
                // notification holds this SC for passive-server use.
                for ntfn in s.notifications.iter_mut() {
                    if ntfn.bound_sc == Some(sc_id) {
                        ntfn.bound_sc = None;
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
                let slots = match s.cnode_slots_at_mut(cnode_idx) {
                    Some(s) => s,
                    None => return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    ))),
                };
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
        let slot = match s.cnode_slot_mut(cnode_idx, res.slot_index) {
            Some(s) => s,
            None => return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability))),
        };
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

/// `seL4_DomainSet_Set(target=DomainSet, domain, thread)` — assigns
/// a TCB to a scheduling domain. We model a single domain (CONFIG_NUM
/// _DOMAINS=1 in the matched libsel4), so any non-zero domain is
/// rejected with InvalidArgument; domain=0 just stamps the field on
/// the target TCB. DOMAINS0001/0002/0003 in sel4test verify exactly
/// this contract.
fn decode_domain(
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    if !matches!(label, InvocationLabel::DomainSetSet) {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation)));
    }
    let domain = (args.a2 & 0xff) as u8;
    // Sel4test's matched config compiles libsel4 with NUM_DOMAINS=1,
    // so the only valid domain is 0.
    const NUM_DOMAINS: u8 = 1;
    if domain >= NUM_DOMAINS {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidArgument)));
    }
    unsafe {
        let s = KERNEL.get();
        let inv_tcb = s.scheduler.slab.get_mut(invoker);
        if inv_tcb.pending_extra_caps_count == 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_TruncatedMessage)));
        }
        let tcb_cap = inv_tcb.pending_extra_caps[0];
        inv_tcb.pending_extra_caps_count = 0;
        let tcb_id = match tcb_cap {
            Cap::Thread { tcb } => crate::tcb::TcbId(tcb.addr() as u16),
            _ => return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability))),
        };
        s.scheduler.slab.get_mut(tcb_id).domain = domain;
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
        let slot = match s.cnode_slot_mut(cnode_idx, res.slot_index) {
            Some(s) => s,
            None => return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability))),
        };
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

    // Upstream rejects `num_objects` outside [1, CONFIG_RETYPE_FAN_OUT_LIMIT]
    // with seL4_RangeError, and stamps mr0=1 (min) + mr1=limit so userspace
    // can read the bounds back via seL4_GetMR. RETYPE0000 in sel4test
    // probes this with `num_objects = 0` and asserts on both bounds.
    const RETYPE_FAN_OUT_LIMIT: u64 = 256;
    if num_objects == 0 || num_objects > RETYPE_FAN_OUT_LIMIT {
        unsafe {
            let inv = KERNEL.get().scheduler.slab.get_mut(invoker);
            inv.msg_regs[0] = 1;
            inv.msg_regs[1] = RETYPE_FAN_OUT_LIMIT;
            inv.ipc_length = 2;
        }
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_RangeError,
        )));
    }

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
                s.cnode_slot(cnode_idx, res.slot_index)
                    .map(|c| c.cap()).unwrap_or(Cap::Null)
            }
        } else {
            s.scheduler.slab.get(invoker).cspace_root
        };
        let (cnode_ptr, dest_radix) = match dest_cnode_cap {
            Cap::CNode { ptr, radix, .. } => (ptr, radix),
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
        // Resolve the SOURCE untyped's slot in the invoker's CSpace
        // BEFORE we take a mutable borrow on `s.cnodes`. We use this
        // (src_cnode_idx, src_slot_index) as the parent_id for each
        // child cap so cnode_revoke walks the right MDB chain. (Using
        // the dest CNode would point children at random slots in the
        // test process's CNode and Revoke would shoot down unrelated
        // caps.)
        let invoker_root = s.scheduler.slab.get(invoker).cspace_root;
        let src_res = crate::cspace::resolve_address_bits(
            s, &invoker_root, args.a0,
            crate::cspace::WORD_BITS,
        ).map_err(|_| KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_FailedLookup)))?;
        let src_cnode_idx = KernelState::cnode_index(src_res.slot_ptr);
        let src_slot_index = src_res.slot_index;
        // Borrow as raw slice so we don't lock the whole `s` —
        // the surrounding code needs separate access to
        // `s.scheduler` etc. BKL serialises kernel state.
        let cnode_slots: &mut [Cte] = {
            let raw = match s.cnode_slots_at_mut(cnode_idx) {
                Some(s) => s as *mut [Cte],
                None => return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability))),
            };
            &mut *raw
        };

        // Verify the destination range is empty — Retype refuses
        // to overwrite caps. Use the dest CNode cap's logical radix,
        // not the underlying storage capacity, so a 4-slot dest
        // (radix=2) really has only 4 valid offsets even though
        // every CNode in our pool is physically 4096 slots.
        // RETYPE0000 in sel4test cares: it sizes the dest CNode at 4
        // and expects offset >= 4 to fail with seL4_RangeError.
        let logical_capacity = 1usize << dest_radix;
        let upper = dest_offset + num_objects as usize;
        if upper > logical_capacity {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
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
        // MDB. We resolved the source untyped's location above
        // (src_cnode_idx, src_slot_index).
        let parent_id = crate::cte::MdbId::pack(
            src_cnode_idx as u8,
            src_slot_index as u16,
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
                        // Phase 43 — scrub any stale kernel
                        // references to this slab slot. The slot may
                        // have been reused after a previous TCB was
                        // freed by a path that didn't fully clean up
                        // (e.g. spec test cleanup that calls
                        // `slab.free` directly). Without this, an SC's
                        // bound_tcb / notification's bound_tcb /
                        // reply's bound_tcb could still point at the
                        // re-used id, and a subsequent mcs_tick or
                        // signal would dereference what it expected to
                        // be a different TCB.
                        scrub_tcb_refs(s_ptr.as_mut().unwrap(), id);
                        Cap::Thread {
                            tcb: PPtr::<crate::cap::Tcb>::new(id.0 as u64)
                                .expect("nonzero tcb id"),
                        }
                    }
                    Cap::Endpoint { badge, rights, .. } => {
                        match (*s_ptr).alloc_endpoint() {
                            Some(i) => Cap::Endpoint {
                                ptr: KernelState::endpoint_ptr(i),
                                badge,
                                rights,
                            },
                            None => {
                                crate::arch::log("[retype: endpoint pool exhausted]\n");
                                Cap::Null
                            }
                        }
                    }
                    Cap::Notification { badge, rights, .. } => {
                        match (*s_ptr).alloc_notification() {
                            Some(i) => Cap::Notification {
                                ptr: KernelState::ntfn_ptr(i),
                                badge,
                                rights,
                            },
                            None => {
                                crate::arch::log("[retype: ntfn pool exhausted]\n");
                                Cap::Null
                            }
                        }
                    }
                    Cap::CNode { radix, guard_size, guard, .. } => {
                        // Pick small pool for radix ≤ SMALL_CNODE_RADIX
                        // (CSPACE0001's 64 radix-1 CNodes etc.). Fall
                        // back to big pool if small is full or radix
                        // exceeds the small pool's capacity.
                        let alloc = if radix <= crate::kernel::SMALL_CNODE_RADIX {
                            (*s_ptr).alloc_small_cnode()
                                .or_else(|| (*s_ptr).alloc_cnode())
                        } else {
                            (*s_ptr).alloc_cnode()
                        };
                        match alloc {
                            Some(vi) => Cap::CNode {
                                ptr: KernelState::cnode_ptr(vi),
                                radix,
                                guard_size,
                                guard,
                            },
                            None => {
                                crate::arch::log("[retype: cnode pool exhausted]\n");
                                Cap::Null
                            }
                        }
                    }
                    Cap::SchedContext { size_bits, .. } => {
                        match (*s_ptr).alloc_sched_context() {
                            Some(i) => Cap::SchedContext {
                                ptr: KernelState::sched_context_ptr(i),
                                size_bits,
                            },
                            None => {
                                crate::arch::log("[retype: sc pool exhausted]\n");
                                Cap::Null
                            }
                        }
                    }
                    Cap::Reply { can_grant, .. } => {
                        match (*s_ptr).alloc_reply() {
                            Some(i) => Cap::Reply {
                                ptr: KernelState::reply_ptr(i),
                                can_grant,
                            },
                            None => {
                                crate::arch::log("[retype: reply pool exhausted]\n");
                                Cap::Null
                            }
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
                child_count_inc(parent_id, 1);
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
                if let Some(slot) = s.cnode_slot_mut(src_idx, res.slot_index) {
                    slot.set_cap(&state.to_cap());
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
        InvocationLabel::CNodeCancelBadgedSends => {
            cnode_cancel_badged_sends(target, args, invoker)
        }
        InvocationLabel::CNodeRotate => cnode_rotate(target, args, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// `seL4_CNode_Rotate(_service=dest_root, dest_index, dest_depth,
///   dest_badge, pivot_root, pivot_index, pivot_depth, pivot_badge,
///   src_root, src_index, src_depth)` — atomic 3-way move.
///
/// libsel4's stub: msginfo length=8, extra_caps=2.
///   mr0=dest_index, mr1=dest_depth, mr2=dest_badge, mr3=pivot_index,
///   mr4=pivot_depth, mr5=pivot_badge, mr6=src_index, mr7=src_depth,
///   extraCaps[0]=pivot_root, extraCaps[1]=src_root.
///
/// Semantics (mirrors upstream): the cap at `src` moves to `dest`,
/// `src` is cleared, and `pivot` keeps its cap (possibly rebadged).
/// Constraints: dest must be empty (else DeleteFirst), src must be
/// non-empty (else FailedLookup), src != pivot (else IllegalOperation).
fn cnode_rotate(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let dest_root = target;
    let dest_index = args.a2;
    let dest_depth = args.a3 as u32;
    let pivot_index = args.a5;
    unsafe {
        let s = KERNEL.get();
        let inv_tcb = s.scheduler.slab.get(invoker);
        let pivot_depth = inv_tcb.msg_regs[4] as u32;
        let src_index = inv_tcb.msg_regs[6];
        let src_depth = inv_tcb.msg_regs[7] as u32;
        let (pivot_root, src_root) = if inv_tcb.pending_extra_caps_count >= 2 {
            (inv_tcb.pending_extra_caps[0], inv_tcb.pending_extra_caps[1])
        } else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_TruncatedMessage)));
        };
        s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;

        // Resolve all three slots.
        let dest_res = crate::cspace::resolve_address_bits(
            s, &dest_root, dest_index, dest_depth)?;
        if dest_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let pivot_res = crate::cspace::resolve_address_bits(
            s, &pivot_root, pivot_index, pivot_depth)?;
        if pivot_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let src_res = crate::cspace::resolve_address_bits(
            s, &src_root, src_index, src_depth)?;
        if src_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        let dest_cn = KernelState::cnode_index(dest_res.slot_ptr);
        let pivot_cn = KernelState::cnode_index(pivot_res.slot_ptr);
        let src_cn = KernelState::cnode_index(src_res.slot_ptr);
        let dest_si = dest_res.slot_index;
        let pivot_si = pivot_res.slot_index;
        let src_si = src_res.slot_index;

        // src == pivot is illegal — would lose the cap.
        if src_cn == pivot_cn && src_si == pivot_si {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation)));
        }
        // src must be non-empty.
        let src_cap = s.cnode_slot(src_cn, src_si)
            .map(|c| c.cap()).unwrap_or(Cap::Null);
        if src_cap.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        // dest must be empty unless dest == src (swap with self).
        if !(dest_cn == src_cn && dest_si == src_si) {
            let dest_occupied = s.cnode_slot(dest_cn, dest_si)
                .map(|c| !c.cap().is_null()).unwrap_or(false);
            if dest_occupied {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_DeleteFirst)));
            }
        }
        let pivot_cap = s.cnode_slot(pivot_cn, pivot_si)
            .map(|c| c.cap()).unwrap_or(Cap::Null);
        if pivot_cap.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }

        // Order of writes matters when dest == src: clear src first
        // would lose the cap. Do dest assignment first; only clear
        // src if it's a distinct slot.
        if let Some(slot) = s.cnode_slot_mut(dest_cn, dest_si) {
            slot.set_cap(&src_cap);
        }
        if let Some(slot) = s.cnode_slot_mut(pivot_cn, pivot_si) {
            slot.set_cap(&pivot_cap);
        }
        if !(dest_cn == src_cn && dest_si == src_si) {
            if let Some(slot) = s.cnode_slot_mut(src_cn, src_si) {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
            }
        }
    }
    Ok(())
}

/// CNode::Revoke — Phase 30. Delete every cap whose MDB-parent
/// chain leads back to `(target_cnode, src_index)`. We track each
/// CTE's parent in `Cte::set_parent` (recorded by `Untyped::Retype`
/// + `CNode::Copy/Mint`); the walk is a fixed-point pass that
/// repeatedly clears CTEs whose parent has already been
/// revoked-or-source. The source slot itself is left intact —
/// Revoke deletes the children only; callers use CNodeDelete to
/// remove the source.
/// Phase 43 — `seL4_CNode_CancelBadgedSends`. Walks the target
/// CNode looking for an Endpoint cap at slot `args.a2`; for that
/// endpoint, finds all queued senders whose stored badge matches
/// the cap's badge, removes them from the queue, and Restarts them.
/// Mirrors upstream's `cancelBadgedSends` (we ignore non-badged
/// caps, returning Ok with no work).
fn cnode_cancel_badged_sends(
    target: Cap,
    args: &SyscallArgs,
    _invoker: TcbId,
) -> KResult<()> {
    let src_index = args.a2 as usize;
    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidCapability))),
    };
    unsafe {
        let s = KERNEL.get();
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        let slot_count = s.cnode_slots_at(cnode_idx)
            .map(|sl| sl.len()).unwrap_or(0);
        if src_index >= slot_count {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError)));
        }
        let cap = s.cnode_slot(cnode_idx, src_index)
            .map(|c| c.cap()).unwrap_or(Cap::Null);
        let (ep_idx, badge) = match cap {
            Cap::Endpoint { ptr, badge, .. } => {
                let i = KernelState::endpoint_index(ptr);
                (i, badge.0)
            }
            // Upstream's `decodeCNodeInvocation` rejects non-Endpoint
            // (and non-Notification) targets here with IllegalOperation.
            // CNODEOP0006 calls cancelBadgedSends on an empty slot and
            // expects exactly that.
            _ => return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation))),
        };
        // Badge of 0 = unbadged, no-op (success).
        if badge == 0 { return Ok(()); }
        let s_ptr: *mut crate::kernel::KernelState = s;
        let ep = &mut (*s_ptr).endpoints[ep_idx];
        if !matches!(ep.state, crate::endpoint::EpState::Send) {
            return Ok(());
        }
        // Walk the send queue and remove threads whose ipc_badge
        // matches our badge.
        let mut cur = ep.head;
        while let Some(t) = cur {
            let next = (*s_ptr).scheduler.slab.get(t).ep_next;
            let t_badge = (*s_ptr).scheduler.slab.get(t).ipc_badge;
            if t_badge == badge {
                crate::endpoint::cancel_ipc_anywhere(
                    &mut (*s_ptr).scheduler, t);
                // Phase 43 — the cancelled sender resumes from its
                // blocked seL4_Call as if the call returned a reply
                // with `seL4_InvalidCapability` as the label, which
                // is what test_ep_cancelBadgedSends asserts on.
                // Without this fan-in, rsi still holds the SENT
                // msginfo (label = 0) and the test fails.
                #[cfg(target_arch = "x86_64")]
                {
                    let cancelled = (*s_ptr).scheduler.slab.get_mut(t);
                    let label = seL4_Error::seL4_InvalidCapability as u64;
                    cancelled.user_context.rsi = label << 12;
                    cancelled.user_context.rdi = 0;
                    cancelled.blocked_is_call = false;
                }
                (*s_ptr).scheduler.make_runnable(t);
            }
            cur = next;
        }
    }
    Ok(())
}

fn cnode_revoke(target: Cap, args: &SyscallArgs, _invoker: TcbId) -> KResult<()> {
    let src_index = args.a2 as usize;
    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        let cn_slot_count = s.cnode_slots_at(cnode_idx)
            .map(|sl| sl.len()).unwrap_or(0);
        if src_index >= cn_slot_count {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        let source_id = crate::cte::MdbId::pack(cnode_idx as u8, src_index as u16);

        // Tombstone bitmap: bit set means "this CTE has been
        // revoked-or-is-source". Held in a static (BKL-serialised)
        // so we don't blow the kernel stack. Split into per-pool
        // backing arrays sized to each pool's actual capacity —
        // packing as a single MAX_CNODES * CNODE_SLOTS array would
        // grow ~3x once the small pool is included.
        const SLOTS_PER_NODE: usize = crate::kernel::CNODE_SLOTS;
        const SMALL_SLOTS: usize = crate::kernel::SMALL_CNODE_SLOTS;
        static mut REVOKED_BIG:
            [[bool; SLOTS_PER_NODE]; crate::kernel::MAX_CNODES] =
            [[false; SLOTS_PER_NODE]; crate::kernel::MAX_CNODES];
        static mut REVOKED_SMALL:
            [[bool; SMALL_SLOTS]; crate::kernel::MAX_SMALL_CNODES] =
            [[false; SMALL_SLOTS]; crate::kernel::MAX_SMALL_CNODES];
        // Reset both pool bitmaps. We touch the statics through raw
        // pointers below to keep the borrow checker out of the way —
        // the closures used by the marking + clearing phases need
        // overlapping reads/writes that &mut won't permit.
        for row in (&mut *core::ptr::addr_of_mut!(REVOKED_BIG)).iter_mut() {
            for v in row.iter_mut() { *v = false; }
        }
        for row in (&mut *core::ptr::addr_of_mut!(REVOKED_SMALL)).iter_mut() {
            for v in row.iter_mut() { *v = false; }
        }
        // Helpers: dispatch on virtual cnode index.
        let is_revoked = |ci: usize, si: usize| -> bool {
            if ci < crate::kernel::MAX_CNODES {
                if si < SLOTS_PER_NODE {
                    (*core::ptr::addr_of!(REVOKED_BIG))[ci][si]
                } else { false }
            } else if ci < crate::kernel::KernelState::cnode_pool_count() {
                let small_i = ci - crate::kernel::MAX_CNODES;
                if si < SMALL_SLOTS {
                    (*core::ptr::addr_of!(REVOKED_SMALL))[small_i][si]
                } else { false }
            } else {
                false
            }
        };
        let mark_revoked = |ci: usize, si: usize| {
            if ci < crate::kernel::MAX_CNODES {
                if si < SLOTS_PER_NODE {
                    (*core::ptr::addr_of_mut!(REVOKED_BIG))[ci][si] = true;
                }
            } else if ci < crate::kernel::KernelState::cnode_pool_count() {
                let small_i = ci - crate::kernel::MAX_CNODES;
                if si < SMALL_SLOTS {
                    (*core::ptr::addr_of_mut!(REVOKED_SMALL))[small_i][si] = true;
                }
            }
        };
        mark_revoked(cnode_idx, src_index);

        // Iterate to fixed point: any CTE whose parent is revoked
        // gets revoked too. Capacity-bounded — at most
        // `cnode_pool_count() * CNODE_SLOTS` CTEs to mark.
        let mut progress = true;
        while progress {
            progress = false;
            for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
                let slot_count = if ci < crate::kernel::MAX_CNODES {
                    s.cnodes[ci].0.len()
                } else {
                    SMALL_SLOTS
                };
                for si in 0..slot_count {
                    if is_revoked(ci, si) { continue; }
                    let parent = s.cnode_slot(ci, si).and_then(|c| c.parent());
                    if let Some(p) = parent {
                        let pi = p.cnode_idx() as usize;
                        let ps = p.slot() as usize;
                        if is_revoked(pi, ps) {
                            mark_revoked(ci, si);
                            progress = true;
                        }
                    }
                }
            }
        }

        // Clear every revoked slot except the source itself.
        // Also reset the child_count for both the cleared slot
        // (no longer holds anything that has children) and decrement
        // the parent's count (we just removed one of its children).
        for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
            let slot_count = if ci < crate::kernel::MAX_CNODES {
                s.cnodes[ci].0.len()
            } else {
                SMALL_SLOTS
            };
            for si in 0..slot_count {
                if !is_revoked(ci, si)
                    || (ci == cnode_idx && si == src_index)
                {
                    continue;
                }
                let id = crate::cte::MdbId::pack(ci as u8, si as u16);
                child_count_reset(id);
                // Phase 43 — free pool slots so long sel4test
                // runs don't exhaust the static pools. Only the
                // FIRST cap (where the object was retyped from
                // an Untyped) does the free; copies via Mint
                // would call free again for the same pool slot
                // which is harmless (free is idempotent).
                let cap_to_free = s.cnode_slot(ci, si)
                    .map(|c| c.cap())
                    .unwrap_or(Cap::Null);
                // Phase 43 — only free the underlying object when
                // no OTHER live cap points at the same pointer.
                // Mint/Copy create derivative caps that share the
                // object — freeing on every delete wipes the EP /
                // Notification / etc. while the master cap still
                // refers to it. CANCEL_BADGED_SENDS_0001 hit this:
                // revoking a badged endpoint cap reset the master
                // endpoint, dropping all 32 queued senders.
                // `KernelState::*_ptr` use the same `(i+1)`
                // encoding scheme across pools, so TCB id N
                // collides with Endpoint index N-1, etc. Match
                // discriminator + ptr to keep cross-type
                // collisions out.
                let same_obj_lives = |target: &Cap| -> bool {
                    let (want_disc, want_ptr) = match target {
                        Cap::Endpoint { ptr, .. } => (1u8, ptr.addr()),
                        Cap::Notification { ptr, .. } => (2u8, ptr.addr()),
                        Cap::SchedContext { ptr, .. } => (3u8, ptr.addr()),
                        Cap::Reply { ptr, .. } => (4u8, ptr.addr()),
                        Cap::CNode { ptr, .. } => (5u8, ptr.addr()),
                        Cap::Thread { tcb } => (6u8, tcb.addr()),
                        _ => return false,
                    };
                    // For CNode caps: skip self-references inside
                    // the CNode itself; they become unreachable
                    // once the last external ref is gone.
                    let target_self_cnode_idx = match target {
                        Cap::CNode { ptr, .. } =>
                            Some(KernelState::cnode_index(*ptr)),
                        _ => None,
                    };
                    for ci2 in 0..crate::kernel::KernelState::cnode_pool_count() {
                        if Some(ci2) == target_self_cnode_idx { continue; }
                        let inner_count = if ci2 < crate::kernel::MAX_CNODES {
                            s.cnodes[ci2].0.len()
                        } else {
                            SMALL_SLOTS
                        };
                        for si2 in 0..inner_count {
                            if ci2 == ci && si2 == si { continue; }
                            if is_revoked(ci2, si2) { continue; }
                            let other_cap = s.cnode_slot(ci2, si2)
                                .map(|c| c.cap())
                                .unwrap_or(Cap::Null);
                            let (other_disc, other_ptr) = match other_cap {
                                Cap::Endpoint { ptr, .. } => (1u8, ptr.addr()),
                                Cap::Notification { ptr, .. } => (2u8, ptr.addr()),
                                Cap::SchedContext { ptr, .. } => (3u8, ptr.addr()),
                                Cap::Reply { ptr, .. } => (4u8, ptr.addr()),
                                Cap::CNode { ptr, .. } => (5u8, ptr.addr()),
                                Cap::Thread { tcb } => (6u8, tcb.addr()),
                                _ => continue,
                            };
                            if other_disc == want_disc && other_ptr == want_ptr {
                                return true;
                            }
                        }
                    }
                    false
                };
                if !same_obj_lives(&cap_to_free) {
                    match cap_to_free {
                        Cap::Thread { tcb } => {
                            let id = crate::tcb::TcbId(tcb.addr() as u16);
                            destroy_tcb(s, id);
                        }
                        Cap::Endpoint { ptr, .. } => {
                            s.free_endpoint(KernelState::endpoint_index(ptr));
                        }
                        Cap::Notification { ptr, .. } => {
                            s.free_notification(KernelState::ntfn_index(ptr));
                        }
                        Cap::SchedContext { ptr, .. } => {
                            s.free_sched_context(
                                KernelState::sched_context_index(ptr));
                        }
                        Cap::Reply { ptr, .. } => {
                            s.free_reply(KernelState::reply_index(ptr));
                        }
                        Cap::CNode { ptr, .. } => {
                            s.free_cnode_virt(KernelState::cnode_index(ptr));
                        }
                        _ => {}
                    }
                }
                if let Some(slot) = s.cnode_slot_mut(ci, si) {
                    slot.set_cap(&Cap::Null);
                    slot.set_parent(None);
                }
            }
        }
        // The source itself kept the cap but lost all its descendants.
        let src_id = crate::cte::MdbId::pack(cnode_idx as u8, src_index as u16);
        child_count_reset(src_id);

        // Silence unused: the structural fallback used to live
        // here. Keep `is_derived_from` available for any code that
        // still wants the structural check (none does today).
        let _ = source_id;

        // Phase 43 — if the source is an Untyped, every derived
        // object has been cleared, so reset the source's free index
        // back to 0 so the next Retype starts from the bottom of the
        // block. Otherwise the second test's allocations exhaust the
        // untyped even though the memory is now free.
        let source = s.cnode_slot(cnode_idx, src_index)
            .map(|c| c.cap()).unwrap_or(Cap::Null);
        if let Cap::Untyped { ptr, block_bits, is_device, .. } = source {
            if let Some(slot) = s.cnode_slot_mut(cnode_idx, src_index) {
                slot.set_cap(&Cap::Untyped {
                    ptr,
                    block_bits,
                    free_index: 0,
                    is_device,
                });
            }
        }
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

        let mut copy = s.cnode_slot(src_cnode_idx, src_res.slot_index)
            .map(|c| c.cap()).unwrap_or(Cap::Null);
        let dest_occupied = s.cnode_slot(dest_cnode_idx, dest_res.slot_index)
            .map(|c| !c.cap().is_null()).unwrap_or(false);
        if dest_occupied {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst)));
        }
        if copy.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
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
        if let Some(slot) = s.cnode_slot_mut(dest_cnode_idx, dest_res.slot_index) {
            slot.set_cap(&copy);
            // Phase 30 — the new cap is derived from the source slot;
            // its MDB parent is the source CTE.
            let src_id = crate::cte::MdbId::pack(
                src_cnode_idx as u8, src_res.slot_index as u16);
            slot.set_parent(Some(src_id));
            child_count_inc(src_id, 1);
        }
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
        let src_cap = s.cnode_slot(src_cnode_idx, src_res.slot_index)
            .map(|c| c.cap()).unwrap_or(Cap::Null);
        // Upstream order: dest-not-empty check first (DeleteFirst),
        // then src-empty check (FailedLookup). Matches sel4test's
        // `is_slot_empty` helper in helpers.c.
        let dest_occupied = s.cnode_slot(dest_cnode_idx, dest_res.slot_index)
            .map(|c| !c.cap().is_null()).unwrap_or(false);
        if dest_occupied {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst)));
        }
        if src_cap.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup)));
        }
        if let Some(slot) = s.cnode_slot_mut(dest_cnode_idx, dest_res.slot_index) {
            slot.set_cap(&src_cap);
        }
        if let Some(slot) = s.cnode_slot_mut(src_cnode_idx, src_res.slot_index) {
            slot.set_cap(&Cap::Null);
        }
    }
    Ok(())
}

/// Phase 43 — clear every `Option<TcbId>` field across the kernel
/// that points at `id`. Used both at TCB destruction time
/// (`destroy_tcb`) and at slot-reuse time in retype, so a freshly
/// allocated TCB doesn't inherit dangling back-references from a
/// previous occupant of its slab slot.
unsafe fn scrub_tcb_refs(s: &mut crate::kernel::KernelState, id: TcbId) {
    for n in s.notifications.iter_mut() {
        if n.bound_tcb == Some(id) { n.bound_tcb = None; }
    }
    for sc in s.sched_contexts.iter_mut() {
        if sc.bound_tcb == Some(id) { sc.bound_tcb = None; }
    }
    for r in s.replies.iter_mut() {
        if r.bound_tcb == Some(id) { r.bound_tcb = None; }
    }
    for opt in s.scheduler.slab.entries.iter_mut() {
        if let Some(t) = opt.as_mut() {
            if t.reply_to == Some(id) { t.reply_to = None; }
        }
    }
}

/// Phase 43 — destroy a TCB whose last cap was just deleted.
/// Walks every kernel structure that might still reference `id` and
/// scrubs the link before freeing the slab entry. Without this, a
/// later signal_or_wait / pop_head / mcs_tick can dereference a stale
/// id (manifests as `TcbSlab::get on empty slot id=N`).
unsafe fn destroy_tcb(s: &mut crate::kernel::KernelState, id: TcbId) {
    // Idempotent: revoke walks call this once per cleared slot, so a
    // TCB cap duplicated across multiple slots in the revoked subtree
    // would otherwise re-enter destroy after the first call already
    // freed the slab entry. Bail if we've already freed this slot.
    if s.scheduler.slab.entries[id.0 as usize].is_none() {
        return;
    }
    crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, id);
    s.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
    scrub_tcb_refs(s, id);
    s.scheduler.slab.entries[id.0 as usize] = None;
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
        let (deleted_cap, parent_id) = match s.cnode_slot(cnode_idx, res.slot_index) {
            Some(c) => (c.cap(), c.parent()),
            None => (Cap::Null, None),
        };

        if let Some(slot) = s.cnode_slot_mut(cnode_idx, res.slot_index) {
            slot.set_cap(&Cap::Null);
            slot.set_parent(None);
        }

        // Phase 43 — deleting the LAST cap to a TCB triggers thread
        // destruction in upstream seL4. We approximate: on every
        // Thread cap delete, suspend the TCB. On every Endpoint /
        // Notification / SchedContext / Reply / CNode cap delete,
        // release the pool slot for reuse (so long sel4test runs
        // don't exhaust pool sizes). But ONLY when no other cap
        // refers to the same object — Mint/Copy create derivatives
        // sharing the underlying object. (See
        // CANCEL_BADGED_SENDS_0001: deleting a derived endpoint cap
        // with the master still live used to wipe queued senders.)
        // Match by (discriminator, ptr) so cross-pool index collisions
        // (TCB id N == endpoint slot N+1 etc.) don't keep the object
        // pinned spuriously.
        let same_obj_lives = |target: &Cap| -> bool {
            let (want_disc, want_ptr) = match target {
                Cap::Endpoint { ptr, .. } => (1u8, ptr.addr()),
                Cap::Notification { ptr, .. } => (2u8, ptr.addr()),
                Cap::SchedContext { ptr, .. } => (3u8, ptr.addr()),
                Cap::Reply { ptr, .. } => (4u8, ptr.addr()),
                Cap::CNode { ptr, .. } => (5u8, ptr.addr()),
                Cap::Thread { tcb } => (6u8, tcb.addr()),
                _ => return false,
            };
            // For CNode caps: refs INSIDE the CNode itself (the
            // canonical seL4_CapInitThreadCNode self-reference) don't
            // count — once the last EXTERNAL ref is gone, those
            // self-refs become unreachable. sel4test's
            // sel4utils_destroy_process leaves a self-ref in the
            // process's CSpace; without this skip, we'd never free
            // the test process's CNode and the pool exhausts after
            // ~MAX_CNODES tests.
            let target_self_cnode_idx = match target {
                Cap::CNode { ptr, .. } => Some(KernelState::cnode_index(*ptr)),
                _ => None,
            };
            for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
                if Some(ci) == target_self_cnode_idx { continue; }
                let inner_count = s.cnode_slots_at(ci)
                    .map(|sl| sl.len())
                    .unwrap_or(0);
                for si in 0..inner_count {
                    if ci == cnode_idx && si == res.slot_index { continue; }
                    let other_cap = s.cnode_slot(ci, si)
                        .map(|c| c.cap()).unwrap_or(Cap::Null);
                    let (other_disc, other_ptr) = match other_cap {
                        Cap::Endpoint { ptr, .. } => (1u8, ptr.addr()),
                        Cap::Notification { ptr, .. } => (2u8, ptr.addr()),
                        Cap::SchedContext { ptr, .. } => (3u8, ptr.addr()),
                        Cap::Reply { ptr, .. } => (4u8, ptr.addr()),
                        Cap::CNode { ptr, .. } => (5u8, ptr.addr()),
                        Cap::Thread { tcb } => (6u8, tcb.addr()),
                        _ => continue,
                    };
                    if other_disc == want_disc && other_ptr == want_ptr {
                        return true;
                    }
                }
            }
            false
        };
        // Frame caps need PT-entry cleanup BEFORE the cap is gone:
        // FRAMEDIPC0003 deletes a mapped frame cap and expects later
        // user accesses to that vaddr to fault. Without this, the page
        // stays mapped via stale PTE and the test thread silently
        // continues into corrupted state.
        if let Cap::Frame { ptr, size, mapped: Some(vaddr), asid, .. } = deleted_cap {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let pml4_paddr = pml4_paddr_for_asid(asid);
                if pml4_paddr != 0 {
                    match size {
                        crate::cap::FrameSize::Small => {
                            crate::arch::x86_64::usermode::unmap_user_4k_in_pml4(
                                pml4_paddr, vaddr);
                        }
                        crate::cap::FrameSize::Large => {
                            crate::arch::x86_64::usermode::unmap_user_2m_in_pml4(
                                pml4_paddr, vaddr);
                        }
                        crate::cap::FrameSize::Huge => {
                            crate::arch::x86_64::usermode::unmap_user_1g_in_pml4(
                                pml4_paddr, vaddr);
                        }
                    }
                    crate::smp::shootdown_tlb(vaddr);
                }
            }
            let _ = (ptr, asid, vaddr, size);
        }
        if !same_obj_lives(&deleted_cap) {
            match deleted_cap {
                Cap::Thread { tcb } => {
                    let id = crate::tcb::TcbId(tcb.addr() as u16);
                    destroy_tcb(s, id);
                }
                Cap::Endpoint { ptr, .. } => {
                    s.free_endpoint(KernelState::endpoint_index(ptr));
                }
                Cap::Notification { ptr, .. } => {
                    s.free_notification(KernelState::ntfn_index(ptr));
                }
                Cap::SchedContext { ptr, .. } => {
                    s.free_sched_context(
                        KernelState::sched_context_index(ptr));
                }
                Cap::Reply { ptr, .. } => {
                    s.free_reply(KernelState::reply_index(ptr));
                }
                Cap::CNode { ptr, .. } => {
                    // Phase 43 — destroying the LAST cap to a CNode
                    // means the contents become unreachable too;
                    // walk the slots and destroy each one's underlying
                    // object so the memory returns to the Untyped pool.
                    // sel4utils_destroy_process relies on this: it
                    // revokes the CSpace cap then deletes it; without
                    // this recursive cleanup, all the test process's
                    // TCBs/Endpoints/Frames leak and DOMAINS0001's
                    // basic_set_up fails on Untyped exhaustion after
                    // a handful of test processes.
                    let inner_idx = KernelState::cnode_index(ptr);
                    let inner_slot_count = s.cnode_slots_at(inner_idx)
                        .map(|sl| sl.len())
                        .unwrap_or(0);
                    {
                    if inner_slot_count > 0 {
                        for slot_i in 0..inner_slot_count {
                            let inner_slot = s.cnode_slot(inner_idx, slot_i);
                            let (inner_cap, inner_parent) = match inner_slot {
                                Some(c) => (c.cap(), c.parent()),
                                None => continue,
                            };
                            // Skip Null and self-references (the CNode
                            // having a cap to itself). Also skip caps
                            // that have other live references — same
                            // refcount-aware logic as the cap-delete
                            // path above.
                            if inner_cap.is_null() { continue; }
                            if matches!(inner_cap, Cap::CNode { ptr: ip, .. }
                                if ip.addr() == ptr.addr())
                            {
                                continue;
                            }
                            // Borrow re-check across the closure call.
                            let mut other_ref = false;
                            'scan: for ci2 in 0..crate::kernel::KernelState::cnode_pool_count() {
                                let inner_count = s.cnode_slots_at(ci2)
                                    .map(|sl| sl.len())
                                    .unwrap_or(0);
                                for si2 in 0..inner_count {
                                    if ci2 == inner_idx && si2 == slot_i { continue; }
                                    let want = match &inner_cap {
                                        Cap::Endpoint { ptr, .. } => (1u8, ptr.addr()),
                                        Cap::Notification { ptr, .. } => (2u8, ptr.addr()),
                                        Cap::SchedContext { ptr, .. } => (3u8, ptr.addr()),
                                        Cap::Reply { ptr, .. } => (4u8, ptr.addr()),
                                        Cap::CNode { ptr, .. } => (5u8, ptr.addr()),
                                        Cap::Thread { tcb } => (6u8, tcb.addr()),
                                        _ => break 'scan,
                                    };
                                    let other_cap = s.cnode_slot(ci2, si2)
                                        .map(|c| c.cap()).unwrap_or(Cap::Null);
                                    let (od, op) = match other_cap {
                                        Cap::Endpoint { ptr, .. } => (1u8, ptr.addr()),
                                        Cap::Notification { ptr, .. } => (2u8, ptr.addr()),
                                        Cap::SchedContext { ptr, .. } => (3u8, ptr.addr()),
                                        Cap::Reply { ptr, .. } => (4u8, ptr.addr()),
                                        Cap::CNode { ptr, .. } => (5u8, ptr.addr()),
                                        Cap::Thread { tcb } => (6u8, tcb.addr()),
                                        _ => continue,
                                    };
                                    if od == want.0 && op == want.1 {
                                        other_ref = true;
                                        break 'scan;
                                    }
                                }
                            }
                            // Clear the slot first so a recursive call
                            // that walks cnodes again sees it empty.
                            if let Some(slot) = s.cnode_slot_mut(inner_idx, slot_i) {
                                slot.set_cap(&Cap::Null);
                                slot.set_parent(None);
                            }
                            if !other_ref {
                                match inner_cap {
                                    Cap::Thread { tcb } => {
                                        let tid = crate::tcb::TcbId(tcb.addr() as u16);
                                        destroy_tcb(s, tid);
                                    }
                                    Cap::Endpoint { ptr: p, .. } => {
                                        s.free_endpoint(KernelState::endpoint_index(p));
                                    }
                                    Cap::Notification { ptr: p, .. } => {
                                        s.free_notification(KernelState::ntfn_index(p));
                                    }
                                    Cap::SchedContext { ptr: p, .. } => {
                                        s.free_sched_context(
                                            KernelState::sched_context_index(p));
                                    }
                                    Cap::Reply { ptr: p, .. } => {
                                        s.free_reply(KernelState::reply_index(p));
                                    }
                                    Cap::CNode { ptr: p, .. } => {
                                        s.free_cnode_virt(KernelState::cnode_index(p));
                                    }
                                    _ => {}
                                }
                                // Roll back the cap's parent Untyped
                                // free_index too — same as a regular
                                // cnode_delete would.
                                let (db, ds) = cap_extent(&inner_cap);
                                reclaim_untyped_chain_at_tail(
                                    inner_parent, db, ds);
                            }
                        }
                    }
                    }
                    s.free_cnode_virt(inner_idx);
                }
                _ => {}
            }
        }

        // Phase 42 — Untyped reclaim. allocman's split allocator
        // calls CNode_Delete on bisect-ladder children and expects
        // the parent Untyped's `free_index` to roll back so the
        // memory becomes allocatable again. We approximate the
        // upstream MDB-driven cleanup by, on every Untyped delete,
        // walking up the parent chain and recomputing each parent's
        // `free_index` as `max(child.base + child.size) -
        // parent.base` over its surviving children. If no children
        // remain the parent is reset to fully-free.
        // Phase 43 — reclaim runs for *any* deleted cap, not just
        // child Untypeds. The parent's free_index was bumped at
        // Retype regardless of the resulting child type, so a
        // deleted Frame/TCB/EP/PT/PD/etc. should release the same
        // bytes back to the parent. Pass the deleted cap's
        // (base, size) so reclaim can fast-path the common case
        // where the deleted child wasn't at the parent's tail.
        let (deleted_base, deleted_size) = cap_extent(&deleted_cap);
        reclaim_untyped_chain_at_tail(parent_id, deleted_base, deleted_size);
    }
    Ok(())
}

/// Compute (base, size) of a cap's underlying object's physical
/// memory. Used by the reclaim fast-path to decide whether a delete
/// might shrink the parent's free_index. Returns (0, 0) for caps
/// whose ptr field encodes a pool index (TCB, Endpoint, Notification,
/// CNode, Reply) rather than a real paddr — for those we can't
/// fast-path and must fall through to the full walk.
fn cap_extent(cap: &Cap) -> (u64, u64) {
    match cap {
        Cap::Untyped { ptr, block_bits, .. } => (ptr.addr(), 1u64 << block_bits),
        Cap::Frame { ptr, size, .. } => {
            let n: u64 = match size {
                crate::cap::FrameSize::Small => 4096,
                crate::cap::FrameSize::Large => 2 * 1024 * 1024,
                crate::cap::FrameSize::Huge => 1024 * 1024 * 1024,
            };
            (ptr.addr(), n)
        }
        Cap::PageTable { ptr, .. } => (ptr.addr(), 4096),
        Cap::PageDirectory { ptr, .. } => (ptr.addr(), 4096),
        Cap::Pdpt { ptr, .. } => (ptr.addr(), 4096),
        Cap::PML4 { ptr, .. } => (ptr.addr(), 4096),
        Cap::SchedContext { ptr, size_bits, .. } => (ptr.addr(), 1u64 << size_bits),
        // Pool-indexed caps — ptr.addr() is NOT a paddr, so we can't
        // compare ranges. Force fall-through to full walk by returning
        // an extent of (0, 0).
        _ => (0, 0),
    }
}

/// Phase 43 — per-parent live-child counter. Indexed by
/// `cnode_idx * CNODE_SLOTS + slot_index`. Maintained on Retype
/// (increment per child emitted) and on cnode_delete (decrement).
/// When a delete brings the count to 0 we reset the parent Untyped's
/// `free_index` to 0 — no need for the O(N) reclaim walk in the
/// common alloc-then-free-all pattern. ~128 KiB BSS.
const CHILD_COUNT_LEN: usize = crate::kernel::MAX_CNODES * crate::kernel::CNODE_SLOTS;
static mut CHILD_COUNTS: [u32; CHILD_COUNT_LEN] = [0; CHILD_COUNT_LEN];

#[inline]
fn child_count_idx(pid: crate::cte::MdbId) -> Option<usize> {
    let ci = pid.cnode_idx() as usize;
    let si = pid.slot() as usize;
    if ci < crate::kernel::MAX_CNODES && si < crate::kernel::CNODE_SLOTS {
        Some(ci * crate::kernel::CNODE_SLOTS + si)
    } else {
        None
    }
}

pub unsafe fn child_count_inc(pid: crate::cte::MdbId, by: u32) {
    if let Some(idx) = child_count_idx(pid) {
        let counts = &mut *core::ptr::addr_of_mut!(CHILD_COUNTS);
        counts[idx] = counts[idx].saturating_add(by);
    }
}

unsafe fn child_count_dec(pid: crate::cte::MdbId) -> u32 {
    if let Some(idx) = child_count_idx(pid) {
        let counts = &mut *core::ptr::addr_of_mut!(CHILD_COUNTS);
        if counts[idx] > 0 {
            counts[idx] -= 1;
        }
        counts[idx]
    } else {
        u32::MAX
    }
}

unsafe fn child_count_reset(pid: crate::cte::MdbId) {
    if let Some(idx) = child_count_idx(pid) {
        let counts = &mut *core::ptr::addr_of_mut!(CHILD_COUNTS);
        counts[idx] = 0;
    }
}

/// Phase 43 — fast-path reclaim. If the deleted child's end_paddr is
/// strictly less than the parent's effective end (parent.base +
/// free_index), some other surviving child still extends past it, so
/// the parent's free_index can't shrink — bail out without the
/// expensive O(N) walk. Otherwise fall through to the full walk.
unsafe fn reclaim_untyped_chain_at_tail(
    start: Option<crate::cte::MdbId>,
    deleted_base: u64,
    deleted_size: u64,
) {
    // Phase 43 — child-counter only path. Decrement the parent's
    // counter; if zero we reset free_index and recurse upward (the
    // parent itself has now disappeared from its parent's view).
    // For non-zero counts we DO NOT shrink free_index — the next
    // Retype starts from the high watermark instead of filling holes
    // left by intermediate deletes. This is less precise than
    // upstream's per-cap MDB walk but ~free in time, and it matches
    // the alloc-N/free-N pattern vka uses in practice (free_index
    // only shrinks once *all* children are gone).
    if let Some(pid) = start {
        let remaining = child_count_dec(pid);
        if remaining == 0 {
            let s = KERNEL.get();
            let pcn = pid.cnode_idx() as usize;
            let psl = pid.slot() as usize;
            let parent_cap = s.cnode_slot(pcn, psl).map(|c| c.cap());
            let parent_of_parent = s.cnode_slot(pcn, psl).and_then(|c| c.parent());
            if let Some(Cap::Untyped { ptr, block_bits, is_device, .. }) = parent_cap {
                if let Some(slot) = s.cnode_slot_mut(pcn, psl) {
                    slot.set_cap(&Cap::Untyped {
                        ptr, block_bits, free_index: 0, is_device,
                    });
                }
                // Walk further up — this level just emptied,
                // so the parent's-parent might also have its
                // last child gone now. Recurse with this empty
                // parent as the deleted-cap.
                let _ = (deleted_base, deleted_size);
                reclaim_untyped_chain_at_tail(
                    parent_of_parent, ptr.addr(), 1u64 << block_bits);
            }
        }
        return;
    }

    // (0, 0) means the deleted cap is pool-indexed (TCB/EP/etc.); we
    // can't compare paddrs, so fall through to the full walk.
    if deleted_size != 0 {
        let s = KERNEL.get();
        if let Some(pid) = start {
            let pcn = pid.cnode_idx() as usize;
            let psl = pid.slot() as usize;
            if let Some(Cap::Untyped { ptr, free_index, .. }) =
                s.cnode_slot(pcn, psl).map(|c| c.cap())
            {
                let parent_base = ptr.addr();
                let parent_eff_end = parent_base + free_index;
                let deleted_end = deleted_base + deleted_size;
                // Deleted child's tail is below parent's
                // effective end → some other child still holds
                // the tail. No shrink possible.
                if deleted_end < parent_eff_end {
                    return;
                }
            }
        }
    }
    reclaim_untyped_chain(start);
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
        let cap = match s.cnode_slot(pcn, psl) {
            Some(c) => c.cap(),
            None => return,
        };
        let (parent_base, parent_block_bits, parent_free_index) = match cap {
            Cap::Untyped { ptr, block_bits, free_index, .. } => {
                (ptr.addr(), block_bits as u32, free_index)
            }
            _ => return,
        };
        let parent_total = 1u64 << parent_block_bits;
        let parent_end = parent_base + parent_total;
        // If parent already has free_index = 0, no work to do here
        // and no reason to walk the parent chain — the chain only
        // shrinks above us when this level shrank.
        if parent_free_index == 0 {
            return;
        }

        // Find the highest end-paddr among surviving children of pid.
        // Count ALL child cap types (not just Untyped) — Untyped::Retype
        // bumps the parent's free_index regardless of the resulting
        // child type, so frames/TCBs/EPs/etc. all consume the same
        // parent bytes and need to be tracked here too.
        let mut max_end: u64 = parent_base; // == "no children" sentinel
        for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
            let inner_count = s.cnode_slots_at(ci)
                .map(|sl| sl.len()).unwrap_or(0);
            for si in 0..inner_count {
                let cte = match s.cnode_slot(ci, si) {
                    Some(c) => c,
                    None => continue,
                };
                if cte.parent() != Some(pid) {
                    continue;
                }
                let (cbase, csize) = match cte.cap() {
                    Cap::Untyped { ptr, block_bits, .. } => {
                        (ptr.addr(), 1u64 << block_bits)
                    }
                    Cap::Frame { ptr, size, .. } => {
                        let n: u64 = match size {
                            crate::cap::FrameSize::Small => 4096,
                            crate::cap::FrameSize::Large => 2 * 1024 * 1024,
                            crate::cap::FrameSize::Huge => 1024 * 1024 * 1024,
                        };
                        (ptr.addr(), n)
                    }
                    Cap::PageTable { ptr, .. } => (ptr.addr(), 4096),
                    Cap::PageDirectory { ptr, .. } => (ptr.addr(), 4096),
                    Cap::Pdpt { ptr, .. } => (ptr.addr(), 4096),
                    Cap::PML4 { ptr, .. } => (ptr.addr(), 4096),
                    Cap::Endpoint { ptr, .. } => (ptr.addr(), 16),
                    Cap::Notification { ptr, .. } => (ptr.addr(), 32),
                    Cap::CNode { ptr, radix, .. } => {
                        // CNode storage = 2^radix * sizeof(Cte) bytes.
                        // We don't actually know the cte size here; use a
                        // conservative 32 bytes (matches Cte layout).
                        let n = (1u64 << radix) * 32;
                        (ptr.addr(), n)
                    }
                    Cap::Reply { ptr, .. } => (ptr.addr(), 32),
                    Cap::Thread { tcb } => (tcb.addr(), 4096),
                    Cap::SchedContext { ptr, size_bits, .. } => {
                        (ptr.addr(), 1u64 << size_bits)
                    }
                    _ => continue,
                };
                let end = cbase + csize;
                if end > max_end {
                    max_end = end;
                }
            }
        }
        let new_fi = max_end - parent_base;
        // Read the live cap, write back with updated free_index.
        if let Some(Cap::Untyped { ptr, block_bits, free_index, is_device }) =
            s.cnode_slot(pcn, psl).map(|c| c.cap())
        {
            if new_fi < free_index {
                let updated = Cap::Untyped {
                    ptr, block_bits, free_index: new_fi, is_device,
                };
                if let Some(slot) = s.cnode_slot_mut(pcn, psl) {
                    slot.set_cap(&updated);
                }
                // Continue up: maybe the parent's parent also has a
                // tail to reclaim now that this one shrank.
                cursor = s.cnode_slot(pcn, psl).and_then(|c| c.parent());
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
                // Phase 43 — properly migrate the thread between
                // priority queues. Without this, a TCB's priority
                // field is updated but it stays in its OLD priority
                // bucket — choose_thread keeps picking it as if it
                // were still high-priority, blocking lower-priority
                // wakes. sel4test's BIND005/006 lower the driver
                // from 255 to 9 expecting the helper at 10 to run;
                // without re-queue, the driver stays in the 255
                // bucket and the helper is starved.
                let cpu = s.scheduler.slab.get(id).affinity as usize;
                let was_runnable = s.scheduler.slab.get(id).is_runnable();
                if was_runnable {
                    s.scheduler.nodes[cpu].queues
                        .dequeue(&mut s.scheduler.slab, id);
                }
                s.scheduler.slab.get_mut(id).priority = prio;
                if was_runnable {
                    s.scheduler.nodes[cpu].queues
                        .enqueue(&mut s.scheduler.slab, id);
                    // If we just demoted the current thread on this
                    // CPU and a higher-priority thread is waiting,
                    // force a reschedule.
                    if s.scheduler.nodes[cpu].current == Some(id) {
                        if let Some(top) = s.scheduler.nodes[cpu]
                            .queues.peek_highest()
                        {
                            if top > prio {
                                s.scheduler.nodes[cpu].current = None;
                            }
                        }
                    }
                }
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
                        // Phase 43 — count is mr1 (= args.a3) per
                        // libsel4's `seL4_TCB_ReadRegisters` stub
                        // (mr0=suspend|flags, mr1=count, mr2..=output).
                        // We were reading it from mr2 (args.a4=0 here),
                        // which made `are_tcbs_distinct` see length=0
                        // and report "different TCBs".
                        let count = (args.a3 as usize).min(regs.len());
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
                    // (no fault_ep cptr in message words). Recover the
                    // fault EP cptr from the invoker's IPC buffer's
                    // caps_or_badges[0] so deliver_fault has something
                    // to look up later. FRAMEDIPC0003 needs this — its
                    // helper page-faults on a deleted-frame access and
                    // expects the kernel to send a fault to its fault
                    // EP, not to silently suspend.
                    let inv_tcb = s.scheduler.slab.get(invoker);
                    let ipc_paddr = inv_tcb.ipc_buffer_paddr;
                    let count = inv_tcb.pending_extra_caps_count as usize;
                    let fault_cptr = if count > 0 && ipc_paddr != 0 {
                        #[cfg(target_arch = "x86_64")]
                        unsafe {
                            let buf = crate::arch::x86_64::paging::phys_to_lin(
                                ipc_paddr) as *const u64;
                            core::ptr::read_volatile(
                                buf.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET))
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        { 0 }
                    } else { 0 };
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    let cnode = if count > 1 { Some(inv_tcb.pending_extra_caps[1]) } else { None };
                    let vspace = if count > 2 { Some(inv_tcb.pending_extra_caps[2]) } else { None };
                    inv_tcb.pending_extra_caps_count = 0;
                    // Stash the fault EP cptr on the target TCB.
                    s.scheduler.slab.get_mut(id).fault_handler = fault_cptr;
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
                // Refuse double-bind (matches seL4's behaviour) on
                // either side of the link.
                let t = s.scheduler.slab.get_mut(id);
                if t.bound_notification.is_some() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst)));
                }
                if s.notifications[ntfn_idx as usize].bound_tcb.is_some() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst)));
                }
                s.scheduler.slab.get_mut(id).bound_notification = Some(ntfn_idx);
                s.notifications[ntfn_idx as usize].bound_tcb = Some(id);
                Ok(())
            }
            InvocationLabel::TCBUnbindNotification => {
                let t = s.scheduler.slab.get_mut(id);
                if let Some(ntfn_idx) = t.bound_notification.take() {
                    if let Some(n) = s.notifications.get_mut(ntfn_idx as usize) {
                        n.bound_tcb = None;
                    }
                }
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
            // Save into the target TCB's cpu_context.fs_base so the
            // dispatcher restores it on next entry.
            InvocationLabel::TCBSetTLSBase => {
                let base = args.a2;
                s.scheduler.slab.get_mut(id).cpu_context.fs_base = base;
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    if Some(id) == crate::kernel::current_thread() {
                        use crate::arch::x86_64::msr::{wrmsr, IA32_FS_BASE};
                        wrmsr(IA32_FS_BASE, base);
                    }
                }
                Ok(())
            }
            // Phase 43 — `seL4_TCB_SetFlags(_service, clear, set)`
            // returns post-update flags via mr0 of the reply. The
            // result struct contains {error, flags}; the libsel4 stub
            // reads `flags = mr0`. Test FPU0003 verifies SetFlags is a
            // round-trip.
            InvocationLabel::TCBSetFlags => {
                let clear = args.a2;
                let set = args.a3;
                let new_flags = {
                    let t = s.scheduler.slab.get_mut(id);
                    t.flags = (t.flags & !clear) | set;
                    t.flags
                };
                let inv_t = s.scheduler.slab.get_mut(invoker);
                inv_t.msg_regs[0] = new_flags;
                inv_t.ipc_length = 1;
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
        untyped_retype_upstream_abi_far_offset();
        revoke_chain_clears_only_descendants();
        repeated_alloc_free_reclaims_untyped();
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

    /// Phase 43 — sel4test driver issues `seL4_Untyped_Retype` via
    /// libsel4's upstream ABI:
    ///   msginfo: label=UntypedRetype, extra_caps=1, length=6
    ///   mr0=type, mr1=size_bits, mr2=node_index, mr3=node_depth
    ///   IPC buf [4]=node_offset, [5]=num_objects
    ///   extraCaps[0]=root (dest CNode)
    /// We were silently failing to land the emitted cap at far slot
    /// indices for some test sequences. Reproduce the exact path here
    /// so any regression shows up in the kernel-spec phase rather than
    /// downstream as `_utspace_split_alloc: Failed to retype untyped`.
    #[inline(never)]
    fn untyped_retype_upstream_abi_far_offset() {
        let invoker = setup_invoker(0);
        // Override the invoker's CSpace cap to advertise the full
        // CNODE_RADIX so the retype can place a child at a "far"
        // slot index (>= 32). setup_invoker uses radix=5 by default
        // for legacy microtest specs.
        unsafe {
            let s = KERNEL.get();
            let cnode_ptr = KernelState::cnode_ptr(0);
            s.scheduler.slab.get_mut(invoker).cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: crate::kernel::CNODE_RADIX,
                guard_size: 64 - crate::kernel::CNODE_RADIX,
                guard: 0,
            };
        }
        let untyped_base = 0x0090_0000u64;
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
        // Stage the upstream ABI on the invoker's TCB: msg_regs[4] =
        // node_offset, msg_regs[5] = num_objects, pending_extra_caps[0]
        // = root cap. Mirrors what `handle_send` would have populated
        // from the IPC buffer + caps_or_badges[].
        let root_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        let target_slot = 0x57f;
        unsafe {
            let s = KERNEL.get();
            let t = s.scheduler.slab.get_mut(invoker);
            t.msg_regs[4] = target_slot;
            t.msg_regs[5] = 1;
            t.pending_extra_caps[0] = root_cap;
            t.pending_extra_caps_count = 1;
        }
        // Upstream ABI args:
        //   info.label = UntypedRetype, info.extra_caps = 1, length = 6
        //   a2 = type, a3 = size_bits, a4 = node_index, a5 = node_depth
        let info_word = ((InvocationLabel::UntypedRetype as u64) << 12)
            | (1u64 << 7)    // extra_caps = 1
            | 6u64;          // length = 6
        let args = SyscallArgs {
            a0: 0,
            a1: info_word,
            a2: ObjectType::Endpoint.to_word(),
            a3: 0,           // size_bits (unused for Endpoint)
            a4: 0,           // node_index = 0 (root cap IS dest CNode)
            a5: 0,           // node_depth = 0 (root cap directly)
        };
        decode_invocation(ut_cap, &args, invoker).expect("retype far ok");

        // Verify cap landed at the FAR slot we requested, not somewhere
        // else.
        unsafe {
            let s = KERNEL.get();
            match s.cnodes[0].0[target_slot as usize].cap() {
                Cap::Endpoint { .. } => {}
                other => panic!(
                    "expected Endpoint at far slot 0x{:x}, got {:?}",
                    target_slot, other),
            }
            // No collateral writes at slot 4 (the LEGACY-ABI default
            // dest_offset).
            assert!(s.cnodes[0].0[4].cap().is_null(),
                "slot 4 should remain Null when upstream ABI requests slot 0x{:x}",
                target_slot);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Untyped::Retype upstream ABI lands at requested far slot\n");
    }

    /// Phase 43 — sel4test's basic_tear_down revokes each rootserver
    /// Untyped after every test. Verify revoke clears the proper
    /// descendant subtree and leaves UNRELATED slots alone, even
    /// when those slots are far from the source slot index.
    /// (DOMAINS0001 fails after 17 tests; if revoke is silently
    /// nulling slot 0x57f despite no derivation chain to it, this
    /// spec will catch it.)
    #[inline(never)]
    fn revoke_chain_clears_only_descendants() {
        let invoker = setup_invoker(0);
        // Override cspace_root with full radix so slots 100, 200, 0x57f
        // are reachable.
        unsafe {
            let s = KERNEL.get();
            let cnode_ptr = KernelState::cnode_ptr(0);
            s.scheduler.slab.get_mut(invoker).cspace_root = Cap::CNode {
                ptr: cnode_ptr,
                radix: crate::kernel::CNODE_RADIX,
                guard_size: 64 - crate::kernel::CNODE_RADIX,
                guard: 0,
            };
        }
        let parent_ut = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(0x00A0_0000).unwrap(),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        // Plant an UNRELATED Untyped at slot 0x57f — must survive a
        // revoke of slot 0.
        let unrelated_ut = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(0x00B0_0000).unwrap(),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[0] = Cte::with_cap(&parent_ut);
            s.cnodes[0].0[0x57f] = Cte::with_cap(&unrelated_ut);
            // Default parent for the unrelated cap is None (sentinel).
            assert!(s.cnodes[0].0[0x57f].parent().is_none(),
                "fresh Cte::with_cap should have parent=None");
        }
        // Retype parent into a sub-Untyped at slot 100, then sub into
        // an Endpoint at slot 200 (chained derivation). Both should
        // be revoked when we revoke slot 0; slot 0x57f must NOT be.
        let cnode_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        // Legacy ABI: a3 = (size_bits << 32) | num_objects.
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: ObjectType::Untyped.to_word(),
            a3: (8u64 << 32) | 1,   // size_bits=8 (256B), num=1
            a4: 100,                // dest_offset
            ..Default::default()
        };
        decode_invocation(parent_ut, &args, invoker).expect("retype sub-ut");

        // Snapshot the sub-Untyped cap.
        let sub_ut = unsafe { KERNEL.get().cnodes[0].0[100].cap() };
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: ObjectType::Endpoint.to_word(),
            a3: 1,
            a4: 200,
            ..Default::default()
        };
        decode_invocation(sub_ut, &args, invoker).expect("retype ep");

        // Revoke the parent at slot 0.
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: 0,
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("revoke parent");

        unsafe {
            let s = KERNEL.get();
            // Parent cap stays in slot 0 (revoke source is preserved).
            assert!(matches!(s.cnodes[0].0[0].cap(), Cap::Untyped { .. }),
                "revoke source slot 0 should keep its cap");
            // Both descendants gone.
            assert!(s.cnodes[0].0[100].cap().is_null(),
                "sub-Untyped at 100 should be nulled");
            assert!(s.cnodes[0].0[200].cap().is_null(),
                "Endpoint at 200 should be nulled");
            // The unrelated Untyped MUST survive.
            match s.cnodes[0].0[0x57f].cap() {
                Cap::Untyped { ptr, .. } => assert_eq!(ptr.addr(), 0x00B0_0000,
                    "unrelated Untyped at 0x57f must survive an unrelated revoke"),
                other => panic!("unrelated cap at 0x57f got nulled by revoke: {:?}",
                    other),
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Revoke walks only the actual descendant subtree\n");
    }

    /// Phase 43 — TRIVIAL0001 in sel4test allocates an endpoint,
    /// frees it, and repeats 100 times. vka_alloc retypes the untyped;
    /// vka_free cnode_deletes the endpoint cap. After enough cycles the
    /// untyped's free_index must roll back so the next retype has room.
    /// Verify the alloc/free/realloc loop completes without
    /// NotEnoughMemory by exercising the kernel-side path directly.
    #[inline(never)]
    fn repeated_alloc_free_reclaims_untyped() {
        let invoker = setup_invoker(0);
        // 16 KiB Untyped — only fits ~256 16-byte endpoints with no
        // reclaim. We'll do 500 cycles to force reclaim to actually
        // happen.
        let ut_cap = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(0x00C0_0000).unwrap(),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[0] = Cte::with_cap(&ut_cap);
        }
        let cnode_cap = unsafe {
            KERNEL.get().scheduler.slab.get(invoker).cspace_root
        };
        for cycle in 0..500u32 {
            // Retype 1 endpoint at slot 4.
            let args = SyscallArgs {
                a1: (InvocationLabel::UntypedRetype as u64) << 12,
                a2: ObjectType::Endpoint.to_word(),
                a3: 1,
                a4: 4,
                ..Default::default()
            };
            let r = decode_invocation(ut_cap, &args, invoker);
            if r.is_err() {
                panic!("retype failed at cycle {} (free_index didn't reclaim?)",
                    cycle);
            }
            // Confirm cap landed.
            unsafe {
                let s = KERNEL.get();
                assert!(matches!(s.cnodes[0].0[4].cap(), Cap::Endpoint { .. }),
                    "endpoint missing at cycle {}", cycle);
            }
            // Mirror vka_free_object: revoke then delete. Some
            // vka implementations only call cnode_delete; others
            // do revoke + delete. Either should work.
            let rev_args = SyscallArgs {
                a1: (InvocationLabel::CNodeRevoke as u64) << 12,
                a2: 4,
                ..Default::default()
            };
            decode_invocation(cnode_cap, &rev_args, invoker)
                .expect("revoke ok");
            let del_args = SyscallArgs {
                a1: (InvocationLabel::CNodeDelete as u64) << 12,
                a2: 4,
                ..Default::default()
            };
            decode_invocation(cnode_cap, &del_args, invoker)
                .expect("delete ok");
            unsafe {
                let s = KERNEL.get();
                assert!(s.cnodes[0].0[4].cap().is_null(),
                    "slot 4 should be empty at cycle {}", cycle);
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ 500 alloc/free cycles reclaim untyped free_index\n");
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
