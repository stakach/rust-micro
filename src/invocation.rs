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

use crate::cap::{Cap, PAddr, PPtr};
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
        Cap::Untyped { .. } => "Ut",
        Cap::CNode { .. } => "Cn",
        Cap::Thread { .. } => "Tcb",
        Cap::IrqControl => "IrC",
        Cap::IrqHandler { .. } => "IrH",
        Cap::Frame { .. } => "Fr",
        Cap::PageTable { .. } => "PT",
        Cap::PageDirectory { .. } => "PD",
        Cap::Pdpt { .. } => "PDPT",
        Cap::PML4 { .. } => "PML4",
        Cap::AsidControl => "AsC",
        Cap::AsidPool { .. } => "AsP",
        Cap::SchedContext { .. } => "SC",
        Cap::SchedControl { .. } => "SCtl",
        Cap::Reply { .. } => "Rep",
        Cap::Endpoint { .. } => "Ep",
        Cap::Notification { .. } => "Ntfn",
        Cap::IOPort { .. } => "IoP",
        Cap::IOPortControl => "IoPC",
        Cap::IoSpace { .. } => "IoS",
        Cap::IoPageTable { .. } => "IoPT",
        Cap::Null => "Null",
        _ => "??",
    }
}

/// Print a small u64 in decimal via `crate::arch::log`. Avoids
/// pulling in `format!` in #[no_std].
fn log_dec(mut v: u64) {
    if v == 0 {
        crate::arch::log("0");
        return;
    }
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
    if !INV_TRACE {
        return;
    }
    crate::arch::log("<inv cap=");
    crate::arch::log(inv_cap_tag(target));
    crate::arch::log(" label=");
    log_dec(label_n);
    crate::arch::log(" xc=");
    log_dec(xc as u64);
    crate::arch::log(">\n");
}

fn inv_log_exit(result: &KResult<()>) {
    if !INV_TRACE {
        return;
    }
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
    if !INV_TRACE {
        return;
    }
    crate::arch::log(if call {
        "<send call cptr="
    } else {
        "<send cptr="
    });
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
    if !INV_TRACE {
        return;
    }
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
    if v == 0 {
        crate::arch::log("0");
        return;
    }
    let mut buf = [b'0'; 16];
    let mut i = 16;
    while v > 0 && i > 0 {
        i -= 1;
        let nib = (v & 0xF) as u8;
        buf[i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + (nib - 10)
        };
        v >>= 4;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

/// Like `log_hex` but without the `0x` prefix — for inline use.
pub fn log_hex_u64(mut v: u64) {
    if v == 0 {
        crate::arch::log("0");
        return;
    }
    let mut buf = [b'0'; 16];
    let mut i = 16;
    while v > 0 && i > 0 {
        i -= 1;
        let nib = (v & 0xF) as u8;
        buf[i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + (nib - 10)
        };
        v >>= 4;
    }
    if let Ok(s) = core::str::from_utf8(&buf[i..]) {
        crate::arch::log(s);
    }
}

/// Decode an invocation against a non-Endpoint cap. Called from
/// the IPC dispatcher when SysSend/SysCall targets a non-IPC cap.
pub fn decode_invocation(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    // Decode the invocation label from MessageInfo.
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let label_n = info.label();
    let xc_count = unsafe {
        KERNEL
            .get()
            .scheduler
            .slab
            .get(invoker)
            .pending_extra_caps_count
    };
    inv_log_entry(&target, label_n, xc_count);

    let label = match InvocationLabel::from_u64(label_n) {
        Some(l) => l,
        None => {
            let r = Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidArgument,
            )));
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
        Cap::SchedControl { core } => decode_sched_control(core, label, args, invoker),
        Cap::Reply { .. } => decode_reply(target, args, invoker),
        Cap::Domain => decode_domain(label, args, invoker),
        Cap::IOPort {
            first_port,
            last_port,
        } => decode_io_port(first_port, last_port, label, args, invoker),
        Cap::IOPortControl => decode_io_port_control(label, args, invoker),
        // Phase 44 — VT-d. IoPageTable caps take Map/Unmap; IoSpace
        // caps have no invocations of their own.
        Cap::IoPageTable { .. } => decode_x86_iopt(target, label, args, invoker),
        Cap::IoSpace { .. } => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
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
        InvocationLabel::X86PageMapIO => decode_x86_iomap(target, args, invoker),
        InvocationLabel::X86PageGetAddress => decode_frame_get_address(target, args, invoker),
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

unsafe fn update_invoked_frame_slot(
    args: &SyscallArgs,
    invoker: TcbId,
    paddr: u64,
    new_cap: Cap,
) -> KResult<()> {
    let s = KERNEL.get();
    let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
    let Ok(res) =
        crate::cspace::resolve_address_bits(s, &cspace_root, args.a0, crate::cspace::WORD_BITS)
    else {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidCapability,
        )));
    };
    if res.bits_remaining != 0 {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidCapability,
        )));
    }
    let cnode_idx = KernelState::cnode_index(res.slot_ptr);
    let Some(slot) = s.cnode_slot_mut(cnode_idx, res.slot_index) else {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidCapability,
        )));
    };
    match slot.cap() {
        Cap::Frame { ptr, .. } if ptr.addr() == paddr => {
            slot.set_cap(&new_cap);
            Ok(())
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_InvalidCapability,
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
    let (frame_ptr, paddr, size, _device, current_mapped) = match target {
        Cap::Frame {
            ptr,
            size,
            is_device,
            mapped,
            ..
        } => (ptr, ptr.addr(), size, is_device, mapped),
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
    // The rights word's bit 2 (0b100) carries `ExecuteNever` (`from_word` ignores
    // it) — set the page's NX bit so it can't be executed (W^X).
    let execute_never = args.a3 & 0b100 != 0;

    // Two wire formats coexist:
    //   * Phase 33d (compressed, microtest): args.a4 = vspace_cptr.
    //     extra_caps == 0.
    //   * Phase 42 upstream (sel4test): vspace passed as extraCaps[0],
    //     args.a4 = attr (we ignore — caching not yet modelled).
    //     Distinguished by msginfo.extra_caps() > 0.
    let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
    let upstream = info.extra_caps() > 0;

    if upstream {
        let staged_caps = unsafe {
            KERNEL
                .get()
                .scheduler
                .slab
                .get(invoker)
                .pending_extra_caps_count
        };
        if info.length() < 6 || staged_caps == 0 {
            unsafe {
                KERNEL
                    .get()
                    .scheduler
                    .slab
                    .get_mut(invoker)
                    .pending_extra_caps_count = 0;
            }
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_TruncatedMessage,
            )));
        }
    }

    // Per-size alignment. Small=4 KiB (12-bit), Large=2 MiB (21-bit),
    // Huge=1 GiB (30-bit). FRAMEEXPORTS0001 reserves a 1 GiB-aligned
    // vaddr range so all three sizes share the same base — only the
    // size_bits-derived stride between mappings matters.
    let align_bits: u32 = match size {
        crate::cap::FrameSize::Small => 12,
        crate::cap::FrameSize::Large => 21,
        crate::cap::FrameSize::Huge => 30,
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
                Some(Cap::PML4 { ptr, asid, .. }) if asid != 0 => Some((ptr.addr(), asid)),
                Some(Cap::PML4 { .. }) => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
                _ => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
            }
        } else if args.a4 != 0 {
            let cspace_root = KERNEL.get().scheduler.slab.get(invoker).cspace_root;
            let pml4_cap = crate::cspace::lookup_cap(KERNEL.get(), &cspace_root, args.a4)?;
            match pml4_cap {
                Cap::PML4 { ptr, asid, .. } if asid != 0 => Some((ptr.addr(), asid)),
                Cap::PML4 { .. } => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
                _ => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
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
                crate::cap::FrameSize::Small => usermode::map_user_4k_into_foreign_pml4(
                    pml4_paddr,
                    vaddr,
                    paddr,
                    writable,
                    execute_never,
                ),
                crate::cap::FrameSize::Large => usermode::map_user_2m_into_foreign_pml4(
                    pml4_paddr,
                    vaddr,
                    paddr,
                    writable,
                    execute_never,
                ),
                crate::cap::FrameSize::Huge => usermode::map_user_1g_into_foreign_pml4(
                    pml4_paddr,
                    vaddr,
                    paddr,
                    writable,
                    execute_never,
                ),
            };
            if let Err(missing) = map_result {
                if missing == 4 {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst,
                    )));
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
                    seL4_Error::seL4_FailedLookup,
                )));
            }
        } else if matches!(size, crate::cap::FrameSize::Small) {
            usermode::map_user_4k_public(vaddr, paddr, writable, execute_never);
        } else {
            // Legacy microtest path doesn't support Large/Huge.
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidArgument,
            )));
        }
    }

    // Update the invoked cap to reflect the mapping. Several caps can name the same physical frame
    // while carrying different map state, so the cptr in the invocation is the source of truth; a
    // paddr scan can mark a sibling cap and corrupt later derivations.
    let updated = Cap::Frame {
        ptr: frame_ptr,
        size,
        rights,
        mapped: Some(vaddr),
        asid: asid_for_cap,
        is_device: _device,
        map_type: crate::cap::FrameMapType::VSpace,
    };
    unsafe {
        update_invoked_frame_slot(args, invoker, paddr, updated)?;
    }
    Ok(())
}

/// Phase 44 — indexed ASID-pool lookup. Returns 0 if the ASID is
/// unassigned; callers treat that as an idempotent unmap/delete.
#[cfg(target_arch = "x86_64")]
fn pml4_paddr_for_asid(asid: u16) -> u64 {
    crate::asid::pml4_paddr(asid)
}

fn decode_frame_unmap(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    let (frame_ptr, paddr, size, rights, mapped_vaddr, asid, is_device, map_type) = match target {
        Cap::Frame {
            ptr,
            size,
            rights,
            mapped,
            asid,
            is_device,
            map_type,
        } => (
            ptr,
            ptr.addr(),
            size,
            rights,
            mapped,
            asid,
            is_device,
            map_type,
        ),
        _ => unreachable!(),
    };

    // Phase 44 — a frame mapped into a VT-d IO space is torn down via
    // unmapIOPage (clear the leaf VT-d PTE), NOT the vspace path. The
    // IO mapping's "asid" field is the PCI request-id.
    #[cfg(target_arch = "x86_64")]
    if map_type == crate::cap::FrameMapType::IoSpace {
        if let Some(io_address) = mapped_vaddr {
            unsafe {
                unmap_io_page(asid, io_address, paddr);
            }
        }
    } else if let Some(vaddr) = mapped_vaddr {
        unsafe {
            let pml4_paddr = pml4_paddr_for_asid(asid);
            if pml4_paddr != 0 {
                let unmapped = match size {
                    crate::cap::FrameSize::Small => {
                        crate::arch::x86_64::usermode::unmap_user_4k_in_pml4(
                            pml4_paddr, vaddr, paddr,
                        )
                    }
                    crate::cap::FrameSize::Large => {
                        crate::arch::x86_64::usermode::unmap_user_2m_in_pml4(
                            pml4_paddr, vaddr, paddr,
                        )
                    }
                    crate::cap::FrameSize::Huge => {
                        crate::arch::x86_64::usermode::unmap_user_1g_in_pml4(
                            pml4_paddr, vaddr, paddr,
                        )
                    }
                };
                if unmapped {
                    crate::smp::shootdown_tlb(vaddr);
                }
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = mapped_vaddr;
        let _ = size;
    }

    // Clear the mapping state in the invoked cap. Falling back to a paddr scan here would have the
    // same sibling-cap hazard as PageMap when the executive keeps separate mapped/client/source caps.
    let unmapped = Cap::Frame {
        ptr: frame_ptr,
        size,
        rights,
        mapped: None,
        asid: 0,
        is_device,
        map_type: crate::cap::FrameMapType::None,
    };
    unsafe {
        update_invoked_frame_slot(args, invoker, paddr, unmapped)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 44 — VT-d IO page-table / IO-frame invocations. Mirrors
// seL4 src/arch/x86/object/iospace.c.
// ---------------------------------------------------------------------------

/// Fetch the invoker's single pending extra cap (the IO-space cap),
/// consuming the pending list. Returns `Cap::Null` if none.
fn take_single_extra_cap(invoker: TcbId) -> Cap {
    unsafe {
        let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
        let cap = if inv_tcb.pending_extra_caps_count > 0 {
            inv_tcb.pending_extra_caps[0]
        } else {
            Cap::Null
        };
        inv_tcb.pending_extra_caps_count = 0;
        cap
    }
}

/// `X86IOPageTable::{Map,Unmap}` — decodeX86IOPTInvocation (iospace.c:169).
fn decode_x86_iopt(
    target: Cap,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::iommu;

        let (base_paddr, is_mapped, level, mapped_address, ioasid) = match target {
            Cap::IoPageTable {
                ptr,
                is_mapped,
                level,
                mapped_address,
                ioasid,
            } => (ptr.addr(), is_mapped, level, mapped_address, ioasid),
            _ => unreachable!(),
        };

        if label == InvocationLabel::X86IOPageTableUnmap {
            // deleteIOPageTable (iospace.c:397) then clear isMapped.
            unsafe {
                delete_io_page_table(base_paddr, is_mapped, level, mapped_address, ioasid);
            }
            let new_cap = Cap::IoPageTable {
                ptr: crate::cap::PPtr::new(base_paddr).unwrap(),
                is_mapped: false,
                level: 0,
                mapped_address: 0,
                ioasid: 0,
            };
            update_invoked_iopt_slot(args, invoker, base_paddr, new_cap)?;
            return Ok(());
        }

        if label != InvocationLabel::X86IOPageTableMap {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation,
            )));
        }

        // X86IOPageTableMap. extraCaps[0] = io_space, arg0 = io_address.
        let io_space = take_single_extra_cap(invoker);
        let io_address = args.a2 & !((1u64 << (iommu::VTD_PT_INDEX_BITS + iommu::PAGE_BITS)) - 1);

        if is_mapped {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
        let (pci_request_id, domain_id) = match io_space {
            Cap::IoSpace {
                pci_device,
                domain_id,
            } => (pci_device, domain_id),
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )))
            }
        };
        // asidInvalid == 0.
        if pci_request_id == 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }

        let ctx = unsafe { iommu::lookup_vtd_context_slot(pci_request_id, true) };
        let Some(ctx) = ctx else {
            // No IOMMU / pool exhausted.
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        };

        if !unsafe { ctx.present() } {
            // Install this PT as the context (1st-level) root.
            unsafe {
                ctx.install_root(domain_id, base_paddr);
            }
            // A device now has an IO-space context — turn on VT-d translation. Until now
            // DMA was identity (TE off); from here it's confined to mapped IOVAs.
            unsafe {
                iommu::enable_translation();
            }
            let new_cap = Cap::IoPageTable {
                ptr: crate::cap::PPtr::new(base_paddr).unwrap(),
                is_mapped: true,
                level: 0,
                mapped_address: 0,
                ioasid: pci_request_id,
            };
            update_invoked_iopt_slot(args, invoker, base_paddr, new_cap)?;
            return Ok(());
        }

        // Context present — install this PT as an intermediate table.
        let top = unsafe { ctx.asr() };
        let lu = unsafe { iommu::lookup_iopt_slot(top, io_address) };
        if !lu.ok {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let new_level = iommu::num_iopt_levels() - lu.level;
        if unsafe { iommu::slot_addr(lu.slot) } != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        unsafe {
            iommu::slot_install(lu.slot, base_paddr, true, true);
        }
        let new_cap = Cap::IoPageTable {
            ptr: crate::cap::PPtr::new(base_paddr).unwrap(),
            is_mapped: true,
            level: new_level as u8,
            mapped_address: io_address,
            ioasid: pci_request_id,
        };
        update_invoked_iopt_slot(args, invoker, base_paddr, new_cap)?;
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (target, label, args, invoker);
        Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        )))
    }
}

/// deleteIOPageTable (iospace.c:397). Clears whatever VT-d entry this
/// PT is installed at, if it still owns it.
#[cfg(target_arch = "x86_64")]
unsafe fn delete_io_page_table(
    base_paddr: u64,
    is_mapped: bool,
    level: u8,
    mapped_address: u64,
    ioasid: u16,
) {
    use crate::arch::x86_64::iommu;
    if !is_mapped {
        return;
    }
    let Some(ctx) = iommu::lookup_vtd_context_slot(ioasid, false) else {
        return;
    };
    if !ctx.present() {
        return;
    }
    let top = ctx.asr();
    if level == 0 {
        // Top-level: this PT is the context root. Only clear if it
        // still owns the context entry.
        if top != base_paddr {
            return;
        }
        ctx.clear();
    } else {
        let lu = iommu::lookup_iopt_slot_levels(
            top,
            mapped_address >> iommu::PAGE_BITS,
            (level - 1) as u64,
            (level - 1) as u64,
        );
        if !lu.ok || lu.level != 0 {
            return;
        }
        if iommu::slot_addr(lu.slot) != base_paddr {
            return;
        }
        iommu::slot_clear(lu.slot);
    }
}

/// unmapIOPage (iospace.c:453). Clears the leaf VT-d PTE for an
/// IO-mapped frame, if the frame still owns it.
#[cfg(target_arch = "x86_64")]
unsafe fn unmap_io_page(pci_request_id: u16, io_address: u64, frame_paddr: u64) {
    use crate::arch::x86_64::iommu;
    let Some(ctx) = iommu::lookup_vtd_context_slot(pci_request_id, false) else {
        return;
    };
    if !ctx.present() {
        return;
    }
    let top = ctx.asr();
    let lu = iommu::lookup_iopt_slot(top, io_address);
    if !lu.ok || lu.level != 0 {
        return;
    }
    if iommu::slot_addr(lu.slot) != frame_paddr {
        return;
    }
    iommu::slot_clear(lu.slot);
}

/// `X86Page::MapIO` — decodeX86IOMapInvocation (iospace.c:296). Maps a
/// 4 KiB frame into an IO space's leaf VT-d PTE.
fn decode_x86_iomap(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::iommu;

        let (frame_paddr, size, frame_rights, frame_mapped, frame_device) = match target {
            Cap::Frame {
                ptr,
                size,
                rights,
                mapped,
                is_device,
                ..
            } => (ptr.addr(), size, rights, mapped, is_device),
            _ => unreachable!(),
        };

        // Must be a 4 KiB page, currently unmapped.
        if !matches!(size, crate::cap::FrameSize::Small) {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
        if frame_mapped.is_some() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }

        // arg0 = rights mask, arg1 = io_address.
        let rights_mask = args.a2;
        let io_address = args.a3 & !((1u64 << iommu::PAGE_BITS) - 1);

        let io_space = take_single_extra_cap(invoker);
        let pci_request_id = match io_space {
            Cap::IoSpace { pci_device, .. } => pci_device,
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )))
            }
        };
        if pci_request_id == 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }

        let ctx = unsafe { iommu::lookup_vtd_context_slot(pci_request_id, false) };
        let Some(ctx) = ctx else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        };
        if !unsafe { ctx.present() } {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }

        let top = unsafe { ctx.asr() };
        let lu = unsafe { iommu::lookup_iopt_slot(top, io_address) };
        if !lu.ok || lu.level != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        if unsafe { iommu::slot_addr(lu.slot) } != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }

        // write/read = (rights mask) AND (frame rights).
        const ALLOW_WRITE: u64 = 1 << 0;
        const ALLOW_READ: u64 = 1 << 1;
        let write = (rights_mask & ALLOW_WRITE != 0)
            && matches!(frame_rights, crate::cap::FrameRights::ReadWrite);
        let read = (rights_mask & ALLOW_READ != 0)
            && !matches!(frame_rights, crate::cap::FrameRights::KernelOnly);
        if !write && !read {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidArgument,
            )));
        }
        unsafe {
            iommu::slot_install(lu.slot, frame_paddr, write, read);
        }

        // Record the IO mapping on the frame cap.
        let new_cap = Cap::Frame {
            ptr: crate::cap::PAddr::new(frame_paddr),
            size,
            rights: frame_rights,
            mapped: Some(io_address),
            asid: pci_request_id,
            is_device: frame_device,
            map_type: crate::cap::FrameMapType::IoSpace,
        };
        unsafe {
            update_invoked_frame_slot(args, invoker, frame_paddr, new_cap)?;
        }
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (target, args, invoker);
        Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        )))
    }
}

/// Overwrite the invoked IO page-table cap. The cptr in `args.a0` is the source of truth; scanning
/// by physical address can mutate an alias and scales poorly for the NT root CSpace.
#[cfg(target_arch = "x86_64")]
fn update_invoked_iopt_slot(
    args: &SyscallArgs,
    invoker: TcbId,
    base_paddr: u64,
    new_cap: Cap,
) -> KResult<()> {
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let Ok(res) =
            crate::cspace::resolve_address_bits(s, &cspace_root, args.a0, crate::cspace::WORD_BITS)
        else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        let Some(slot) = s.cnode_slot_mut(cnode_idx, res.slot_index) else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        match slot.cap() {
            Cap::IoPageTable { ptr, .. } if ptr.addr() == base_paddr => {
                slot.set_cap(&new_cap);
                Ok(())
            }
            _ => Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            ))),
        }
    }
}

/// `X86Page::GetAddress` — return the frame's physical address in
/// the caller's `msg_regs[0]`. The syscall return path fans this
/// out to user-mode `rdx` (Phase 15a).
fn decode_frame_get_address(target: Cap, _args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
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
// at the matching index and records both virtual address and ASID.
// Unmap verifies the parent entry still names this physical paging
// structure before detaching it and flushing the affected vspace.
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
        InvocationLabel::X86PageTableUnmap => decode_pt_unmap(target, args, invoker),
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
        InvocationLabel::X86PageDirectoryUnmap => decode_pd_unmap(target, args, invoker),
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
        InvocationLabel::X86PDPTUnmap => decode_pdpt_unmap(target, args, invoker),
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
fn map_paging_struct(target: Cap, args: &SyscallArgs, invoker: TcbId, level: u32) -> KResult<()> {
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

    let (installed, mapped_asid) = unsafe {
        let vspace: Option<(u64, u16)> = if upstream {
            let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
            let count = inv_tcb.pending_extra_caps_count as usize;
            let cap = if count > 0 {
                Some(inv_tcb.pending_extra_caps[0])
            } else {
                None
            };
            inv_tcb.pending_extra_caps_count = 0;
            match cap {
                Some(Cap::PML4 { ptr, asid, .. }) if asid != 0 => Some((ptr.addr(), asid)),
                Some(Cap::PML4 { .. }) => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
                _ => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
            }
        } else if args.a3 != 0 {
            let cspace_root = KERNEL.get().scheduler.slab.get(invoker).cspace_root;
            let pml4_cap = crate::cspace::lookup_cap(KERNEL.get(), &cspace_root, args.a3)?;
            match pml4_cap {
                Cap::PML4 { ptr, asid, .. } if asid != 0 => Some((ptr.addr(), asid)),
                Cap::PML4 { .. } => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
                _ => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
            }
        } else {
            #[cfg(not(feature = "spec"))]
            {
                let pml4_paddr = usermode::current_pml4_paddr();
                let Some(asid) = crate::asid::asid_for_pml4(pml4_paddr) else {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )));
                };
                Some((pml4_paddr, asid))
            }
            #[cfg(feature = "spec")]
            {
                None
            }
        };

        let mapped_asid = vspace.map(|(_, asid)| asid).unwrap_or(0);
        let installed = if let Some((pml4_paddr, _)) = vspace {
            usermode::install_user_table_in_paddr(pml4_paddr, level, vaddr, paddr)
        } else {
            #[cfg(not(feature = "spec"))]
            {
                usermode::install_user_table(level, vaddr, paddr)
            }
            #[cfg(feature = "spec")]
            {
                let _ = (level, vaddr, paddr);
                Ok(())
            }
        };
        (installed, mapped_asid)
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

    update_invoked_paging_slot(args, invoker, &target, Some(vaddr), mapped_asid)?;
    Ok(())
}

fn unmap_paging_struct(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    unsafe {
        if !paging_cap_is_final(KERNEL.get(), &target) {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RevokeFirst,
            )));
        }
    }
    if paging_structure_mapping(&target).is_some() {
        // seL4's explicit paging-structure Unmap clears the table after a best-effort detach.
        // Deletion finalization deliberately does not clear it: the source Untyped owns reuse.
        detach_paging_structure(&target);
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let table =
                crate::arch::x86_64::paging::phys_to_lin(paging_struct_state(&target).0) as *mut u8;
            core::ptr::write_bytes(table, 0, 4096);
        }
    }
    update_invoked_paging_slot(args, invoker, &target, None, 0)?;
    Ok(())
}

fn same_paging_object(a: &Cap, b: &Cap) -> bool {
    match (a, b) {
        (Cap::PageTable { ptr: a, .. }, Cap::PageTable { ptr: b, .. }) => a.addr() == b.addr(),
        (Cap::PageDirectory { ptr: a, .. }, Cap::PageDirectory { ptr: b, .. }) => {
            a.addr() == b.addr()
        }
        (Cap::Pdpt { ptr: a, .. }, Cap::Pdpt { ptr: b, .. }) => a.addr() == b.addr(),
        _ => false,
    }
}

/// seL4 keeps same-object caps adjacent in its MDB, making this query constant-time. rust-micro's
/// compact parent-only MDB has no sibling link, so mapped paging structures use a bounded registry
/// walk. This is intentionally limited to explicit unmap and mapped-cap finalization; ordinary cap
/// deletion remains O(1).
unsafe fn paging_cap_is_final(s: &crate::kernel::KernelState, cap: &Cap) -> bool {
    if !matches!(
        cap,
        Cap::PageTable { .. } | Cap::PageDirectory { .. } | Cap::Pdpt { .. }
    ) {
        return false;
    }
    let mut references = 0u32;
    for ci in 0..KernelState::cnode_pool_count() {
        let Some(slots) = s.cnode_slots_at(ci) else {
            continue;
        };
        for slot in slots {
            if same_paging_object(&slot.cap(), cap) {
                references += 1;
                if references > 1 {
                    return false;
                }
            }
        }
    }
    references == 1
}

unsafe fn finalise_cap_mapping(s: &crate::kernel::KernelState, cap: &Cap) {
    if matches!(
        cap,
        Cap::PageTable { .. } | Cap::PageDirectory { .. } | Cap::Pdpt { .. }
    ) {
        if paging_structure_mapping(cap).is_some() && paging_cap_is_final(s, cap) {
            // `unmapPageTable`/`unmapPageDirectory`/`unmapPDPT` are best-effort in seL4. A parent
            // table or ASID may already be gone; final capability deletion still succeeds.
            detach_paging_structure(cap);
        }
    } else {
        detach_frame_mapping(cap);
    }
}

fn derive_paging_structure(cap: &Cap) -> KResult<()> {
    if matches!(
        cap,
        Cap::PageTable { mapped: None, .. }
            | Cap::PageDirectory { mapped: None, .. }
            | Cap::Pdpt { mapped: None, .. }
            | Cap::PML4 { mapped: false, .. }
    ) {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        )));
    }
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

fn paging_structure_mapping(cap: &Cap) -> Option<(u64, u64, u16, u32)> {
    match *cap {
        Cap::PageTable {
            ptr,
            mapped: Some(vaddr),
            asid,
        } => Some((ptr.addr(), vaddr, asid, 1)),
        Cap::PageDirectory {
            ptr,
            mapped: Some(vaddr),
            asid,
        } => Some((ptr.addr(), vaddr, asid, 2)),
        Cap::Pdpt {
            ptr,
            mapped: Some(vaddr),
            asid,
        } => Some((ptr.addr(), vaddr, asid, 3)),
        _ => None,
    }
}

fn detach_paging_structure(cap: &Cap) -> bool {
    let Some((paddr, vaddr, asid, level)) = paging_structure_mapping(cap) else {
        return false;
    };
    let pml4_paddr = pml4_paddr_for_asid(asid);
    if pml4_paddr == 0 {
        return false;
    }
    let detached = unsafe {
        crate::arch::x86_64::usermode::unmap_user_table_in_paddr(pml4_paddr, level, vaddr, paddr)
    };
    if detached {
        crate::smp::shootdown_vspace(pml4_paddr);
    }
    detached
}

fn detach_frame_mapping(cap: &Cap) {
    if let Cap::Frame {
        ptr,
        size,
        mapped: Some(vaddr),
        asid,
        map_type,
        ..
    } = *cap
    {
        unsafe {
            if map_type == crate::cap::FrameMapType::IoSpace {
                unmap_io_page(asid, vaddr, ptr.addr());
            } else if map_type == crate::cap::FrameMapType::VSpace {
                let pml4_paddr = pml4_paddr_for_asid(asid);
                if pml4_paddr != 0 {
                    let unmapped = match size {
                        crate::cap::FrameSize::Small => {
                            crate::arch::x86_64::usermode::unmap_user_4k_in_pml4(
                                pml4_paddr,
                                vaddr,
                                ptr.addr(),
                            )
                        }
                        crate::cap::FrameSize::Large => {
                            crate::arch::x86_64::usermode::unmap_user_2m_in_pml4(
                                pml4_paddr,
                                vaddr,
                                ptr.addr(),
                            )
                        }
                        crate::cap::FrameSize::Huge => {
                            crate::arch::x86_64::usermode::unmap_user_1g_in_pml4(
                                pml4_paddr,
                                vaddr,
                                ptr.addr(),
                            )
                        }
                    };
                    if unmapped {
                        crate::smp::shootdown_tlb(vaddr);
                    }
                }
            }
        }
    }
}

const CNODE_WORK_CAPACITY: usize = KernelState::cnode_pool_count();
const CNODE_WORK_WORDS: usize = (CNODE_WORK_CAPACITY + 63) / 64;
const _: () = assert!(CNODE_WORK_CAPACITY <= u16::MAX as usize);

/// Bounded by the complete CNode identity registry rather than by nesting depth.
struct CNodeWorkList {
    entries: [u16; CNODE_WORK_CAPACITY],
    seen: [u64; CNODE_WORK_WORDS],
    head: usize,
    tail: usize,
}

impl CNodeWorkList {
    const fn new() -> Self {
        Self {
            entries: [0; CNODE_WORK_CAPACITY],
            seen: [0; CNODE_WORK_WORDS],
            head: 0,
            tail: 0,
        }
    }

    fn reset(&mut self) {
        self.seen.fill(0);
        self.head = 0;
        self.tail = 0;
    }

    fn push(&mut self, vi: usize) -> bool {
        if vi >= CNODE_WORK_CAPACITY {
            return false;
        }
        let bit = 1u64 << (vi % 64);
        if self.seen[vi / 64] & bit != 0 {
            return true;
        }
        if self.tail == self.entries.len() {
            return false;
        }
        self.seen[vi / 64] |= bit;
        self.entries[self.tail] = vi as u16;
        self.tail += 1;
        true
    }

    fn pop(&mut self) -> Option<usize> {
        if self.head == self.tail {
            return None;
        }
        let vi = self.entries[self.head] as usize;
        self.head += 1;
        Some(vi)
    }
}

struct CNodeWorkCell(core::cell::UnsafeCell<CNodeWorkList>);

unsafe impl Sync for CNodeWorkCell {}

static CNODE_WORK: CNodeWorkCell = CNodeWorkCell(core::cell::UnsafeCell::new(CNodeWorkList::new()));

/// Invocation and finalization run under the kernel BKL. Reuse one static queue so a traversal over
/// the complete CNode registry does not consume most of a 4 KiB per-TCB kernel stack.
unsafe fn cnode_worklist() -> &'static mut CNodeWorkList {
    let work = &mut *CNODE_WORK.0.get();
    work.reset();
    work
}

unsafe fn cnode_tree_registered(s: &crate::kernel::KernelState, cap: &Cap) -> bool {
    let Cap::CNode { ptr, .. } = cap else {
        return true;
    };

    let work = cnode_worklist();
    if !work.push(KernelState::cnode_index(*ptr)) {
        return false;
    }
    while let Some(vi) = work.pop() {
        let Some(slots) = s.cnode_slots_at(vi) else {
            return false;
        };
        for slot in slots {
            let inner = slot.cap();
            if inner.is_null() {
                continue;
            }
            if let Cap::CNode { ptr: inner_ptr, .. } = inner {
                if !work.push(KernelState::cnode_index(inner_ptr)) {
                    return false;
                }
            }
        }
    }
    true
}

unsafe fn cnode_release_mappings_valid(
    s: &crate::kernel::KernelState,
    cap: &Cap,
    cleared_refs: u32,
    cleared_self_refs: u32,
) -> bool {
    let Cap::CNode { ptr, .. } = cap else {
        return true;
    };
    let vi = KernelState::cnode_index(*ptr);
    let Some(slots) = s.cnode_slots_at(vi) else {
        return false;
    };
    let self_refs = slots
        .iter()
        .filter(|slot| {
            matches!(slot.cap(), Cap::CNode { ptr: inner, .. } if inner.addr() == ptr.addr())
        })
        .count() as u32;
    let Some(remaining_refs) = crate::kernel::cap_refcount(cap).checked_sub(cleared_refs) else {
        return false;
    };
    let Some(remaining_self_refs) = self_refs.checked_sub(cleared_self_refs) else {
        return false;
    };
    remaining_refs != remaining_self_refs || cnode_tree_registered(s, cap)
}

unsafe fn revoke_cnode_clear_counts(
    s: &crate::kernel::KernelState,
    object_vi: usize,
    revoke_epoch: u32,
    source: (usize, usize),
) -> (u32, u32) {
    let mut refs = 0u32;
    let mut self_refs = 0u32;
    for ci in 0..KernelState::cnode_pool_count() {
        let slot_count = s.cnode_slots_at(ci).map_or(0, |slots| slots.len());
        for si in 0..slot_count {
            if (ci, si) == source || !cte_revoke_marked(s, ci, si, revoke_epoch) {
                continue;
            }
            let Some(Cap::CNode { ptr, .. }) = s.cnode_slot(ci, si).map(|slot| slot.cap()) else {
                continue;
            };
            if KernelState::cnode_index(ptr) != object_vi {
                continue;
            }
            refs = refs
                .checked_add(1)
                .expect("CNode clear reference count overflow");
            if ci == object_vi {
                self_refs = self_refs
                    .checked_add(1)
                    .expect("CNode self-reference count overflow");
            }
        }
    }
    (refs, self_refs)
}

fn paging_cap_with_mapping(
    cap: Cap,
    target_paddr: u64,
    new_mapped: Option<u64>,
    new_asid: u16,
) -> Option<Cap> {
    match cap {
        Cap::PageTable { ptr, .. } if ptr.addr() == target_paddr => Some(Cap::PageTable {
            ptr,
            mapped: new_mapped,
            asid: new_asid,
        }),
        Cap::PageDirectory { ptr, .. } if ptr.addr() == target_paddr => Some(Cap::PageDirectory {
            ptr,
            mapped: new_mapped,
            asid: new_asid,
        }),
        Cap::Pdpt { ptr, .. } if ptr.addr() == target_paddr => Some(Cap::Pdpt {
            ptr,
            mapped: new_mapped,
            asid: new_asid,
        }),
        _ => None,
    }
}

fn update_invoked_paging_slot(
    args: &SyscallArgs,
    invoker: TcbId,
    cap: &Cap,
    new_mapped: Option<u64>,
    new_asid: u16,
) -> KResult<()> {
    let target_paddr = paging_struct_state(cap).0;
    unsafe {
        let s = KERNEL.get();
        let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
        let Ok(res) =
            crate::cspace::resolve_address_bits(s, &cspace_root, args.a0, crate::cspace::WORD_BITS)
        else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        let Some(slot) = s.cnode_slot_mut(cnode_idx, res.slot_index) else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        if let Some(updated) =
            paging_cap_with_mapping(slot.cap(), target_paddr, new_mapped, new_asid)
        {
            slot.set_cap(&updated);
            Ok(())
        } else {
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )))
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
fn decode_pt_unmap(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    unmap_paging_struct(target, args, invoker)
}
fn decode_pd_unmap(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    unmap_paging_struct(target, args, invoker)
}
fn decode_pdpt_unmap(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    unmap_paging_struct(target, args, invoker)
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

/// x86_64 has `seL4_NumASIDPoolsBits = 3` → 8 ASID pools total.
/// Pool index 0 is the rootserver's pre-allocated
/// `InitThreadASIDPool` (asid_base 0); MakePool carves indices
/// 1..8, so `asid_base = index * 512`. Bounded + recyclable pool
/// indices keep the per-pool bookkeeping arrays small and stable
/// across create/free cycles (vs an ever-growing base counter).
const MAX_ASID_POOLS: usize = crate::asid::MAX_ASID_POOLS;

/// Bitmap of in-use pool indices (bit i = index i). Bit 0 (the init
/// pool) is permanently set. MakePool allocates the lowest clear bit
/// in 1..8 (→ DeleteFirst when full, VSPACE0004); freeing an AsidPool
/// cap clears its bit (so the index recycles).
static ASID_POOL_INUSE: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(1);

/// Per-pool count of ASIDs handed out, indexed by pool index
/// (`asid_base / 512`, always 0..8). Assign returns `seL4_DeleteFirst`
/// once a pool's count hits 512 (`seL4_ASIDPoolIndexBits = 9` →
/// VSPACE0005 "overassigning ASID pool"). Only consulted for
/// MakePool'd pools (asid_base != 0); the init pool keeps the global
/// wrapping offset.
#[allow(clippy::declare_interior_mutable_const)]
static ASID_POOL_USED: [core::sync::atomic::AtomicU16; MAX_ASID_POOLS] = {
    const Z: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
    [Z; MAX_ASID_POOLS]
};

/// Allocate the lowest free pool index in 1..MAX_ASID_POOLS, or
/// `None` if all are in use. Resets that pool's used-count.
fn alloc_asid_pool_index() -> Option<usize> {
    use core::sync::atomic::Ordering;
    let mut bits = ASID_POOL_INUSE.load(Ordering::Relaxed);
    for idx in 1..MAX_ASID_POOLS {
        let mask = 1u16 << idx;
        if bits & mask == 0 {
            ASID_POOL_INUSE.store(bits | mask, Ordering::Relaxed);
            ASID_POOL_USED[idx].store(0, Ordering::Relaxed);
            return Some(idx);
        }
        let _ = &mut bits;
    }
    None
}

/// Release a pool index (called when its AsidPool cap is deleted).
fn free_asid_pool_index(idx: usize) {
    use core::sync::atomic::Ordering;
    if idx == 0 || idx >= MAX_ASID_POOLS {
        return;
    }
    let bits = ASID_POOL_INUSE.load(Ordering::Relaxed);
    ASID_POOL_INUSE.store(bits & !(1u16 << idx), Ordering::Relaxed);
    ASID_POOL_USED[idx].store(0, Ordering::Relaxed);
    crate::asid::clear_pool((idx * crate::asid::ASIDS_PER_POOL) as u16);
}

/// Reset the ASID-allocator statics to their post-boot defaults.
/// Called once at rootserver launch so spec-phase MakePool/Assign
/// runs don't leak into the real test suite's pool accounting.
pub fn reset_asid_state() {
    use core::sync::atomic::Ordering;
    ASID_POOL_INUSE.store(1, Ordering::Relaxed);
    for u in ASID_POOL_USED.iter() {
        u.store(0, Ordering::Relaxed);
    }
    crate::asid::reset();
    NEXT_ASID_OFFSET.store(2, Ordering::Relaxed);
}

fn decode_asid_control(label: InvocationLabel, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    use core::sync::atomic::Ordering;
    match label {
        InvocationLabel::X86ASIDControlMakePool => {
            // Two ABI shapes coexist:
            //   * Upstream (libsel4 `seL4_X86_ASIDControl_MakePool`):
            //       extraCaps[0] = Untyped (pool storage)
            //       extraCaps[1] = dest CNode (root)
            //       mr0 (a2)     = dest slot index
            //       mr1 (a3)     = depth
            //   * Legacy (kernel spec): a2 = Untyped cap_ptr,
            //       a3 = dest CNode cptr (ignored → invoker CSpace),
            //       a4 = dest slot index.
            let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
            let upstream = info.extra_caps() >= 2;

            unsafe {
                let s = KERNEL.get();
                let invoker_cspace = s.scheduler.slab.get(invoker).cspace_root;

                let (untyped, dest_cnode_cap, dest_index, depth) = if upstream {
                    let inv = s.scheduler.slab.get(invoker);
                    if inv.pending_extra_caps_count < 2 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )));
                    }
                    let untyped = inv.pending_extra_caps[0];
                    let root = inv.pending_extra_caps[1];
                    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
                    (untyped, root, args.a2 as usize, args.a3 as u32)
                } else {
                    let untyped = crate::cspace::lookup_cap(s, &invoker_cspace, args.a2)?;
                    (untyped, invoker_cspace, args.a4 as usize, 0u32)
                };

                // Pools are limited (MAX_ASID_POOLS); the 8th MakePool
                // must fail (VSPACE0004). Check up front so we don't
                // consume the untyped on a doomed call; the index is
                // actually claimed below once all validation passes.
                if (ASID_POOL_INUSE.load(Ordering::Relaxed) & ((1u16 << MAX_ASID_POOLS) - 1))
                    == ((1u16 << MAX_ASID_POOLS) - 1)
                {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst,
                    )));
                }

                let mut state = match crate::untyped::UntypedState::from_cap(&untyped) {
                    Some(s) => s,
                    None => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };

                // Resolve the dest slot within the dest CNode cap at
                // `depth` (upstream) or directly (legacy depth==0).
                let cnode_ptr = match dest_cnode_cap {
                    Cap::CNode { ptr, .. } => ptr,
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };
                let (cnode_idx, dest_offset) = if upstream && depth != 0 {
                    let res = crate::cspace::resolve_address_bits(
                        s,
                        &dest_cnode_cap,
                        dest_index as u64,
                        depth,
                    )?;
                    if res.bits_remaining != 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_FailedLookup,
                        )));
                    }
                    (KernelState::cnode_index(res.slot_ptr), res.slot_index)
                } else {
                    (KernelState::cnode_index(cnode_ptr), dest_index)
                };

                let slots = match s.cnode_slots_at_mut(cnode_idx) {
                    Some(s) => s,
                    None => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };
                if dest_offset >= slots.len() || !slots[dest_offset].cap().is_null() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst,
                    )));
                }

                // Carve 4 KiB out of the Untyped for the pool storage.
                // Manual carve (mirrors what `retype()` does for one
                // child of size 2^12 = 4 KiB).
                let aligned = (state.free_index_bytes + 0xFFF) & !0xFFF;
                let block_total = 1u64 << state.block_bits;
                if aligned + 0x1000 > block_total {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_NotEnoughMemory,
                    )));
                }
                let pool_paddr = state.base + aligned;
                state.free_index_bytes = aligned + 0x1000;
                // Claim a bounded pool index (validation has passed).
                // `alloc_asid_pool_index` also zeroes this pool's
                // per-pool ASID-used counter so Assign can enforce the
                // 512-ASID limit (VSPACE0005). asid_base = index * 512.
                let pool_index = match alloc_asid_pool_index() {
                    Some(i) => i,
                    None => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_DeleteFirst,
                        )))
                    }
                };
                let asid_base = (pool_index as u16) * 512;

                let pool_cap = Cap::AsidPool {
                    ptr: PPtr::<crate::cap::AsidPoolStorage>::new(pool_paddr).ok_or_else(|| {
                        KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidArgument,
                        ))
                    })?,
                    asid_base,
                };
                slots[dest_offset].set_cap(&pool_cap);
                // Locate the source Untyped's slot in this CNode (the
                // upstream extraCap resolves into the rootserver's flat
                // cspace, same CNode as the dest). Used for the MDB
                // parent link and to commit the bumped free_index.
                let mut untyped_slot = None;
                for (i, slot) in slots.iter().enumerate() {
                    if let Cap::Untyped { ptr, .. } = slot.cap() {
                        if ptr.addr() == state.base {
                            untyped_slot = Some(i);
                            break;
                        }
                    }
                }
                if let Some(usl) = untyped_slot {
                    // Phase 30 — record the new pool's MDB parent as
                    // the source Untyped's slot.
                    let parent_id = crate::cte::MdbId::pack(cnode_idx as u32, usl as u32);
                    slots[dest_offset].set_parent(Some(parent_id));
                    child_count_inc(parent_id, 1);
                    // Commit the bumped Untyped state back into its slot.
                    slots[usl].set_cap(&state.to_cap());
                }
                let _ = pool_index; // index claimed above
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
    use core::sync::atomic::Ordering;
    let (asid_base, pool_paddr) = match target {
        Cap::AsidPool { asid_base, ptr } => (asid_base, ptr.addr()),
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
                            seL4_Error::seL4_InvalidCapability,
                        )));
                    }
                    let cap = inv_tcb.pending_extra_caps[0];
                    let buf_paddr = inv_tcb.ipc_buffer_paddr;
                    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
                    if buf_paddr == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )));
                    }
                    let buf = crate::arch::x86_64::paging::phys_to_lin(buf_paddr) as *const u64;
                    let cptr =
                        core::ptr::read_volatile(buf.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET));
                    let res = crate::cspace::resolve_address_bits(s, &invoker_cspace, cptr, 64)?;
                    if res.bits_remaining != 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_FailedLookup,
                        )));
                    }
                    (KernelState::cnode_index(res.slot_ptr), res.slot_index, cap)
                } else {
                    let cnode_ptr = match invoker_cspace {
                        Cap::CNode { ptr, .. } => ptr,
                        _ => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
                    };
                    let cnode_idx = KernelState::cnode_index(cnode_ptr);
                    let slot_idx = args.a2 as usize;
                    let slots = match s.cnode_slots_at(cnode_idx) {
                        Some(s) => s,
                        None => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
                    };
                    if slot_idx >= slots.len() {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_RangeError,
                        )));
                    }
                    (cnode_idx, slot_idx, slots[slot_idx].cap())
                };
                let (ptr, mapped) = match vspace_cap {
                    Cap::PML4 {
                        ptr,
                        mapped,
                        asid: 0,
                    } => (ptr, mapped),
                    // Already assigned to an ASID — upstream
                    // decodeX86ASIDPoolAssign returns InvalidCapability
                    // (VSPACE0002 assigns the already-mapped
                    // page_directory and expects exactly that).
                    Cap::PML4 { .. } => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };
                // Allocate the next ASID in this pool.
                //   * MakePool'd pools (asid_base != 0): use a per-pool
                //     used-counter in the storage page so the pool
                //     enforces its 512-ASID limit (VSPACE0005 assigns
                //     512 then expects DeleteFirst). These pools don't
                //     unassign mid-test, so a counter (not a bitmap)
                //     is sufficient.
                //   * Init pool (asid_base == 0): the rootserver pool
                //     that every inter-AS test process draws from —
                //     keep the existing global wrapping offset (never
                //     exhausts), so its many assign/teardown cycles
                //     across the suite stay unaffected.
                let _ = pool_paddr;
                let assigned = if asid_base != 0 {
                    let idx = (asid_base / 512) as usize;
                    let used = ASID_POOL_USED
                        .get(idx)
                        .map(|u| u.load(Ordering::Relaxed))
                        .unwrap_or(0);
                    if used >= 512 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_DeleteFirst,
                        )));
                    }
                    if let Some(u) = ASID_POOL_USED.get(idx) {
                        u.store(used + 1, Ordering::Relaxed);
                    }
                    asid_base.saturating_add(used)
                } else {
                    asid_base.saturating_add(
                        (NEXT_ASID_OFFSET.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
                            & 0x1FF) as u16,
                    )
                };
                if let Some(slot) = s.cnode_slot_mut(slot_cnode_idx, slot_idx) {
                    slot.set_cap(&Cap::PML4 {
                        ptr,
                        mapped,
                        asid: assigned,
                    });
                }
                Ok(())
            }
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// Per-pool offset bumper for the init ASID pool. Starts at 2 so the
/// first user-process assignment doesn't collide with rootserver ASID 1.
static NEXT_ASID_OFFSET: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);

// ---------------------------------------------------------------------------
// Phase 36d — Reply cap invocations. Send on a Cap::Reply wakes
// the TCB the kernel bound to it during the originating Call. The
// reply message rides in args.a2..a5 (and the IPC buffer for
// length > 4). Mirrors seL4 MCS's `seL4_Send(replyCap, msginfo)`.
// ---------------------------------------------------------------------------

pub(crate) const REPLY_HANDOFF_MAGIC: Word = 0x4e54_4f53_5245_5431;

fn reply_handoff_requested(s: &KernelState, invoker: TcbId) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        s.scheduler.slab.get(invoker).user_context.r13 == REPLY_HANDOFF_MAGIC
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (s, invoker);
        false
    }
}

fn handoff_marked_reply_to_caller(
    s: &mut KernelState,
    invoker: TcbId,
    caller: TcbId,
    handoff_requested: bool,
) {
    if !handoff_requested || s.scheduler.current() != Some(invoker) {
        return;
    }
    let Some(invoker_tcb) = s.scheduler.slab.try_get(invoker) else {
        return;
    };
    let Some(caller_tcb) = s.scheduler.slab.try_get(caller) else {
        return;
    };
    if !caller_tcb.is_runnable()
        || !caller_tcb.is_schedulable()
        || !caller_tcb.enqueued
        || caller_tcb.affinity != invoker_tcb.affinity
        || caller_tcb.domain != s.scheduler.cur_domain
    {
        return;
    }
    s.scheduler.set_current(Some(caller));
}

fn clear_receiver_call_state_for_reply_caller(s: &mut KernelState, caller: TcbId) {
    for entry in s.scheduler.slab.entries.iter_mut() {
        let Some(tcb) = entry.as_mut() else {
            continue;
        };
        if tcb.reply_to == Some(caller) {
            tcb.reply_to = None;
            tcb.active_sc = None;
        }
        if tcb.composite_reply_handoff == Some(caller) {
            tcb.composite_reply_handoff = None;
        }
    }
}

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
            None => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )))
            }
        };
        let handoff_requested = reply_handoff_requested(s, invoker);
        #[cfg(target_arch = "x86_64")]
        if handoff_requested {
            s.scheduler.slab.get_mut(invoker).user_context.r13 = 0;
        }
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
                let buf = (crate::arch::x86_64::paging::phys_to_lin(me.ipc_buffer_paddr)
                    as *const u64)
                    .wrapping_add(1);
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
        // Fault replies bypass the normal message transfer: the
        // caller is blocked on a FAULT (not a syscall), so the IPC
        // fan-out below would stomp its live registers. Apply
        // upstream handleFaultReply semantics instead.
        if s.scheduler.slab.get(caller).pending_fault != 0 {
            let restart = crate::fault::apply_fault_reply(s, caller, label, length as usize, &regs);
            s.scheduler.slab.get_mut(invoker).active_sc = None;
            s.replies[idx].bound_tcb = None;
            // Only clear the legacy reply_to stash if it names THIS
            // caller — the replier may hold a SECOND outstanding reply
            // (TIMEOUTFAULT0002: a handler replies to the client via
            // one reply cap while still owing a TimeoutReply to the
            // server, whose caller lives in reply_to).
            if s.scheduler.slab.get(invoker).reply_to == Some(caller) {
                s.scheduler.slab.get_mut(invoker).reply_to = None;
            }
            // IPC0021 — return the SC the faulter donated to a passive
            // fault handler (fault delivery is a Call) so the restarted
            // faulter is schedulable again.
            crate::sched_context::return_donated_sc(s, caller);
            if restart {
                s.scheduler.make_runnable(caller);
                handoff_marked_reply_to_caller(s, invoker, caller, handoff_requested);
            } else {
                s.scheduler
                    .block(caller, crate::tcb::ThreadStateType::Inactive);
            }
            return Ok(());
        }
        let _ = (label, length, regs);
        // Full message transfer (register range + long tail) +
        // IPC-return fan-in, shared with endpoint IPC so long
        // replies (IPC0002/0003, up to seL4_MsgMaxLength) work.
        crate::endpoint::deliver_message(&mut s.scheduler, invoker, caller, 0);
        debug_assert!(matches!(
            s.scheduler.slab.get(caller).state,
            crate::tcb::ThreadStateType::BlockedOnReply
        ));
        // Phase 33c — return the donated SC.
        s.scheduler.slab.get_mut(invoker).active_sc = None;
        // Passive-server reply: move the donated SC back to the caller
        // (upstream reply_pop), making the server passive again and
        // the caller schedulable.
        crate::sched_context::return_donated_sc(s, caller);
        s.scheduler.make_runnable(caller);
        handoff_marked_reply_to_caller(s, invoker, caller, handoff_requested);
        // Clear the reply binding — the slot is reusable for the
        // next Call once the receiver Recv's on the same Reply
        // cap (or a different one).
        s.replies[idx].bound_tcb = None;
        // Also clear the legacy stash so a stale `reply_to` doesn't
        // double-wake — but only when it names THIS caller (the
        // replier may owe a second, unrelated reply; see the fault
        // branch above, TIMEOUTFAULT0002).
        if s.scheduler.slab.get(invoker).reply_to == Some(caller) {
            s.scheduler.slab.get_mut(invoker).reply_to = None;
        }
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
        Cap::SchedContext { ptr, .. } => KernelState::sched_context_index(ptr) as u16,
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
                            seL4_Error::seL4_InvalidCapability,
                        )));
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
                        // Upstream decodeSchedContext_Bind: binding a
                        // TCB when the TCB already has an SC, or this SC
                        // already has a bound TCB, is IllegalOperation
                        // (SCHED_CONTEXT_0003), not DeleteFirst.
                        if s.scheduler.slab.get(tcb_id).sc.is_some() {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_IllegalOperation,
                            )));
                        }
                        if s.sched_contexts[sc_id as usize].bound_tcb.is_some() {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_IllegalOperation,
                            )));
                        }
                        let was_runnable = s.scheduler.slab.get(tcb_id).is_runnable();
                        s.scheduler.slab.get_mut(tcb_id).sc = Some(sc_id);
                        s.sched_contexts[sc_id as usize].bound_tcb = Some(tcb_id);
                        // The SC carries the core it was configured for
                        // (per-core SchedControl). The bound thread follows
                        // it there so a later Resume runs it on that core —
                        // this is the configure-then-bind order used by
                        // sel4utils (SCHED_CONTEXT_0014), where Configure saw
                        // no bound TCB to migrate. Pull an already-queued
                        // thread off its old core first; the make_runnable /
                        // on_sc_gained paths below re-enqueue on the new
                        // affinity. Gated to the smp build (the default
                        // single-node build ignores per-core affinity).
                        #[cfg(feature = "smp")]
                        {
                            let target = s.sched_contexts[sc_id as usize].core as u32;
                            let old = s.scheduler.slab.get(tcb_id).affinity;
                            if old != target && was_runnable {
                                let dom = s.scheduler.slab.get(tcb_id).domain as usize;
                                s.scheduler.nodes[old as usize].queues[dom]
                                    .dequeue(&mut s.scheduler.slab, tcb_id);
                            }
                            s.scheduler.slab.get_mut(tcb_id).affinity = target;
                        }
                        // Phase 43 — BIND005 deferred wake. If a
                        // notification was signalled while this TCB
                        // had no SC, the badge is parked in the
                        // notification's Active state. Now that the
                        // TCB has an SC again, drain the pending
                        // badge into the TCB and wake it.
                        let bn = s.scheduler.slab.get(tcb_id).bound_notification;
                        let mut woke_for_badge = false;
                        if let Some(bn_idx) = bn {
                            let ntfn = &mut s.notifications[bn_idx as usize];
                            if matches!(ntfn.state, crate::notification::NtfnState::Active) {
                                let badge = ntfn.pending_badge;
                                ntfn.pending_badge = 0;
                                ntfn.state = crate::notification::NtfnState::Idle;
                                let was_blocked_recv = matches!(
                                    s.scheduler.slab.get(tcb_id).state,
                                    crate::tcb::ThreadStateType::BlockedOnReceive
                                );
                                if was_blocked_recv {
                                    crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, tcb_id);
                                }
                                let tcb_t = s.scheduler.slab.get_mut(tcb_id);
                                tcb_t.ipc_badge = badge;
                                #[cfg(target_arch = "x86_64")]
                                {
                                    tcb_t.user_context.rdi = badge;
                                    tcb_t.user_context.rsi = 0;
                                }
                                s.scheduler.make_runnable(tcb_id);
                                woke_for_badge = true;
                            }
                        }
                        // IPC0017 — binding an SC to a server that was
                        // already runnable but passive (it popped a
                        // message while SC-less and is now Running but
                        // unscheduled) makes it schedulable: enqueue it.
                        // Skip if the badge path already (re)enqueued it.
                        if was_runnable && !woke_for_badge {
                            s.scheduler.on_sc_gained(tcb_id);
                        }
                    }
                    Cap::Notification { ptr, .. } => {
                        let ntfn_idx = KernelState::ntfn_index(ptr);
                        // Upstream: binding when this SC already has a
                        // notification bound is IllegalOperation
                        // (SCHED_CONTEXT_0003). We track the SC->ntfn
                        // link on the notification (bound_sc), so scan
                        // for an existing binding of this SC.
                        if s.notifications
                            .iter()
                            .enumerate()
                            .any(|(i, n)| i != ntfn_idx && n.bound_sc == Some(sc_id))
                            || s.notifications[ntfn_idx].bound_sc == Some(sc_id)
                        {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_IllegalOperation,
                            )));
                        }
                        let ntfn = &mut s.notifications[ntfn_idx];
                        // Bind SC to this notification so future
                        // signal()s donate budget to the bound TCB.
                        // Record the SC on the notification AND on the
                        // bound TCB so signal() can find both.
                        if let Some(bt) = ntfn.bound_tcb {
                            let tcb = s.scheduler.slab.get_mut(bt);
                            if tcb.sc.is_none() {
                                tcb.sc = Some(sc_id);
                                s.sched_contexts[sc_id as usize].bound_tcb = Some(bt);
                            }
                        }
                        // Mark the SC as bound to the notification so
                        // unbind can find it.
                        ntfn.bound_sc = Some(sc_id);
                    }
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                }
            }
            Ok(())
        }
        InvocationLabel::SchedContextUnbind => {
            unsafe {
                let s = KERNEL.get();
                if let Some(tcb_id) = s.sched_contexts[sc_id as usize].bound_tcb {
                    #[cfg(all(feature = "smp", target_arch = "x86_64"))]
                    crate::smp::remote_tcb_stall(tcb_id);
                    // Remove from the ready queue / surrender the CPU
                    // before clearing the SC so a runnable thread that
                    // loses its SC can't keep being scheduled. IPC0017
                    // unbinds a server's SC so it can't run while
                    // clients block waiting for it.
                    s.scheduler.on_sc_lost(tcb_id);
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
        // SchedContext_UnbindObject — unbind ONE specific object (a
        // TCB or a notification) from this SC (SCHED_CONTEXT_0003).
        // Object via extraCaps[0] (upstream) or a2 (legacy). Non
        // TCB/ntfn → InvalidCapability; an object not currently bound
        // to this SC → IllegalOperation.
        InvocationLabel::SchedContextUnbindObject => {
            let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
            let upstream = info.extra_caps() > 0;
            unsafe {
                let s = KERNEL.get();
                let obj_cap = if upstream {
                    let inv = s.scheduler.slab.get_mut(invoker);
                    if inv.pending_extra_caps_count == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )));
                    }
                    let c = inv.pending_extra_caps[0];
                    inv.pending_extra_caps_count = 0;
                    c
                } else {
                    let cspace = s.scheduler.slab.get(invoker).cspace_root;
                    crate::cspace::lookup_cap(s, &cspace, args.a2)?
                };
                match obj_cap {
                    Cap::Thread { tcb } => {
                        let tcb_id = crate::tcb::TcbId(tcb.addr() as u16);
                        if s.sched_contexts[sc_id as usize].bound_tcb != Some(tcb_id) {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_IllegalOperation,
                            )));
                        }
                        #[cfg(all(feature = "smp", target_arch = "x86_64"))]
                        crate::smp::remote_tcb_stall(tcb_id);
                        s.scheduler.on_sc_lost(tcb_id);
                        s.scheduler.slab.get_mut(tcb_id).sc = None;
                        s.sched_contexts[sc_id as usize].bound_tcb = None;
                    }
                    Cap::Notification { ptr, .. } => {
                        let ntfn_idx = KernelState::ntfn_index(ptr);
                        if s.notifications[ntfn_idx].bound_sc != Some(sc_id) {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_IllegalOperation,
                            )));
                        }
                        s.notifications[ntfn_idx].bound_sc = None;
                    }
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                }
            }
            Ok(())
        }
        // Upstream seL4_MCS `SchedContext_Consumed`: return the total
        // execution charged since the previous consumed report and reset
        // that report counter. Cumulative bound/donated accounting is a
        // separate rust-micro extension below and is deliberately untouched.
        InvocationLabel::SchedContextConsumed => {
            unsafe {
                let s = KERNEL.get();
                let sc = &mut s.sched_contexts[sc_id as usize];
                let consumed_us = sc.consumed.saturating_mul(1000);
                sc.consumed = 0;
                let inv = s.scheduler.slab.get_mut(invoker);
                inv.msg_regs[0] = consumed_us;
                inv.ipc_length = 1;
            }
            Ok(())
        }
        // rust-micro capability-scoped extension. Return cumulative time
        // spent by the SC's bound TCB and time spent while the same SC was
        // donated over IPC. The counters are monotonic for the lifetime of
        // the SC and use seL4_Time microseconds on the wire.
        InvocationLabel::SchedContextReadRuntime => {
            unsafe {
                let s = KERNEL.get();
                let sc = &s.sched_contexts[sc_id as usize];
                let bound_us = sc.bound_consumed.saturating_mul(1000);
                let donated_us = sc.donated_consumed.saturating_mul(1000);
                let inv = s.scheduler.slab.get_mut(invoker);
                inv.msg_regs[0] = bound_us;
                inv.msg_regs[1] = donated_us;
                inv.ipc_length = 2;
            }
            Ok(())
        }
        // SCHED0017 — SchedContext_YieldTo. Mirrors upstream
        // decodeSchedContext_YieldTo error paths:
        //   * unbound SC                          → IllegalOperation
        //   * target tcb == invoker (self-yield)  → IllegalOperation
        //   * target.priority > invoker.mcp       → IllegalOperation
        //   * target unrunnable                   → NoError, consumed=0
        // The "actually yield budget" path needs timer infrastructure
        // (charge consumption, swap SCs, reschedule); SCHED0019 is
        // gated on that and not in the regex yet.
        InvocationLabel::SchedContextYieldTo => {
            unsafe {
                let s = KERNEL.get();
                let bound = s.sched_contexts[sc_id as usize].bound_tcb;
                let target_id = match bound {
                    Some(t) => t,
                    None => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_IllegalOperation,
                        )))
                    }
                };
                if target_id == invoker {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_IllegalOperation,
                    )));
                }
                let target_prio = s.scheduler.slab.get(target_id).priority;
                let inv_mcp = s.scheduler.slab.get(invoker).mcp;
                if target_prio > inv_mcp {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_IllegalOperation,
                    )));
                }
                // Upstream: a prior yielder against this SC gets its
                // consumed-report completed before the new yield.
                if let Some(prev) = s.sched_contexts[sc_id as usize].yield_from {
                    crate::sched_context::complete_yield_to(s, prev, sc_id as usize);
                }
                // schedContext_resume-ish: a budget-parked target
                // with a mature refill becomes runnable again.
                let now = crate::sched_context::current_time();
                if s.scheduler.slab.get(target_id).state
                    == crate::tcb::ThreadStateType::BlockedOnBudget
                    && crate::sched_context::refill_ready(&s.sched_contexts[sc_id as usize], now)
                    && s.sched_contexts[sc_id as usize].count > 0
                {
                    s.scheduler.make_runnable(target_id);
                }
                let runnable = s.scheduler.slab.get(target_id).is_runnable();
                let inv_prio = s.scheduler.slab.get(invoker).priority;
                if runnable && target_prio >= inv_prio {
                    // True yield (upstream invokeSchedContext_YieldTo
                    // return_now = false): link yielder ↔ SC, force a
                    // reschedule so the target gets the CPU, and DO
                    // NOT write the consumed-report yet — it's
                    // written by complete_yield_if_pending when the
                    // yielder is next dispatched (activateThread
                    // equivalent), capturing time the target consumed
                    // in between.
                    s.sched_contexts[sc_id as usize].yield_from = Some(invoker);
                    s.scheduler.slab.get_mut(invoker).yield_to = Some(sc_id);
                    let cpu = s.scheduler.slab.get(invoker).affinity as usize;
                    if s.scheduler.nodes[cpu].current == Some(invoker) {
                        s.scheduler.nodes[cpu].current = None;
                    }
                    return Ok(());
                }
                // Immediate-return paths (target unrunnable, or
                // lower priority than us — it can't preempt, so the
                // yield is a no-op): report consumed now.
                let consumed_us = s.sched_contexts[sc_id as usize]
                    .consumed
                    .saturating_mul(1000);
                s.sched_contexts[sc_id as usize].consumed = 0;
                let inv = s.scheduler.slab.get_mut(invoker);
                inv.msg_regs[0] = consumed_us;
                inv.ipc_length = 1;
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
    sched_control_core: u32,
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
            // The upstream ABI carries budget/period in MICROSECONDS
            // (decodeSchedControl_ConfigureFlags runs usToTicks); the
            // legacy/spec ABI passes raw ticks. Keep the raw values
            // for branch-appropriate validation and convert µs->ticks
            // (our tick = 1 ms) only for the upstream path.
            let (sc_cap_opt, raw_budget, raw_period) = if upstream {
                unsafe {
                    let inv_tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
                    let cap = if inv_tcb.pending_extra_caps_count > 0 {
                        Some(inv_tcb.pending_extra_caps[0])
                    } else {
                        None
                    };
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
                // Cap-type check first (matches upstream order):
                // SCHED_CONTEXT_0001 expects InvalidCapability before
                // any RangeError.
                let sc_idx = match sc_cap_opt {
                    Some(Cap::SchedContext { ptr, .. }) => KernelState::sched_context_index(ptr),
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };
                // Validate budget/period (SCHED_CONTEXT_0001). Upstream
                // checks the raw µs against MIN_BUDGET_US (= 2*10 on
                // x86/non-TK1); the legacy/spec ABI is already in ticks.
                let bad = if upstream {
                    const MIN_BUDGET_US: u64 = 2 * 10;
                    raw_budget < MIN_BUDGET_US || raw_period == 0 || raw_budget > raw_period
                } else {
                    raw_budget == 0 || raw_period == 0 || raw_budget > raw_period
                };
                if bad {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_RangeError,
                    )));
                }
                let (budget, period) = if upstream {
                    let to_ticks = |us: u64| (us / 1000).max(1);
                    (to_ticks(raw_budget), to_ticks(raw_period))
                } else {
                    (raw_budget, raw_period)
                };
                let sc = &mut s.sched_contexts[sc_idx];
                // Upstream invokeSchedControl_ConfigureFlags only
                // rebuilds the refill ring (refill_new /
                // refill_update) — scTcb survives a reconfigure.
                // Wiping the whole struct here detached the bound
                // TCB: SCHED0018/19 call set_helper_sched_params on
                // an already-bound helper, and the subsequent
                // YieldTo saw an "unbound" SC.
                let keep_bound = sc.bound_tcb;
                let keep_yield = sc.yield_from;
                let keep_consumed = sc.consumed;
                let keep_bound_consumed = sc.bound_consumed;
                let keep_donated_consumed = sc.donated_consumed;
                *sc = crate::sched_context::SchedContext::new(period, budget);
                sc.bound_tcb = keep_bound;
                sc.yield_from = keep_yield;
                sc.consumed = keep_consumed;
                sc.bound_consumed = keep_bound_consumed;
                sc.donated_consumed = keep_donated_consumed;
                // scBadge — mr3 (= a5) in ConfigureFlags; surfaced as
                // seL4_Timeout_Data in a timeout fault (TIMEOUTFAULT).
                // Legacy/spec callers leave a5 = 0.
                sc.badge = args.a5;
                // Seed one ready refill so a freshly-configured SC
                // can be charged immediately.
                sc.refills[0] = crate::sched_context::Refill {
                    release_time: 0,
                    amount: budget,
                };
                sc.head = 0;
                sc.count = 1;
                // Record the core this SC is configured for (seL4 scCore).
                // A TCB bound to this SC afterwards follows it onto this
                // core — needed when Configure runs before Bind
                // (SCHED_CONTEXT_0014's configure-then-bind order), where
                // the migrate below sees no bound TCB yet.
                sc.core = sched_control_core as u8;
                // SMP: the per-core SchedControl cap names the core this
                // SC (and its bound thread) should run on. Migrate the
                // bound thread there. seL4 binds the core to the SC; we
                // drive the bound TCB's affinity directly. MULTICORE0002
                // /0003/0005 need the helper to actually run on `core`.
                // Gated behind the `smp` cargo feature. The default
                // (DOMAINS / single-node) build reports numNodes=4 but
                // must IGNORE per-core affinity, exactly as it did
                // before SMP landed — otherwise the cross-core IPC tests
                // (IPC0001/0003 "SMP Send+Recv", which loop over
                // env->cores) migrate threads onto APs and hit the
                // unfinished inter-AS-process-on-AP path and hang. The
                // MULTICORE build (`build_kernel.sh smp`) enables it.
                #[cfg(feature = "smp")]
                if let Some(tcb) = keep_bound {
                    // seL4 `remoteTCBStall` precedes `migrateTCB`: if the
                    // bound thread is currently running on another core,
                    // stall that core off it before moving it, so it can't
                    // run on two cores at once (MULTICORE0002/0003).
                    #[cfg(target_arch = "x86_64")]
                    crate::smp::remote_tcb_stall(tcb);
                    s.scheduler.migrate_tcb(tcb, sched_control_core);
                }
                #[cfg(not(feature = "smp"))]
                let _ = (keep_bound, sched_control_core);
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

fn decode_irq_control(label: InvocationLabel, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    match label {
        InvocationLabel::IRQIssueIRQHandler => {
            // a2 = IRQ number, a3 = dest slot index
            if args.a2 >= crate::interrupt::MAX_IRQ as u64 {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_RangeError,
                )));
            }
            let irq = args.a2 as u16;
            let dest_index = args.a3 as usize;
            unsafe {
                let s = KERNEL.get();
                let cspace_root = s.scheduler.slab.get(invoker).cspace_root;
                let cnode_ptr = match cspace_root {
                    Cap::CNode { ptr, .. } => ptr,
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };
                let cnode_idx = KernelState::cnode_index(cnode_ptr);
                let slots = match s.cnode_slots_at(cnode_idx) {
                    Some(s) => s,
                    None => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
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
                if crate::kernel::cap_refcount(&Cap::IrqHandler { irq }) != 0 {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_RevokeFirst,
                    )));
                }
                crate::interrupt::reserve_source(
                    &mut s.irqs,
                    irq,
                    crate::interrupt::IrqSource::Generic,
                )
                .map_err(|_| {
                    KException::SyscallError(SyscallError::new(seL4_Error::seL4_RevokeFirst))
                })?;
                s.cnode_slot_mut(cnode_idx, dest_index)
                    .expect("validated IRQ destination slot")
                    .set_cap(&Cap::IrqHandler { irq });
            }
            Ok(())
        }
        InvocationLabel::X86IRQIssueIRQHandlerIOAPIC => issue_x86_ioapic_irq_handler(args, invoker),
        InvocationLabel::X86IRQIssueIRQHandlerMSI => {
            // MSI needs an interrupt-remapping/configuration implementation. Never mint a handler
            // for hardware the kernel has not actually programmed.
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation,
            )))
        }
        _ => Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        ))),
    }
}

/// Resolve an IOAPIC request against the immutable boot catalog, then program the exact
/// controller-local pin before publishing the handler capability.
fn issue_x86_ioapic_irq_handler(_args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    unsafe {
        let s = KERNEL.get();
        let inv_tcb = s.scheduler.slab.get(invoker);
        let dest_cptr = inv_tcb.msg_regs[0];
        let depth = inv_tcb.msg_regs[1] as u32;
        let ioapic = inv_tcb.msg_regs[2];
        let pin = inv_tcb.msg_regs[3];
        let level = inv_tcb.msg_regs[4];
        let polarity = inv_tcb.msg_regs[5];
        let vector = inv_tcb.msg_regs[6];
        let dest_root = if inv_tcb.pending_extra_caps_count > 0 {
            inv_tcb.pending_extra_caps[0]
        } else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;

        if vector < crate::interrupt::FIRST_IOAPIC_IRQ as u64
            || vector > crate::interrupt::LAST_IOAPIC_IRQ as u64
            || ioapic > usize::MAX as u64
            || pin > u32::MAX as u64
            || level > 1
            || polarity > 1
        {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        match crate::arch::x86_64::ioapic::validate_route(ioapic as usize, pin as u32) {
            Ok(()) => {}
            Err(crate::arch::x86_64::ioapic::IoApicError::NoTopology) => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_IllegalOperation,
                )))
            }
            Err(
                crate::arch::x86_64::ioapic::IoApicError::ControllerOutOfRange
                | crate::arch::x86_64::ioapic::IoApicError::PinOutOfRange,
            ) => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_RangeError,
                )))
            }
            Err(_) => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_IllegalOperation,
                )))
            }
        }

        if !matches!(dest_root, Cap::CNode { .. }) {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
        let res = crate::cspace::resolve_address_bits(s, &dest_root, dest_cptr, depth)?;
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        let Some(slot) = s.cnode_slot(cnode_idx, res.slot_index) else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        if !slot.cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        let handler = Cap::IrqHandler { irq: vector as u16 };
        if crate::kernel::cap_refcount(&handler) != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RevokeFirst,
            )));
        }
        let route_source = crate::interrupt::IrqSource::IoApic {
            controller: ioapic as u16,
            pin: pin as u16,
        };
        crate::interrupt::can_reserve_source(&s.irqs, vector as u16, route_source).map_err(
            |_| KException::SyscallError(SyscallError::new(seL4_Error::seL4_RevokeFirst)),
        )?;
        let cpu_vector = vector as u32 + crate::arch::x86_64::pic::PIC1_VECTOR_BASE as u32;
        crate::arch::x86_64::ioapic::program_redirection(
            ioapic as usize,
            pin as u32,
            cpu_vector,
            level as u32,
            polarity as u32,
            true,
        )
        .map_err(|_| {
            KException::SyscallError(SyscallError::new(seL4_Error::seL4_IllegalOperation))
        })?;
        crate::interrupt::reserve_source(&mut s.irqs, vector as u16, route_source)
            .expect("validated exclusive IRQ source");
        s.cnode_slot_mut(cnode_idx, res.slot_index)
            .expect("validated destination slot")
            .set_cap(&handler);
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
unsafe fn io_in8(_p: u16) -> u8 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_in16(_p: u16) -> u16 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_in32(_p: u16) -> u32 {
    0
}
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
            seL4_Error::seL4_RangeError,
        )));
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
                    seL4_Error::seL4_IllegalOperation,
                )));
            }
        }
    }
    Ok(())
}

/// Domain-cap invocations. Mirrors seL4 `decodeDomainInvocation`
/// (src/object/domain.c):
///   * `DomainSet_Set(domain, thread)` — assign a TCB to a domain.
///   * `DomainSet_ScheduleConfigure(index, domain, duration)` — write
///     one entry of the domain schedule table.
///   * `DomainSet_ScheduleSetStart(index)` — set the schedule start
///     index and force an immediate switch.
/// CONFIG_NUM_DOMAINS=4 / CONFIG_NUM_DOMAIN_SCHEDULES=100 in the matched
/// libsel4 (DOMAINS=ON). DOMAINS0000-0005,9999 exercise these.
fn decode_domain(label: InvocationLabel, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
    use crate::scheduler::{DSCHED_MAX_DURATION, NUM_DOMAINS, NUM_DOM_SCHEDULES};
    let err = |e| Err(KException::SyscallError(SyscallError::new(e)));
    match label {
        InvocationLabel::DomainSetSet => {
            let domain = args.a2;
            // getSyscallArg(0) = domain; domain >= numDomains is an
            // InvalidArgument (note: ScheduleConfigure uses RangeError).
            if domain >= NUM_DOMAINS as u64 {
                return err(seL4_Error::seL4_InvalidArgument);
            }
            unsafe {
                let s = KERNEL.get();
                let inv_tcb = s.scheduler.slab.get_mut(invoker);
                if inv_tcb.pending_extra_caps_count == 0 {
                    return err(seL4_Error::seL4_TruncatedMessage);
                }
                let tcb_cap = inv_tcb.pending_extra_caps[0];
                inv_tcb.pending_extra_caps_count = 0;
                let tcb_id = match tcb_cap {
                    Cap::Thread { tcb } => crate::tcb::TcbId(tcb.addr() as u16),
                    _ => return err(seL4_Error::seL4_InvalidArgument),
                };
                #[cfg(all(feature = "smp", target_arch = "x86_64"))]
                crate::smp::remote_tcb_stall(tcb_id);
                // setDomain: re-queues the thread under the new domain.
                s.scheduler.set_domain(tcb_id, domain as u8);
            }
            Ok(())
        }
        InvocationLabel::DomainScheduleConfigure => {
            // args: index, domain, duration.
            let index = args.a2;
            let domain = args.a3;
            let duration = args.a4;
            // Last entry stays an end marker, hence the -1.
            if index >= (NUM_DOM_SCHEDULES as u64) - 1 {
                return err(seL4_Error::seL4_RangeError);
            }
            if domain >= NUM_DOMAINS as u64 {
                return err(seL4_Error::seL4_RangeError);
            }
            if duration > DSCHED_MAX_DURATION {
                return err(seL4_Error::seL4_InvalidArgument);
            }
            // Both domain and duration must be zero for end markers.
            if duration == 0 && domain != 0 {
                return err(seL4_Error::seL4_InvalidArgument);
            }
            unsafe {
                let s = KERNEL.get();
                // The starting schedule's duration must not be zero.
                if index as usize == s.scheduler.dom_sched_start && duration == 0 {
                    return err(seL4_Error::seL4_InvalidArgument);
                }
                s.scheduler.dom_sched[index as usize] = crate::scheduler::DomScheduleEntry {
                    domain: domain as u8,
                    duration,
                };
            }
            Ok(())
        }
        InvocationLabel::DomainScheduleSetStart => {
            let index = args.a2;
            if index >= NUM_DOM_SCHEDULES as u64 {
                return err(seL4_Error::seL4_RangeError);
            }
            unsafe {
                let s = KERNEL.get();
                // The starting schedule must not be an end marker.
                if s.scheduler.dom_sched[index as usize].duration == 0 {
                    return err(seL4_Error::seL4_InvalidArgument);
                }
                // Force an immediate switch to the new starting index:
                // end the current slice and park the cursor just before
                // the (reserved) end marker so the next choose_thread
                // wraps to `start`. Mirrors invokeDomainScheduleSetStart.
                s.scheduler.dom_sched_start = index as usize;
                s.scheduler.domain_time = 0;
                s.scheduler.dom_sched_idx = NUM_DOM_SCHEDULES - 2;
                s.scheduler.set_current(None);
            }
            Ok(())
        }
        _ => err(seL4_Error::seL4_IllegalOperation),
    }
}

fn decode_io_port_control(
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    if !matches!(label, InvocationLabel::X86IOPortControlIssue) {
        return Err(KException::SyscallError(SyscallError::new(
            seL4_Error::seL4_IllegalOperation,
        )));
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
            seL4_Error::seL4_InvalidArgument,
        )));
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
                seL4_Error::seL4_InvalidCapability,
            )));
        };
        if !matches!(dest_root, Cap::CNode { .. }) {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
        let res = crate::cspace::resolve_address_bits(s, &dest_root, dest_index, depth)?;
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        let slot = match s.cnode_slot_mut(cnode_idx, res.slot_index) {
            Some(s) => s,
            None => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability,
                )))
            }
        };
        if !slot.cap().is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        slot.set_cap(&Cap::IOPort {
            first_port: first,
            last_port: last,
        });
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
                crate::interrupt::ack_irq(&mut s.irqs, irq).map_err(|_| {
                    KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))
                })?;
                #[cfg(target_arch = "x86_64")]
                if let Ok(crate::interrupt::IrqSource::IoApic { controller, pin }) =
                    crate::interrupt::source(&s.irqs, irq)
                {
                    let _ = crate::arch::x86_64::ioapic::set_route_mask(
                        controller as usize,
                        pin as u32,
                        false,
                    );
                }
                Ok(())
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
                            seL4_Error::seL4_InvalidCapability,
                        )));
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
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };
                let ntfn_idx = KernelState::ntfn_index(ntfn_ptr) as u16;
                // Replace any existing handler binding and install
                // the new one. The badge from the badged cap is
                // recorded on the IRQ entry so handle_interrupt can
                // signal with it (sel4test minted BIT(N) per timer).
                let _ = crate::interrupt::clear_handler(&mut s.irqs, irq);
                crate::interrupt::set_notification(&mut s.irqs, irq, ntfn_idx, ntfn_badge)
                    .map_err(|_| {
                        KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        ))
                    })?;
                #[cfg(target_arch = "x86_64")]
                {
                    if let Ok(crate::interrupt::IrqSource::IoApic { controller, pin }) =
                        crate::interrupt::source(&s.irqs, irq)
                    {
                        let _ = crate::arch::x86_64::ioapic::set_route_mask(
                            controller as usize,
                            pin as u32,
                            false,
                        );
                    }
                }
                Ok(())
            }
            InvocationLabel::IRQClearIRQHandler => {
                #[cfg(target_arch = "x86_64")]
                {
                    if let Ok(crate::interrupt::IrqSource::IoApic { controller, pin }) =
                        crate::interrupt::source(&s.irqs, irq)
                    {
                        let _ = crate::arch::x86_64::ioapic::set_route_mask(
                            controller as usize,
                            pin as u32,
                            true,
                        );
                    }
                }
                crate::interrupt::clear_handler(&mut s.irqs, irq).map_err(|_| {
                    KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))
                })
            }
            _ => Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation,
            ))),
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
fn decode_untyped_retype(target: Cap, args: &SyscallArgs, invoker: TcbId) -> KResult<()> {
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
            crate::untyped::UntypedState::from_cap(&target)
                .map(|s| s.base)
                .unwrap_or(0)
        });
        crate::arch::log(" fi=0x");
        log_hex_u64(unsafe {
            crate::untyped::UntypedState::from_cap(&target)
                .map(|s| s.free_index_bytes)
                .unwrap_or(0)
        });
        crate::arch::log(" bb=");
        log_dec(unsafe {
            crate::untyped::UntypedState::from_cap(&target)
                .map(|s| s.block_bits as u64)
                .unwrap_or(0)
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
            let invoker_tcb = unsafe { KERNEL.get().scheduler.slab.get(invoker) };
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
        KERNEL
            .get()
            .scheduler
            .slab
            .get_mut(invoker)
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
                let res =
                    crate::cspace::resolve_address_bits(s, &root_cap, node_index, node_depth)?;
                if res.bits_remaining != 0 {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_FailedLookup,
                    )));
                }
                let cnode_idx = KernelState::cnode_index(res.slot_ptr);
                s.cnode_slot(cnode_idx, res.slot_index)
                    .map(|c| c.cap())
                    .unwrap_or(Cap::Null)
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
            s,
            &invoker_root,
            args.a0,
            crate::cspace::WORD_BITS,
        )
        .map_err(|_| KException::SyscallError(SyscallError::new(seL4_Error::seL4_FailedLookup)))?;
        if src_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let src_cnode_idx = KernelState::cnode_index(src_res.slot_ptr);
        let src_slot_index = src_res.slot_index;
        let invoked_source = s
            .cnode_slot(src_cnode_idx, src_slot_index)
            .ok_or_else(|| {
                KException::SyscallError(SyscallError::new(seL4_Error::seL4_FailedLookup))
            })?
            .cap();
        if invoked_source != target {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )));
        }
        // Borrow as raw slice so we don't lock the whole `s` —
        // the surrounding code needs separate access to
        // `s.scheduler` etc. BKL serialises kernel state.
        let cnode_slots: &mut [Cte] = {
            let raw = match s.cnode_slots_at_mut(cnode_idx) {
                Some(s) => s as *mut [Cte],
                None => {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_InvalidCapability,
                    )))
                }
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
        let logical_capacity = 1usize.checked_shl(dest_radix as u32).ok_or_else(|| {
            KException::SyscallError(SyscallError::new(seL4_Error::seL4_RangeError))
        })?;
        let required = usize::try_from(num_objects).map_err(|_| {
            KException::SyscallError(SyscallError::new(seL4_Error::seL4_RangeError))
        })?;
        let upper = dest_offset.checked_add(required).ok_or_else(|| {
            KException::SyscallError(SyscallError::new(seL4_Error::seL4_RangeError))
        })?;
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

        // Validate the complete physical layout before consulting implementation pool capacity.
        // This preserves ABI/source/destination error precedence and guarantees that the commit
        // path cannot discover an invalid generated pointer after clearing memory.
        crate::untyped::validate_retype(&state, object_type, size_bits, num_objects)?;

        let available = match object_type {
            ObjectType::Tcb => Some(s.scheduler.available_cap_tcbs()),
            ObjectType::Endpoint => Some(s.available_endpoints()),
            ObjectType::Notification => Some(s.available_notifications()),
            ObjectType::CapTable => Some(s.available_dynamic_cnodes()),
            ObjectType::SchedContext => Some(s.available_sched_contexts()),
            ObjectType::Reply => Some(s.available_replies()),
            ObjectType::Untyped | ObjectType::Arch(_) => None,
        };
        if available.is_some_and(|count| count < required) {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_NotEnoughMemory,
            )));
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
        // Need a mutable handle on `s` to allocate from the
        // endpoint / notification / cnode pools too. We reborrow
        // via `KERNEL.get()` to avoid the existing `&mut s.cnodes`
        // borrow's aliasing constraint.
        let s_ptr: *mut crate::kernel::KernelState = KERNEL.get();
        // Phase 30 — record each carved child's parent CTE in the
        // MDB. We resolved the source untyped's location above
        // (src_cnode_idx, src_slot_index).
        let parent_id = crate::cte::MdbId::pack(src_cnode_idx as u32, src_slot_index as u32);
        let result =
            crate::untyped::retype(&mut state, object_type, size_bits, num_objects, |cap| {
                let cap_to_store = match cap {
                    Cap::Thread { .. } => {
                        let id = (*s_ptr)
                            .scheduler
                            .try_admit_cap(crate::tcb::Tcb {
                                state: crate::tcb::ThreadStateType::Inactive,
                                priority: 0,
                                ..Default::default()
                            })
                            .expect("TCB availability preflight must reserve the full fanout");
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
                            tcb: PPtr::<crate::cap::Tcb>::new(id.0 as u64).expect("nonzero tcb id"),
                        }
                    }
                    Cap::Endpoint { badge, rights, .. } => {
                        let i = (*s_ptr)
                            .alloc_endpoint()
                            .expect("Endpoint availability preflight must reserve the full fanout");
                        Cap::Endpoint {
                            ptr: KernelState::endpoint_ptr(i),
                            badge,
                            rights,
                        }
                    }
                    Cap::Notification { badge, rights, .. } => {
                        let i = (*s_ptr).alloc_notification().expect(
                            "Notification availability preflight must reserve the full fanout",
                        );
                        Cap::Notification {
                            ptr: KernelState::ntfn_ptr(i),
                            badge,
                            rights,
                        }
                    }
                    Cap::CNode {
                        ptr,
                        radix,
                        guard_size,
                        guard,
                    } => {
                        let vi = (*s_ptr)
                            .alloc_dynamic_cnode(ptr.addr(), radix)
                            .expect("CapTable descriptor preflight must reserve exact backing");
                        Cap::CNode {
                            ptr: KernelState::cnode_ptr(vi),
                            radix,
                            guard_size,
                            guard,
                        }
                    }
                    Cap::SchedContext { size_bits, .. } => {
                        let i = (*s_ptr).alloc_sched_context().expect(
                            "SchedContext availability preflight must reserve the full fanout",
                        );
                        Cap::SchedContext {
                            ptr: KernelState::sched_context_ptr(i),
                            size_bits,
                        }
                    }
                    Cap::Reply { can_grant, .. } => {
                        let i = (*s_ptr)
                            .alloc_reply()
                            .expect("Reply availability preflight must reserve the full fanout");
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
                cnode_slots[emit_idx].set_cap(&cap_to_store);
                cnode_slots[emit_idx].set_parent(Some(parent_id));
                child_count_inc(parent_id, 1);
                emit_idx += 1;
            });
        result?;

        // Commit through the exact source CTE resolved and verified before mutation. A second lookup
        // could fail or select a same-base ancestor after destination/pool publication.
        let source_slot = s
            .cnode_slot_mut(src_cnode_idx, src_slot_index)
            .expect("validated source CTE must remain registered under the BKL");
        assert_eq!(
            source_slot.cap(),
            target,
            "invoked Untyped CTE changed during a BKL-serialized Retype"
        );
        source_slot.set_cap(&state.to_cap());
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
        InvocationLabel::CNodeCopy => {
            cnode_copy_or_mint(target, args, invoker, /* mint */ false)
        }
        InvocationLabel::CNodeMint => {
            cnode_copy_or_mint(target, args, invoker, /* mint */ true)
        }
        InvocationLabel::CNodeMove => cnode_move(target, args, invoker, /* mutate */ false),
        InvocationLabel::CNodeMutate => cnode_move(target, args, invoker, /* mutate */ true),
        InvocationLabel::CNodeDelete => cnode_delete(target, args, invoker),
        InvocationLabel::CNodeRevoke => cnode_revoke(target, args, invoker),
        InvocationLabel::CNodeCancelBadgedSends => cnode_cancel_badged_sends(target, args, invoker),
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
                seL4_Error::seL4_TruncatedMessage,
            )));
        };
        s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;

        // Resolve all three slots.
        let dest_res = crate::cspace::resolve_address_bits(s, &dest_root, dest_index, dest_depth)?;
        if dest_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let pivot_res =
            crate::cspace::resolve_address_bits(s, &pivot_root, pivot_index, pivot_depth)?;
        if pivot_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let src_res = crate::cspace::resolve_address_bits(s, &src_root, src_index, src_depth)?;
        if src_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
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
                seL4_Error::seL4_IllegalOperation,
            )));
        }
        // src must be non-empty.
        let src_cap = s
            .cnode_slot(src_cn, src_si)
            .map(|c| c.cap())
            .unwrap_or(Cap::Null);
        if src_cap.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        // dest must be empty unless dest == src (swap with self).
        if !(dest_cn == src_cn && dest_si == src_si) {
            let dest_occupied = s
                .cnode_slot(dest_cn, dest_si)
                .map(|c| !c.cap().is_null())
                .unwrap_or(false);
            if dest_occupied {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_DeleteFirst,
                )));
            }
        }
        let pivot_cap = s
            .cnode_slot(pivot_cn, pivot_si)
            .map(|c| c.cap())
            .unwrap_or(Cap::Null);
        if pivot_cap.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
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
fn cnode_cancel_badged_sends(target: Cap, args: &SyscallArgs, _invoker: TcbId) -> KResult<()> {
    let src_index = args.a2 as usize;
    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability,
            )))
        }
    };
    unsafe {
        let s = KERNEL.get();
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        let slot_count = s.cnode_slots_at(cnode_idx).map(|sl| sl.len()).unwrap_or(0);
        if src_index >= slot_count {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        let cap = s
            .cnode_slot(cnode_idx, src_index)
            .map(|c| c.cap())
            .unwrap_or(Cap::Null);
        let (ep_idx, badge) = match cap {
            Cap::Endpoint { ptr, badge, .. } => {
                let i = KernelState::endpoint_index(ptr);
                (i, badge.0)
            }
            // Upstream's `decodeCNodeInvocation` rejects non-Endpoint
            // (and non-Notification) targets here with IllegalOperation.
            // CNODEOP0006 calls cancelBadgedSends on an empty slot and
            // expects exactly that.
            _ => {
                return Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_IllegalOperation,
                )))
            }
        };
        // Badge of 0 = unbadged, no-op (success).
        if badge == 0 {
            return Ok(());
        }
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
                crate::endpoint::cancel_ipc_anywhere(&mut (*s_ptr).scheduler, t);
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

static mut REVOKE_EPOCH: u32 = 0;

unsafe fn begin_revoke_epoch(s: &mut KernelState) -> u32 {
    let mut epoch = REVOKE_EPOCH.wrapping_add(1);
    if epoch == 0 {
        for ci in 0..KernelState::cnode_pool_count() {
            if let Some(slots) = s.cnode_slots_at_mut(ci) {
                for slot in slots {
                    slot.set_revoke_epoch(0);
                }
            }
        }
        epoch = 1;
    }
    REVOKE_EPOCH = epoch;
    epoch
}

fn cte_revoke_marked(s: &KernelState, ci: usize, si: usize, epoch: u32) -> bool {
    s.cnode_slot(ci, si)
        .is_some_and(|slot| slot.revoke_epoch() == epoch)
}

fn mark_cte_revoke(s: &mut KernelState, ci: usize, si: usize, epoch: u32) {
    if let Some(slot) = s.cnode_slot_mut(ci, si) {
        slot.set_revoke_epoch(epoch);
    }
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
        let cn_slot_count = s.cnode_slots_at(cnode_idx).map(|sl| sl.len()).unwrap_or(0);
        if src_index >= cn_slot_count {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        }
        // Mark this walk in each CTE's transient MDB generation. This is BKL-serialized and avoids
        // a second bitmap proportional to every possible CSpace slot.
        let revoke_epoch = begin_revoke_epoch(s);
        mark_cte_revoke(s, cnode_idx, src_index, revoke_epoch);

        // Iterate to fixed point: any CTE whose parent is revoked
        // gets revoked too. Capacity-bounded — at most
        // `cnode_pool_count() * CNODE_SLOTS` CTEs to mark.
        let mut progress = true;
        while progress {
            progress = false;
            for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
                let slot_count = s.cnode_slots_at(ci).map(|slots| slots.len()).unwrap_or(0);
                for si in 0..slot_count {
                    if cte_revoke_marked(s, ci, si, revoke_epoch) {
                        continue;
                    }
                    let parent = s.cnode_slot(ci, si).and_then(|c| c.parent());
                    if let Some(p) = parent {
                        let pi = p.cnode_idx() as usize;
                        let ps = p.slot() as usize;
                        if cte_revoke_marked(s, pi, ps, revoke_epoch) {
                            mark_cte_revoke(s, ci, si, revoke_epoch);
                            progress = true;
                        }
                    }
                }
            }
        }

        // Validate that every CNode which would become final still has registered backing before
        // changing any CTE. Paging edges are deliberately not preconditions: seL4 finalizes a
        // final paging-structure cap with a best-effort unmap even if its parent disappeared first.
        for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
            let slot_count = s.cnode_slots_at(ci).map(|slots| slots.len()).unwrap_or(0);
            for si in 0..slot_count {
                if !cte_revoke_marked(s, ci, si, revoke_epoch)
                    || (ci == cnode_idx && si == src_index)
                {
                    continue;
                }
                let cap = s
                    .cnode_slot(ci, si)
                    .map(|cte| cte.cap())
                    .unwrap_or(Cap::Null);
                let valid = match cap {
                    Cap::CNode { ptr, .. } => {
                        let vi = KernelState::cnode_index(ptr);
                        let (cleared_refs, cleared_self_refs) =
                            revoke_cnode_clear_counts(s, vi, revoke_epoch, (cnode_idx, src_index));
                        cnode_release_mappings_valid(s, &cap, cleared_refs, cleared_self_refs)
                    }
                    _ => true,
                };
                if !valid {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_IllegalOperation,
                    )));
                }
            }
        }

        // Clear every revoked slot except the source itself.
        // Also reset the child_count for both the cleared slot
        // (no longer holds anything that has children) and decrement
        // the parent's count (we just removed one of its children).
        for ci in 0..crate::kernel::KernelState::cnode_pool_count() {
            let slot_count = s.cnode_slots_at(ci).map(|sl| sl.len()).unwrap_or(0);
            for si in 0..slot_count {
                if !cte_revoke_marked(s, ci, si, revoke_epoch)
                    || (ci == cnode_idx && si == src_index)
                {
                    continue;
                }
                let id = crate::cte::MdbId::pack(ci as u32, si as u32);
                // Phase 43 — free pool slots so long sel4test
                // runs don't exhaust the static pools. Only the
                // FIRST cap (where the object was retyped from
                // an Untyped) does the free; copies via Mint
                // would call free again for the same pool slot
                // which is harmless (free is idempotent).
                let cap_to_free = s
                    .cnode_slot(ci, si)
                    .expect("marked revoke slot must remain registered under the BKL")
                    .cap();
                let parent = splice_cte_out(s, id);
                finalise_cap_mapping(s, &cap_to_free);
                // Phase 44 — clear the slot FIRST (the set_cap hook
                // drops the refcount), then release the object if
                // that was its last reference. Replaces the
                // whole-pool same_obj_lives sweep; the
                // revoked-but-uncleared siblings still hold counts,
                // so the object frees exactly when the LAST holder
                // is cleared — same semantics as the old
                // is_revoked-excluding sweep.
                let slot = s
                    .cnode_slot_mut(ci, si)
                    .expect("marked revoke slot must remain registered until cleared");
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
                slot.set_child_count(0);
                slot.set_revoke_epoch(0);
                maybe_free_object(s, &cap_to_free);
                release_parent_edge(parent);
            }
        }
        // The source itself kept the cap but lost all its descendants.
        assert_eq!(
            s.cnode_slot(cnode_idx, src_index)
                .expect("revoke source must remain registered")
                .child_count(),
            0,
            "revoke must retire or splice every source descendant"
        );

        // Phase 43 — if the source is an Untyped, every derived
        // object has been cleared, so reset the source's free index
        // back to 0 so the next Retype starts from the bottom of the
        // block. Otherwise the second test's allocations exhaust the
        // untyped even though the memory is now free.
        let source = s
            .cnode_slot(cnode_idx, src_index)
            .map(|c| c.cap())
            .unwrap_or(Cap::Null);
        if let Cap::Untyped {
            ptr,
            block_bits,
            is_device,
            ..
        } = source
        {
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

fn cnode_copy_or_mint(target: Cap, args: &SyscallArgs, invoker: TcbId, mint: bool) -> KResult<()> {
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
    let (dest_index, dest_depth, src_index, src_depth, badge, rights_word) = if upstream {
        let inv_tcb = unsafe { KERNEL.get().scheduler.slab.get(invoker) };
        // Upstream wire layout (mirrors libsel4's CNode_Copy /
        // CNode_Mint stubs): mr4 = rights, mr5 = badge (Mint).
        let r = inv_tcb.msg_regs[4];
        let b = inv_tcb.msg_regs[5];
        (args.a2, args.a3 as u32, args.a4, args.a5 as u32, b, r)
    } else {
        // Legacy microtest path passes badge in a4 and gives no
        // rights word. Default to "all rights" so existing
        // microtest behaviour is preserved.
        (
            args.a2,
            crate::cspace::WORD_BITS,
            args.a3,
            crate::cspace::WORD_BITS,
            args.a4,
            !0u64,
        )
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

        let dest_res = crate::cspace::resolve_address_bits(s, &dest_root, dest_index, dest_depth)?;
        if dest_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let dest_cnode_idx = KernelState::cnode_index(dest_res.slot_ptr);

        let src_res = crate::cspace::resolve_address_bits(s, &src_root, src_index, src_depth)?;
        if src_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let src_cnode_idx = KernelState::cnode_index(src_res.slot_ptr);

        let mut copy = s
            .cnode_slot(src_cnode_idx, src_res.slot_index)
            .map(|c| c.cap())
            .unwrap_or(Cap::Null);
        let dest_occupied = s
            .cnode_slot(dest_cnode_idx, dest_res.slot_index)
            .map(|c| !c.cap().is_null())
            .unwrap_or(false);
        if dest_occupied {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        if copy.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        // `Arch_deriveCap` preserves mapped paging-structure state and rejects derivation of an
        // unmapped structure. Every mapped alias therefore names the same hardware edge, and only
        // the final alias may explicitly unmap or detach it during deletion. Frame derivation is
        // different: its mapping metadata is cleared in the derived cap.
        derive_paging_structure(&copy)?;
        match &mut copy {
            Cap::Frame { mapped, asid, .. } => {
                *mapped = None;
                *asid = 0;
            }
            _ => {}
        }
        // Mask rights against `rights_word`. Mirrors upstream
        // `maskCapRights` — applies to BOTH Copy and Mint, regardless
        // of badge. Bit layout matches `seL4_CapRights_t`:
        //   bit 0 = capAllowWrite       (= can_send for EP/NTFN)
        //   bit 1 = capAllowRead        (= can_receive)
        //   bit 2 = capAllowGrant       (= can_grant)
        //   bit 3 = capAllowGrantReply  (= can_grant_reply)
        // sel4test's IPCRIGHTS0001 mints an EP cap with rights = 0
        // and verifies seL4_Send through it is silently dropped.
        const ALLOW_WRITE: u64 = 1 << 0;
        const ALLOW_READ: u64 = 1 << 1;
        const ALLOW_GRANT: u64 = 1 << 2;
        const ALLOW_GRANT_REPLY: u64 = 1 << 3;
        match &mut copy {
            Cap::Endpoint { rights, .. } => {
                rights.can_send &= rights_word & ALLOW_WRITE != 0;
                rights.can_receive &= rights_word & ALLOW_READ != 0;
                rights.can_grant &= rights_word & ALLOW_GRANT != 0;
                rights.can_grant_reply &= rights_word & ALLOW_GRANT_REPLY != 0;
            }
            Cap::Notification { rights, .. } => {
                rights.can_send &= rights_word & ALLOW_WRITE != 0;
                rights.can_receive &= rights_word & ALLOW_READ != 0;
            }
            // TODO: mask Frame/Reply rights when sel4test exercises them.
            _ => {}
        }
        let mut io_mint_invalid = false;
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
                // Phase 44 — minting an io_space cap stamps the PCI
                // request-id + IO domain from the badge (mirrors
                // upstream updateCapData for cap_io_space_cap:
                // io_space_capdata { domainID[31:16], PCIDevice[15:0] }).
                // Only the master (pci_device == 0) may be re-stamped,
                // and the domain must be non-zero, else the result is a
                // null cap. `io_mint_invalid` defers the null assignment
                // until after the `&mut copy` borrow ends.
                Cap::IoSpace {
                    domain_id,
                    pci_device,
                } => {
                    let new_domain = ((badge >> 16) & 0xffff) as u16;
                    let new_pci = (badge & 0xffff) as u16;
                    if *pci_device == 0 && new_domain != 0 {
                        *domain_id = new_domain;
                        *pci_device = new_pci;
                    } else {
                        io_mint_invalid = true;
                    }
                }
                Cap::CNode {
                    ptr,
                    radix,
                    guard_size,
                    guard,
                } => {
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
        if io_mint_invalid {
            copy = Cap::Null;
        }
        if let Some(slot) = s.cnode_slot_mut(dest_cnode_idx, dest_res.slot_index) {
            slot.set_cap(&copy);
            // Phase 30 — the new cap is derived from the source slot;
            // its MDB parent is the source CTE.
            let src_id = crate::cte::MdbId::pack(src_cnode_idx as u32, src_res.slot_index as u32);
            slot.set_parent(Some(src_id));
            slot.set_child_count(0);
            slot.set_revoke_epoch(0);
            child_count_inc(src_id, 1);
        }
    }
    Ok(())
}

fn cnode_move(target: Cap, args: &SyscallArgs, invoker: TcbId, _mutate: bool) -> KResult<()> {
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
        (
            args.a2,
            crate::cspace::WORD_BITS,
            args.a3,
            crate::cspace::WORD_BITS,
        )
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
        let dest_res = crate::cspace::resolve_address_bits(s, &dest_root, dest_index, dest_depth)?;
        if dest_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let dest_cnode_idx = KernelState::cnode_index(dest_res.slot_ptr);

        let src_res = crate::cspace::resolve_address_bits(s, &src_root, src_index, src_depth)?;
        if src_res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
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
        // Snapshot the complete source ownership state before mutating either slot — both might
        // be in the same CNode, in which case the borrow checker
        // would object to two simultaneous &mut on the same array.
        let (src_cap, src_parent, src_child_count) = s
            .cnode_slot(src_cnode_idx, src_res.slot_index)
            .map(|c| (c.cap(), c.parent(), c.child_count()))
            .unwrap_or((Cap::Null, None, 0));
        // Upstream order: dest-not-empty check first (DeleteFirst),
        // then src-empty check (FailedLookup). Matches sel4test's
        // `is_slot_empty` helper in helpers.c.
        let dest_occupied = s
            .cnode_slot(dest_cnode_idx, dest_res.slot_index)
            .map(|c| !c.cap().is_null())
            .unwrap_or(false);
        if dest_occupied {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_DeleteFirst,
            )));
        }
        if src_cap.is_null() {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        if let Some(slot) = s.cnode_slot_mut(dest_cnode_idx, dest_res.slot_index) {
            slot.set_cap(&src_cap);
            slot.set_parent(src_parent);
            slot.set_child_count(src_child_count);
            slot.set_revoke_epoch(0);
        }
        let src_id = crate::cte::MdbId::pack(src_cnode_idx as u32, src_res.slot_index as u32);
        let dest_id = crate::cte::MdbId::pack(dest_cnode_idx as u32, dest_res.slot_index as u32);
        reparent_direct_children(s, src_id, Some(dest_id), src_child_count);
        if let Some(slot) = s.cnode_slot_mut(src_cnode_idx, src_res.slot_index) {
            slot.set_cap(&Cap::Null);
            slot.set_parent(None);
            slot.set_child_count(0);
            slot.set_revoke_epoch(0);
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
    crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, id);
    s.scheduler.scrub_tcb(id);
    for n in s.notifications.iter_mut() {
        if n.bound_tcb == Some(id) {
            n.bound_tcb = None;
        }
    }
    for sc in s.sched_contexts.iter_mut() {
        if sc.bound_tcb == Some(id) {
            sc.bound_tcb = None;
        }
    }
    for r in s.replies.iter_mut() {
        if r.bound_tcb == Some(id) {
            r.bound_tcb = None;
        }
    }
    for opt in s.scheduler.slab.entries.iter_mut() {
        if let Some(t) = opt.as_mut() {
            if t.reply_to == Some(id) {
                t.reply_to = None;
            }
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
    // seL4 `remoteTCBStall`: if this thread is running on a remote core,
    // make that core switch off it before we free the slab entry —
    // otherwise the remote core keeps executing a freed TCB
    // (MULTICORE0005 remote-delete).
    #[cfg(target_arch = "x86_64")]
    crate::smp::remote_tcb_stall(id);
    crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, id);
    // YieldTo bookkeeping (SCHED0018 delete phases):
    //   * a yielder waiting on the dying thread's SC gets its
    //     consumed-report now;
    //   * if the dying thread itself has an outstanding yield,
    //     unhook the SC's back-reference so it doesn't dangle.
    if let Some(sc_idx) = s.scheduler.slab.get(id).sc {
        if let Some(yielder) = s.sched_contexts[sc_idx as usize].yield_from {
            if yielder != id {
                crate::sched_context::complete_yield_to(s, yielder, sc_idx as usize);
            }
        }
    }
    if let Some(y_sc) = s.scheduler.slab.get(id).yield_to {
        if (y_sc as usize) < s.sched_contexts.len() {
            s.sched_contexts[y_sc as usize].yield_from = None;
        }
    }
    s.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
    scrub_tcb_refs(s, id);
    // seL4 `fpuRelease`: drop any core's ownership of this thread's FPU
    // state before its save area vanishes, so a later `fpu_switch_to`
    // can't `fxsave` into a freed TCB.
    #[cfg(all(feature = "smp", target_arch = "x86_64"))]
    crate::arch::x86_64::fpu_ctx::fpu_release(id);
    s.scheduler.slab.entries[id.0 as usize] = None;
}

unsafe fn cnode_has_only_self_refs(s: &crate::kernel::KernelState, cap: &Cap) -> bool {
    let Cap::CNode { ptr, .. } = cap else {
        return false;
    };
    let vi = KernelState::cnode_index(*ptr);
    let Some(slots) = s.cnode_slots_at(vi) else {
        return false;
    };
    let self_refs = slots
        .iter()
        .filter(|slot| {
            matches!(slot.cap(), Cap::CNode { ptr: inner, .. } if inner.addr() == ptr.addr())
        })
        .count();
    crate::kernel::cap_refcount(cap) as usize == self_refs
}

#[cfg(feature = "spec")]
static REPARENT_SCAN_SLOTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Rewrite the exact direct MDB edges owned by a CTE whose identity is changing or disappearing.
/// The per-CTE child count makes the overwhelmingly common leaf case O(1); only a CTE that really
/// owns descendants needs the registry walk required by the compact parent-only MDB representation.
unsafe fn reparent_direct_children(
    s: &mut crate::kernel::KernelState,
    old_parent: crate::cte::MdbId,
    new_parent: Option<crate::cte::MdbId>,
    expected_children: u32,
) {
    if expected_children == 0 {
        return;
    }

    let mut moved = 0u32;
    for ci in 0..KernelState::cnode_pool_count() {
        let slot_count = s.cnode_slots_at(ci).map_or(0, |slots| slots.len());
        for si in 0..slot_count {
            #[cfg(feature = "spec")]
            REPARENT_SCAN_SLOTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if s.cnode_slot(ci, si).and_then(|slot| slot.parent()) != Some(old_parent) {
                continue;
            }
            s.cnode_slot_mut(ci, si)
                .expect("scanned CNode slot must remain registered under the BKL")
                .set_parent(new_parent);
            moved = moved.checked_add(1).expect("MDB child count overflow");
        }
    }
    assert_eq!(
        moved, expected_children,
        "MDB child count must equal the registered direct derivation edges"
    );
}

/// Splice the direct derivation children of a disappearing CTE to its own parent. seL4's linked MDB
/// performs this in `emptySlot`; our compact explicit-parent model must do it before a CNode backing
/// descriptor can be reused, otherwise those children would point into the next object assigned the
/// same descriptor identity.
unsafe fn splice_cte_out(
    s: &mut crate::kernel::KernelState,
    removed: crate::cte::MdbId,
) -> Option<crate::cte::MdbId> {
    let removed_cte = s
        .cnode_slot(removed.cnode_idx() as usize, removed.slot() as usize)
        .expect("removed CTE must remain registered while its MDB edge is spliced");
    let new_parent = removed_cte.parent();
    let recorded_children = removed_cte.child_count();
    reparent_direct_children(s, removed, new_parent, recorded_children);
    if let Some(parent) = new_parent {
        let parent = s
            .cnode_slot_mut(parent.cnode_idx() as usize, parent.slot() as usize)
            .expect("derived cap parent must remain live while its child is deleted");
        let adopted = parent
            .child_count()
            .checked_add(recorded_children)
            .expect("MDB child count overflow while splicing a CTE");
        parent.set_child_count(adopted);
    }
    s.cnode_slot_mut(removed.cnode_idx() as usize, removed.slot() as usize)
        .expect("finalized CNode slot must remain registered until it is cleared")
        .set_child_count(0);
    new_parent
}

unsafe fn assert_cnode_release_invariants(s: &crate::kernel::KernelState, vi: usize) {
    let slots = s
        .cnode_slots_at(vi)
        .expect("released CNode must remain registered during validation");
    for slot in slots {
        assert!(
            slot.cap().is_null(),
            "released CNode must contain only null caps"
        );
        assert_eq!(
            slot.parent(),
            None,
            "released CNode slot retains an MDB parent"
        );
        assert_eq!(
            slot.child_count(),
            0,
            "released CNode slot retains MDB children"
        );
        assert_eq!(
            slot.revoke_epoch(),
            0,
            "released CNode slot retains a revoke mark"
        );
    }
    let released = Cap::CNode {
        ptr: KernelState::cnode_ptr(vi),
        radix: slots.len().trailing_zeros() as u8,
        guard_size: 0,
        guard: 0,
    };
    assert_eq!(
        crate::kernel::cap_refcount(&released),
        0,
        "released CNode descriptor retains a live capability reference"
    );
    for ci in 0..KernelState::cnode_pool_count() {
        let slot_count = s.cnode_slots_at(ci).map_or(0, |inner| inner.len());
        for si in 0..slot_count {
            let parent = s.cnode_slot(ci, si).and_then(|slot| slot.parent());
            assert_ne!(
                parent.map(|id| id.cnode_idx() as usize),
                Some(vi),
                "released CNode descriptor retains an inbound MDB edge"
            );
        }
    }
}

/// Release the tracked object or IRQ vector behind `cap` if the last reference is gone. The caller
/// clears its CTE before entering here, so refcounts already exclude that ownership edge. CNode
/// contents are finalized with a registry-sized iterative worklist: arbitrary valid nesting is
/// drained completely without recursive kernel-stack growth or a depth-truncation fallback.
unsafe fn maybe_free_object(s: &mut crate::kernel::KernelState, cap: &Cap) {
    use crate::kernel::cap_refcount;
    match cap {
        Cap::Thread { tcb } => {
            if cap_refcount(cap) == 0 {
                destroy_tcb(s, crate::tcb::TcbId(tcb.addr() as u16));
            }
        }
        Cap::Endpoint { ptr, .. } => {
            if cap_refcount(cap) == 0 {
                s.free_endpoint(KernelState::endpoint_index(*ptr));
            }
        }
        Cap::Notification { ptr, .. } => {
            if cap_refcount(cap) == 0 {
                s.free_notification(KernelState::ntfn_index(*ptr));
            }
        }
        Cap::SchedContext { ptr, .. } => {
            if cap_refcount(cap) == 0 {
                s.free_sched_context(KernelState::sched_context_index(*ptr));
            }
        }
        Cap::Reply { ptr, .. } => {
            if cap_refcount(cap) == 0 {
                let idx = KernelState::reply_index(*ptr);
                // If a caller is still parked on this reply, deleting
                // the Reply cap cancels the in-flight call. Clear the
                // receiver's reply/temporary-charge state just like a
                // real reply transfer would; otherwise a non-passive
                // server keeps `active_sc` pointing at a caller SC that
                // may be deleted immediately afterwards.
                if let Some(caller) = s.replies[idx].bound_tcb {
                    clear_receiver_call_state_for_reply_caller(s, caller);
                    if let Some(caller_tcb) = s.scheduler.slab.try_get(caller) {
                        // Passive-server call donation still has to be
                        // returned to the caller before the reply object
                        // disappears. Guard on BlockedOnReply so we do
                        // not disturb SC loans unrelated to the canceled
                        // call (INTERRUPT0005).
                        if matches!(
                            caller_tcb.state,
                            crate::tcb::ThreadStateType::BlockedOnReply
                        ) {
                            crate::sched_context::return_donated_sc(s, caller);
                        }
                    }
                }
                s.free_reply(idx);
            }
        }
        Cap::IrqHandler { irq } => {
            if cap_refcount(cap) == 0 {
                let source = crate::interrupt::source(&s.irqs, *irq).unwrap_or_default();
                #[cfg(target_arch = "x86_64")]
                if let crate::interrupt::IrqSource::IoApic { controller, pin } = source {
                    let _ = crate::arch::x86_64::ioapic::set_route_mask(
                        controller as usize,
                        pin as u32,
                        true,
                    );
                }
                let _ = crate::interrupt::release_handler(&mut s.irqs, *irq);
            }
        }
        Cap::IoPageTable {
            ptr,
            is_mapped,
            level,
            mapped_address,
            ioasid,
        } => {
            // Phase 44 — deleting a mapped IO page table (e.g. at test
            // teardown when the child's Untyped is revoked) tears down
            // its VT-d entry (deleteIOPageTable). Without this, the
            // context root / intermediate PTE leaks into the next test
            // that reuses the same PCI request-id, corrupting its tree.
            #[cfg(target_arch = "x86_64")]
            if *is_mapped {
                unsafe {
                    delete_io_page_table(ptr.addr(), *is_mapped, *level, *mapped_address, *ioasid);
                }
            }
            let _ = (s, ptr, is_mapped, level, mapped_address, ioasid);
        }
        Cap::AsidPool { asid_base, .. } => {
            // VSPACE0003/0004 — ASID pools are a fixed resource
            // (MAX_ASID_POOLS). Recycle the pool's index when its cap
            // is deleted so it doesn't leak across sel4test runs that
            // create pools and clean them up. AsidPool caps aren't
            // copied by these tests, so freeing on delete is safe; the
            // init pool (index 0, asid_base 0) is guarded inside
            // `free_asid_pool_index`.
            let _ = s;
            free_asid_pool_index((*asid_base / 512) as usize);
        }
        Cap::CNode { ptr, .. } => {
            if !cnode_has_only_self_refs(s, cap) {
                return;
            }
            let work = cnode_worklist();
            assert!(
                work.push(KernelState::cnode_index(*ptr)),
                "tracked CNode identity must fit finalization worklist"
            );

            while let Some(vi) = work.pop() {
                let slots = s
                    .cnode_slots_at(vi)
                    .expect("queued CNode must remain registered under the BKL");
                let n = slots.len();
                let current_ptr = KernelState::cnode_ptr(vi);
                let current_cap = Cap::CNode {
                    ptr: current_ptr,
                    radix: n.trailing_zeros() as u8,
                    guard_size: 0,
                    guard: 0,
                };
                assert!(
                    cnode_has_only_self_refs(s, &current_cap),
                    "queued CNode cannot gain an external reference under the BKL"
                );

                for si in 0..n {
                    let cte = s
                        .cnode_slot(vi, si)
                        .expect("queued CNode slot must remain registered under the BKL");
                    let (inner_cap, inner_parent, inner_children) =
                        (cte.cap(), cte.parent(), cte.child_count());
                    if inner_cap.is_null() {
                        assert_eq!(
                            inner_children, 0,
                            "empty CNode slot cannot own derivation children"
                        );
                        assert_eq!(
                            inner_parent, None,
                            "empty CNode slot cannot retain an MDB parent"
                        );
                        continue;
                    }
                    let spliced_parent =
                        splice_cte_out(s, crate::cte::MdbId::pack(vi as u32, si as u32));
                    assert_eq!(spliced_parent, inner_parent);
                    finalise_cap_mapping(s, &inner_cap);
                    let slot = s
                        .cnode_slot_mut(vi, si)
                        .expect("queued CNode slot must remain registered until cleared");
                    slot.set_cap(&Cap::Null);
                    slot.set_parent(None);
                    slot.set_child_count(0);
                    slot.set_revoke_epoch(0);

                    match inner_cap {
                        Cap::CNode { ptr: inner_ptr, .. }
                            if inner_ptr.addr() == current_ptr.addr() => {}
                        Cap::CNode { ptr: inner_ptr, .. } => {
                            if cnode_has_only_self_refs(s, &inner_cap) {
                                assert!(
                                    work.push(KernelState::cnode_index(inner_ptr)),
                                    "tracked CNode identity must fit finalization worklist"
                                );
                            }
                        }
                        _ => maybe_free_object(s, &inner_cap),
                    }
                    release_parent_edge(inner_parent);
                }
                assert_cnode_release_invariants(s, vi);
                s.free_cnode_virt(vi);
            }
        }
        _ => {}
    }
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
        let res = crate::cspace::resolve_address_bits(s, &target, args.a2, depth)?;
        if res.bits_remaining != 0 {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup,
            )));
        }
        let cnode_idx = KernelState::cnode_index(res.slot_ptr);
        if INV_TRACE {
            crate::arch::log("[del -> cnode=");
            log_dec(cnode_idx as u64);
            crate::arch::log(" slot=");
            log_dec(res.slot_index as u64);
            crate::arch::log("]\n");
        }

        // Keep the cap live while its mappings and MDB edge are validated and spliced.
        let removed_id = crate::cte::MdbId::pack(cnode_idx as u32, res.slot_index as u32);
        let deleted_cap = s
            .cnode_slot(cnode_idx, res.slot_index)
            .expect("resolved delete slot must remain registered under the BKL")
            .cap();

        let valid = match deleted_cap {
            Cap::CNode { ptr, .. } => {
                let vi = KernelState::cnode_index(ptr);
                cnode_release_mappings_valid(s, &deleted_cap, 1, u32::from(cnode_idx == vi))
            }
            _ => true,
        };
        if !valid {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation,
            )));
        }

        let parent_id = splice_cte_out(s, removed_id);
        finalise_cap_mapping(s, &deleted_cap);

        let slot = s
            .cnode_slot_mut(cnode_idx, res.slot_index)
            .expect("resolved delete slot must remain registered until cleared");
        slot.set_cap(&Cap::Null);
        slot.set_parent(None);
        slot.set_child_count(0);
        slot.set_revoke_epoch(0);

        // The slot is already clear, so the exact object refcount excludes this ownership edge.
        // Release the object only when no other capability refers to it.
        maybe_free_object(s, &deleted_cap);

        // Retire exactly this derivation edge. An Untyped becomes reusable when its last direct
        // child disappears; ancestors remain allocated while their child Untyped still exists.
        release_parent_edge(parent_id);
    }
    Ok(())
}

/// Per-parent live-child accounting lives in the parent CTE's MDB storage. This follows a CNode
/// Move with the CTE and scales with memory-backed CNodes without a second kernel-image array.
pub unsafe fn child_count_inc(pid: crate::cte::MdbId, by: u32) {
    let s = KERNEL.get();
    let parent = s
        .cnode_slot_mut(pid.cnode_idx() as usize, pid.slot() as usize)
        .expect("MDB parent must resolve while adding a derivation edge");
    let count = parent
        .child_count()
        .checked_add(by)
        .expect("MDB child count overflow");
    parent.set_child_count(count);
}

/// Clear ownership metadata before a CNode descriptor or static page is reused.
pub unsafe fn child_counts_reset_page(vi: usize) {
    if let Some(slots) = KERNEL.get().cnode_slots_at_mut(vi) {
        for slot in slots {
            slot.set_child_count(0);
            slot.set_revoke_epoch(0);
        }
    }
}

/// Remove exactly one live MDB ownership edge. An empty Untyped becomes reusable, but its own
/// parent remains occupied until this CTE is itself deleted; emptiness never propagates authority
/// upward through a still-live child cap.
unsafe fn release_parent_edge(parent_id: Option<crate::cte::MdbId>) {
    let Some(parent_id) = parent_id else {
        return;
    };
    let s = KERNEL.get();
    let parent = s
        .cnode_slot_mut(parent_id.cnode_idx() as usize, parent_id.slot() as usize)
        .expect("MDB parent must resolve while removing a derivation edge");
    let remaining = parent
        .child_count()
        .checked_sub(1)
        .expect("MDB parent child count underflow");
    parent.set_child_count(remaining);
    if remaining == 0 {
        if let Cap::Untyped {
            ptr,
            block_bits,
            is_device,
            ..
        } = parent.cap()
        {
            parent.set_cap(&Cap::Untyped {
                ptr,
                block_bits,
                free_index: 0,
                is_device,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// TCB invocations.
// ---------------------------------------------------------------------------

const TCB_DEBUG_STATE_WORDS: usize = 29;
const TCB_DEBUG_NONE: Word = Word::MAX;

#[inline]
fn debug_opt_tcb(v: Option<TcbId>) -> Word {
    v.map(|id| id.0 as Word).unwrap_or(TCB_DEBUG_NONE)
}

#[inline]
fn debug_opt_u16(v: Option<u16>) -> Word {
    v.map(|id| id as Word).unwrap_or(TCB_DEBUG_NONE)
}

#[inline]
fn debug_cap_kind(c: &Cap) -> Word {
    match c {
        Cap::Null => 0,
        Cap::Endpoint { .. } => 1,
        Cap::Notification { .. } => 2,
        Cap::Reply { .. } => 3,
        Cap::CNode { .. } => 4,
        Cap::Thread { .. } => 5,
        _ => 255,
    }
}

#[inline]
fn debug_endpoint_state(ep: &crate::endpoint::Endpoint) -> Word {
    match ep.state {
        crate::endpoint::EpState::Idle => 0,
        crate::endpoint::EpState::Send => 1,
        crate::endpoint::EpState::Recv => 2,
    }
}

fn debug_tcb_fault_slot(s: &KernelState, cspace_idx: Word) -> [Word; 6] {
    if cspace_idx == TCB_DEBUG_NONE {
        return [
            TCB_DEBUG_NONE,
            0,
            TCB_DEBUG_NONE,
            TCB_DEBUG_NONE,
            TCB_DEBUG_NONE,
            TCB_DEBUG_NONE,
        ];
    }
    let cap = s
        .cnode_slot(cspace_idx as usize, 6)
        .map(|slot| slot.cap())
        .unwrap_or(Cap::Null);
    let kind = debug_cap_kind(&cap);
    let mut detail = TCB_DEBUG_NONE;
    let mut ep_state = TCB_DEBUG_NONE;
    let mut ep_head = TCB_DEBUG_NONE;
    let mut ep_tail = TCB_DEBUG_NONE;
    if let Cap::Endpoint { ptr, badge, rights } = cap {
        let ep_idx = KernelState::endpoint_index(ptr);
        detail = (ep_idx as Word) << 32
            | ((badge.0 & 0xFFFF) << 8)
            | (rights.can_send as Word)
            | ((rights.can_receive as Word) << 1)
            | ((rights.can_grant as Word) << 2)
            | ((rights.can_grant_reply as Word) << 3);
        if let Some(ep) = s.endpoints.get(ep_idx) {
            ep_state = debug_endpoint_state(ep);
            ep_head = debug_opt_tcb(ep.head);
            ep_tail = debug_opt_tcb(ep.tail);
        }
    }
    [cspace_idx, kind, detail, ep_state, ep_head, ep_tail]
}

#[cfg(target_arch = "x86_64")]
fn write_invocation_words(invoker_tcb: &mut crate::tcb::Tcb, ipc_paddr: Word, words: &[Word]) {
    let in_regs = words.len().min(invoker_tcb.msg_regs.len());
    for (i, word) in words.iter().copied().enumerate().take(in_regs) {
        invoker_tcb.msg_regs[i] = word;
    }
    invoker_tcb.ipc_length = words.len() as u32;
    if words.len() > invoker_tcb.msg_regs.len() && ipc_paddr != 0 {
        let buf = (crate::arch::x86_64::paging::phys_to_lin(ipc_paddr) as *mut u64).wrapping_add(1);
        for (i, word) in words
            .iter()
            .copied()
            .enumerate()
            .skip(invoker_tcb.msg_regs.len())
        {
            unsafe {
                core::ptr::write_volatile(buf.add(i), word);
            }
        }
    }
    if !words.is_empty() {
        invoker_tcb.user_context.r10 = words[0];
    }
    if words.len() > 1 {
        invoker_tcb.user_context.r8 = words[1];
    }
    if words.len() > 2 {
        invoker_tcb.user_context.r9 = words[2];
    }
    if words.len() > 3 {
        invoker_tcb.user_context.r15 = words[3];
    }
    invoker_tcb.user_context.rsi = (words.len() as u64) & 0x7F;
}

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
                // Upstream `suspend()` = cancelIPC + Inactive. A
                // server blocked in an endpoint recv queue must be
                // REMOVED from that queue — otherwise the next
                // sender pops the suspended thread and the message
                // vanishes into it (SCHED0009 suspends servers in
                // reverse priority order and expects each Call to
                // reach the next-highest remaining server).
                // seL4 `remoteTCBStall`: if the thread is running on a
                // remote core, stall that core off it before suspending
                // so the counter freezes immediately (MULTICORE0001).
                #[cfg(target_arch = "x86_64")]
                crate::smp::remote_tcb_stall(id);
                crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, id);
                // Upstream suspend() also completes an outstanding
                // YieldTo against this thread's SC — the yielder
                // gets its consumed-report the moment the yielded-to
                // thread stops running (SCHED0018 phase 1).
                if let Some(sc_idx) = s.scheduler.slab.get(id).sc {
                    if let Some(yielder) = s.sched_contexts[sc_idx as usize].yield_from {
                        crate::sched_context::complete_yield_to(s, yielder, sc_idx as usize);
                    }
                }
                s.scheduler.block(id, crate::tcb::ThreadStateType::Inactive);
                Ok(())
            }
            InvocationLabel::TCBResume => {
                // SCHED0010 — Resume succeeds even on a thread with
                // no SchedContext, but such a thread cannot run.
                // Mark Running so a future SchedContextBind picks it
                // up; only enqueue when an SC is actually present.
                if s.scheduler.slab.get(id).sc.is_some() {
                    s.scheduler.make_runnable(id);
                } else {
                    s.scheduler.slab.get_mut(id).state = crate::tcb::ThreadStateType::Running;
                }
                Ok(())
            }
            // rust-micro extension — put the target thread into
            // hosted-syscall mode. Raw Windows `syscall` instructions
            // fault to the handler as UnknownSyscall instead of
            // dispatching natively; syscall_entry.rs still lets the
            // explicit userspace-ntos native ntdll Call envelope through.
            // Takes no message args; mirrors TCBResume's minimal
            // plumbing. The flag is write-once (never cleared).
            InvocationLabel::TCBSetHostedSyscalls => {
                s.scheduler.slab.get_mut(id).hosted_syscalls = true;
                Ok(())
            }
            InvocationLabel::TCBReadDebugState => {
                let reply_bound = if args.a2 != 0 {
                    let inv_cspace = s.scheduler.slab.get(invoker).cspace_root;
                    match lookup_cap(s, &inv_cspace, args.a2)? {
                        Cap::Reply { ptr, .. } => {
                            let reply_idx = KernelState::reply_index(ptr);
                            s.replies
                                .get(reply_idx)
                                .and_then(|reply| reply.bound_tcb)
                                .map(|t| t.0 as Word)
                                .unwrap_or(TCB_DEBUG_NONE)
                        }
                        _ => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
                    }
                } else {
                    TCB_DEBUG_NONE
                };
                let t = s.scheduler.slab.get(id);
                let cspace_idx = match t.cspace_root {
                    Cap::CNode { ptr, .. } => KernelState::cnode_index(ptr) as Word,
                    _ => TCB_DEBUG_NONE,
                };
                let fault_slot = debug_tcb_fault_slot(s, cspace_idx);
                let queue_top_priority = s.scheduler.nodes[t.affinity as usize].queues
                    [t.domain as usize]
                    .peek_highest()
                    .map(|prio| prio as Word)
                    .unwrap_or(TCB_DEBUG_NONE);
                let direct_handoff =
                    debug_opt_tcb(s.scheduler.nodes[t.affinity as usize].direct_handoff);
                let words: [Word; TCB_DEBUG_STATE_WORDS] = [
                    t.state as Word,
                    t.is_schedulable() as Word,
                    t.enqueued as Word,
                    t.priority as Word,
                    debug_opt_u16(t.sc),
                    debug_opt_u16(t.active_sc),
                    debug_opt_u16(t.pending_reply),
                    debug_opt_tcb(t.reply_to),
                    debug_opt_u16(t.bound_notification),
                    t.blocked_is_call as Word,
                    t.blocked_can_grant as Word,
                    debug_opt_u16(t.donated_sc),
                    t.pending_fault as Word,
                    t.hosted_syscalls as Word,
                    reply_bound,
                    debug_opt_tcb(s.scheduler.current()),
                    id.0 as Word,
                    fault_slot[0],
                    fault_slot[1],
                    fault_slot[2],
                    fault_slot[3],
                    fault_slot[4],
                    fault_slot[5],
                    debug_opt_tcb(t.composite_reply_handoff),
                    t.affinity as Word,
                    t.domain as Word,
                    s.scheduler.cur_domain as Word,
                    queue_top_priority,
                    direct_handoff,
                ];
                #[cfg(target_arch = "x86_64")]
                {
                    let ipc_paddr = s.scheduler.slab.get(invoker).ipc_buffer_paddr;
                    let inv = s.scheduler.slab.get_mut(invoker);
                    write_invocation_words(inv, ipc_paddr, &words);
                }
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
                let (cnode_cap, vspace_cap, ipcbuf_cap, ipc_buffer_vaddr) = if upstream {
                    let staged = s.scheduler.slab.get(invoker).pending_extra_caps;
                    let count = s.scheduler.slab.get(invoker).pending_extra_caps_count as usize;
                    let cnode = if count > 0 { Some(staged[0]) } else { None };
                    let vspace = if count > 1 { Some(staged[1]) } else { None };
                    let ipcbuf = if count > 2 { Some(staged[2]) } else { None };
                    (cnode, vspace, ipcbuf, args.a5)
                } else {
                    let cnode = if args.a3 != 0 {
                        Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a3)?)
                    } else {
                        None
                    };
                    let vspace = if args.a4 != 0 {
                        Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a4)?)
                    } else {
                        None
                    };
                    (cnode, vspace, None, 0)
                };
                let t = s.scheduler.slab.get_mut(id);
                t.fault_handler = args.a2;
                if let Some(c) = cnode_cap {
                    if !matches!(c, Cap::CNode { .. } | Cap::Null) {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )));
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
                        _ => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
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
                // SCHED0005 — when the upstream form is used
                // (extraCaps[0] = authority TCB), reject prio that
                // exceeds authority's MCP with seL4_RangeError.
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                if info.extra_caps() > 0 {
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    let count = inv_tcb.pending_extra_caps_count as usize;
                    let auth_cap = if count > 0 {
                        Some(inv_tcb.pending_extra_caps[0])
                    } else {
                        None
                    };
                    inv_tcb.pending_extra_caps_count = 0;
                    let auth_mcp = match auth_cap {
                        Some(Cap::Thread { tcb }) => {
                            let auth_id = crate::tcb::TcbId(tcb.addr() as u16);
                            s.scheduler.slab.get(auth_id).mcp
                        }
                        _ => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
                    };
                    if prio > auth_mcp {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_RangeError,
                        )));
                    }
                }
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
                let dom = s.scheduler.slab.get(id).domain as usize;
                let was_runnable = s.scheduler.slab.get(id).is_runnable();
                if was_runnable {
                    s.scheduler.nodes[cpu].queues[dom].dequeue(&mut s.scheduler.slab, id);
                }
                s.scheduler.slab.get_mut(id).priority = prio;
                if was_runnable {
                    s.scheduler.nodes[cpu].queues[dom].enqueue(&mut s.scheduler.slab, id);
                    // If we just demoted the current thread on this
                    // CPU and a higher-priority thread is waiting,
                    // force a reschedule.
                    if s.scheduler.nodes[cpu].current == Some(id) {
                        if let Some(top) = s.scheduler.nodes[cpu].queues[dom].peek_highest() {
                            if top > prio {
                                s.scheduler.nodes[cpu].current = None;
                            }
                        }
                    }
                    // SCHED0020 — if we raised ANOTHER thread above
                    // the current thread's priority on this CPU,
                    // force a reschedule. Mirrors upstream
                    // `possibleSwitchTo`.
                    if let Some(cur) = s.scheduler.nodes[cpu].current {
                        if cur != id {
                            let cur_prio = s.scheduler.slab.get(cur).priority;
                            if prio > cur_prio {
                                s.scheduler.nodes[cpu].current = None;
                            }
                        }
                    }
                } else {
                    // SCHED0008 — if the thread is blocked in an
                    // endpoint or notification wait queue, that
                    // queue is priority-ordered. Reposition so the
                    // new priority is honoured on the next pop.
                    use crate::tcb::ThreadStateType::*;
                    let state = s.scheduler.slab.get(id).state;
                    if matches!(
                        state,
                        BlockedOnSend | BlockedOnReceive | BlockedOnNotification
                    ) {
                        crate::endpoint::reposition_in_wait_queue(&mut s.scheduler, id);
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
                        if count > 0 {
                            regs[0] = args.a4;
                        } // rip
                        if count > 1 {
                            regs[1] = args.a5;
                        } // rsp
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
                                let buf =
                                    (crate::arch::x86_64::paging::phys_to_lin(inv.ipc_buffer_paddr)
                                        as *const u64)
                                        .wrapping_add(1);
                                regs[i] = core::ptr::read_volatile(buf.add(msg_idx));
                            }
                        }
                        let t = s.scheduler.slab.get_mut(id);
                        let n = count;
                        // Upstream `seL4_UserContext` slot order:
                        //   0=rip, 1=rsp, 2=rflags, 3=rax, 4=rbx,
                        //   5=rcx, 6=rdx, 7=rsi, 8=rdi, 9=rbp,
                        //   10=r8, 11=r9, 12=r10, 13=r11, 14=r12,
                        //   15=r13, 16=r14, 17=r15, 18=fs_base,
                        //   19=gs_base.
                        //
                        // Two independent contexts:
                        //   * `user_context.rcx` / `.r11` —
                        //     the sysretq path's RIP / RFLAGS slots
                        //     (sysretq destroys those registers).
                        //   * `user_context.rip` / `.rflags` —
                        //     the iretq resume path's RIP / RFLAGS.
                        // sysretq is the default; iretq fires only
                        // when the user wrote an RCX or R11 value
                        // that the sysretq path would lose. For all
                        // OTHER cases, leave rcx/r11 = rip/rflags so
                        // sysretq's tail sees a valid resume RIP.
                        let new_rip = if n > 0 { regs[0] } else { 0 };
                        // Sanitize RFLAGS the way upstream's
                        // Arch_sanitiseRegister does: keep only the
                        // user-legal arithmetic/direction bits
                        // (CF PF AF ZF SF TF DF OF = 0xDD5), force
                        // bit 1 (always-one) and IF (bit 9).
                        // sel4utils passes rflags=0 when starting
                        // threads — storing that verbatim produced
                        // user threads running with IF=0, which
                        // starves the kernel of timer + device IRQs
                        // whenever such a thread spins (SCHED0000's
                        // hang; ticks died after the first
                        // WriteRegisters-started thread ran).
                        let new_rflags = if n > 2 {
                            (regs[2] & 0xDD5) | 0x202
                        } else {
                            0x202
                        };
                        if n > 0 {
                            t.user_context.rip = new_rip;
                        }
                        if n > 1 {
                            t.user_context.rsp = regs[1];
                        }
                        if n > 2 {
                            t.user_context.rflags = new_rflags;
                        }
                        if n > 3 {
                            t.user_context.rax = regs[3];
                        }
                        if n > 4 {
                            t.user_context.rbx = regs[4];
                        }
                        if n > 6 {
                            t.user_context.rdx = regs[6];
                        }
                        if n > 7 {
                            t.user_context.rsi = regs[7];
                        }
                        if n > 8 {
                            t.user_context.rdi = regs[8];
                        }
                        if n > 9 {
                            t.user_context.rbp = regs[9];
                        }
                        if n > 10 {
                            t.user_context.r8 = regs[10];
                        }
                        if n > 11 {
                            t.user_context.r9 = regs[11];
                        }
                        if n > 12 {
                            t.user_context.r10 = regs[12];
                        }
                        if n > 14 {
                            t.user_context.r12 = regs[14];
                        }
                        if n > 15 {
                            t.user_context.r13 = regs[15];
                        }
                        if n > 16 {
                            t.user_context.r14 = regs[16];
                        }
                        if n > 17 {
                            t.user_context.r15 = regs[17];
                        }
                        // Decide on resume path BEFORE writing rcx
                        // and r11, since the choice affects what we
                        // store there.
                        let user_rcx = if n > 5 { regs[5] } else { 0 };
                        let user_r11 = if n > 13 { regs[13] } else { 0 };
                        // If user-set RCX / R11 are independently
                        // meaningful, we MUST use iretq — store the
                        // user values in rcx/r11 and set the flag.
                        let need_iretq =
                            (n > 5 && user_rcx != new_rip) || (n > 13 && user_r11 != new_rflags);
                        if need_iretq {
                            t.user_context.rcx = user_rcx;
                            t.user_context.r11 = user_r11;
                            t.use_iretq_resume = true;
                        } else {
                            // sysretq path: rcx serves as RIP, r11
                            // as RFLAGS. Store rip/rflags there so
                            // the sysretq tail jumps to the right
                            // place. Mark the context sysret-flavor so
                            // resume_ip/reported_ip read rcx as the RIP.
                            t.user_context.rcx = new_rip;
                            t.user_context.r11 = new_rflags;
                            t.use_iretq_resume = false;
                        }
                        // fs_base / gs_base (slots 18, 19) ignored.
                        if resume {
                            // Upstream `restart()` cancels any
                            // in-flight fault — the thread is being
                            // forcibly re-pointed, so a later reply
                            // to its old fault must not rewrite the
                            // registers we just set.
                            s.scheduler.slab.get_mut(id).pending_fault = 0;
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
                            crate::fault::reported_ip(t),
                            t.user_context.rsp,
                            t.user_context.rax,
                        );
                        let inv = s.scheduler.slab.get_mut(invoker);
                        inv.msg_regs[0] = rip;
                        inv.msg_regs[1] = rsp;
                        inv.msg_regs[2] = rax;
                        inv.ipc_length = 3;
                    } else {
                        // Exception-captured threads (#PF/#UD —
                        // `use_iretq_resume`) carry RIP/RFLAGS in
                        // the dedicated iretq slots and TRUE rcx/
                        // r11 in the GPR slots; sysret-flavor
                        // threads use rcx/r11 as RIP/RFLAGS stand-
                        // ins (real rcx/r11 destroyed by SYSCALL —
                        // report 0 like before).
                        let iq = t.use_iretq_resume;
                        let regs: [u64; 20] = [
                            crate::fault::reported_ip(t),            // 0 rip
                            t.user_context.rsp,                      // 1 rsp
                            crate::fault::resume_flags(t),           // 2 rflags
                            t.user_context.rax,                      // 3  rax
                            t.user_context.rbx,                      // 4  rbx
                            if iq { t.user_context.rcx } else { 0 }, // 5 rcx
                            t.user_context.rdx,                      // 6  rdx
                            t.user_context.rsi,                      // 7  rsi
                            t.user_context.rdi,                      // 8  rdi
                            t.user_context.rbp,                      // 9  rbp
                            t.user_context.r8,                       // 10 r8
                            t.user_context.r9,                       // 11 r9
                            t.user_context.r10,                      // 12 r10
                            if iq { t.user_context.r11 } else { 0 }, // 13 r11
                            t.user_context.r12,                      // 14 r12
                            t.user_context.r13,                      // 15 r13
                            t.user_context.r14,                      // 16 r14
                            t.user_context.r15,                      // 17 r15
                            0,                                       // 18 fs_base (not modelled)
                            0,                                       // 19 gs_base (not modelled)
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
                            let buf = (crate::arch::x86_64::paging::phys_to_lin(ipc_paddr)
                                as *mut u64)
                                .wrapping_add(1);
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
                        if count > 0 {
                            inv.user_context.r10 = regs[0];
                        }
                        if count > 1 {
                            inv.user_context.r8 = regs[1];
                        }
                        if count > 2 {
                            inv.user_context.r9 = regs[2];
                        }
                        if count > 3 {
                            inv.user_context.r15 = regs[3];
                        }
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
                            let buf =
                                crate::arch::x86_64::paging::phys_to_lin(ipc_paddr) as *const u64;
                            core::ptr::read_volatile(
                                buf.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET),
                            )
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        {
                            0
                        }
                    } else {
                        0
                    };
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    // MCS semantics: the fault EP cap is resolved
                    // HERE, in the invoker's cspace (extraCaps[0]
                    // was staged as a resolved Cap). Inter-AS fault
                    // handling (PAGEFAULT1001+) depends on this —
                    // the cptr is meaningless in the faulter's own
                    // cspace.
                    let fault_cap = if count > 0 {
                        inv_tcb.pending_extra_caps[0]
                    } else {
                        Cap::Null
                    };
                    let cnode = if count > 1 {
                        Some(inv_tcb.pending_extra_caps[1])
                    } else {
                        None
                    };
                    let vspace = if count > 2 {
                        Some(inv_tcb.pending_extra_caps[2])
                    } else {
                        None
                    };
                    inv_tcb.pending_extra_caps_count = 0;
                    // Stash both the resolved cap (preferred) and
                    // the cptr (legacy fallback) on the target TCB.
                    s.scheduler.slab.get_mut(id).fault_handler = fault_cptr;
                    s.scheduler.slab.get_mut(id).fault_handler_cap = fault_cap;
                    (cnode, vspace)
                } else {
                    let cnode = if args.a3 != 0 {
                        Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a3)?)
                    } else {
                        None
                    };
                    let vspace = if args.a4 != 0 {
                        Some(crate::cspace::lookup_cap(s, &inv_cspace, args.a4)?)
                    } else {
                        None
                    };
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
                            seL4_Error::seL4_InvalidCapability,
                        )));
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
                                    seL4_Error::seL4_RangeError,
                                )));
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
                        _ => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
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
                // seL4 decodeSetIPCBuffer: a zero buffer address means "no
                // IPC buffer" — bufferSlot is NULL and the frame cap is
                // ignored entirely. sel4utils relies on this for
                // no_ipc_buffer threads (e.g. SCHED_CONTEXT_0014), passing
                // addr 0 + seL4_CapNull. Clear the buffer without requiring
                // a Frame cap; drain any staged cap so it can't leak.
                if vaddr == 0 {
                    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
                    let t = s.scheduler.slab.get_mut(id);
                    t.ipc_buffer = 0;
                    t.ipc_buffer_paddr = 0;
                    return Ok(());
                }
                let frame_cap = if upstream {
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    if inv_tcb.pending_extra_caps_count == 0 {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )));
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
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
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
                            seL4_Error::seL4_InvalidCapability,
                        )));
                    }
                    let c = inv_tcb_mut.pending_extra_caps[0];
                    inv_tcb_mut.pending_extra_caps_count = 0;
                    c
                } else {
                    let cspace_root = inv_tcb_mut.cspace_root;
                    crate::cspace::lookup_cap(s, &cspace_root, args.a2)?
                };
                let ntfn_idx = match ntfn_cap {
                    Cap::Notification { ptr, .. } => KernelState::ntfn_index(ptr) as u16,
                    _ => {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_InvalidCapability,
                        )))
                    }
                };
                // Refuse double-bind (matches seL4's behaviour) on
                // either side of the link.
                let t = s.scheduler.slab.get_mut(id);
                if t.bound_notification.is_some() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst,
                    )));
                }
                if s.notifications[ntfn_idx as usize].bound_tcb.is_some() {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_DeleteFirst,
                    )));
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
            // MCS SetTimeoutEndpoint — store the timeout-fault EP cap
            // (extraCaps[0]) on the target TCB so budget exhaustion
            // delivers a Timeout fault there (TIMEOUTFAULT). A Null
            // cap clears it (api_tcb_configure passes seL4_CapNull).
            InvocationLabel::TCBSetTimeoutEndpoint => {
                unsafe {
                    let s = KERNEL.get();
                    let inv = s.scheduler.slab.get_mut(invoker);
                    let cap = if inv.pending_extra_caps_count > 0 {
                        let c = inv.pending_extra_caps[0];
                        inv.pending_extra_caps_count = 0;
                        c
                    } else {
                        Cap::Null
                    };
                    s.scheduler.slab.get_mut(id).timeout_endpoint_cap = cap;
                }
                Ok(())
            }
            // SetMCPriority sets the maximum-controllable-priority
            // bound. mr0 = mcp; extraCaps[0] = authority TCB.
            // SCHED0005 — new MCP must not exceed authority's MCP.
            InvocationLabel::TCBSetMCPriority => {
                let mcp = args.a2 as u8;
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                if info.extra_caps() > 0 {
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    let count = inv_tcb.pending_extra_caps_count as usize;
                    let auth_cap = if count > 0 {
                        Some(inv_tcb.pending_extra_caps[0])
                    } else {
                        None
                    };
                    inv_tcb.pending_extra_caps_count = 0;
                    let auth_mcp = match auth_cap {
                        Some(Cap::Thread { tcb }) => {
                            let auth_id = crate::tcb::TcbId(tcb.addr() as u16);
                            s.scheduler.slab.get(auth_id).mcp
                        }
                        _ => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
                    };
                    if mcp > auth_mcp {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_RangeError,
                        )));
                    }
                } else {
                    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
                }
                s.scheduler.slab.get_mut(id).mcp = mcp;
                Ok(())
            }
            // SetSchedParams (CPriority + MCP combined). Upstream
            // ABI: mr0=mcp, mr1=prio, extraCaps[0]=authority.
            // SCHED0005-style — both bounded by authority's MCP.
            InvocationLabel::TCBSetSchedParams => {
                let mcp = args.a2 as u8;
                let prio = args.a3 as u8;
                let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
                if info.extra_caps() > 0 {
                    let inv_tcb = s.scheduler.slab.get_mut(invoker);
                    let count = inv_tcb.pending_extra_caps_count as usize;
                    let auth_cap = if count > 0 {
                        Some(inv_tcb.pending_extra_caps[0])
                    } else {
                        None
                    };
                    inv_tcb.pending_extra_caps_count = 0;
                    let auth_mcp = match auth_cap {
                        Some(Cap::Thread { tcb }) => {
                            let auth_id = crate::tcb::TcbId(tcb.addr() as u16);
                            s.scheduler.slab.get(auth_id).mcp
                        }
                        _ => {
                            return Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability,
                            )))
                        }
                    };
                    if mcp > auth_mcp || prio > auth_mcp {
                        return Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_RangeError,
                        )));
                    }
                } else {
                    s.scheduler.slab.get_mut(invoker).pending_extra_caps_count = 0;
                }
                let t = s.scheduler.slab.get_mut(id);
                t.mcp = mcp;
                t.priority = prio;
                Ok(())
            }
            // SetTLSBase via TCB invocation (vs the SysSetTLSBase
            // syscall which sets the *invoker's* TLS). a2 = base;
            // a3 selects the segment: 0 (default) = %fs (Linux TLS),
            // non-zero = %gs (the Windows TEB anchor). Save into the
            // target TCB so the dispatcher restores it on next entry.
            InvocationLabel::TCBSetTLSBase => {
                let base = args.a2;
                let want_gs = args.a3 != 0;
                if want_gs {
                    s.scheduler.slab.get_mut(id).cpu_context.gs_base = base;
                } else {
                    s.scheduler.slab.get_mut(id).cpu_context.fs_base = base;
                }
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    if Some(id) == crate::kernel::current_thread() {
                        use crate::arch::x86_64::msr::{wrmsr, IA32_FS_BASE, IA32_KERNEL_GS_BASE};
                        // The user %gs base is applied via the swapped-out MSR so
                        // the return-to-user `swapgs` makes it the active %gs.
                        if want_gs {
                            wrmsr(IA32_KERNEL_GS_BASE, base);
                        } else {
                            wrmsr(IA32_FS_BASE, base);
                        }
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
            // --- Hardware debug API (CONFIG_HARDWARE_DEBUG_API) ----------
            InvocationLabel::TCBSetBreakpoint => {
                use crate::arch::x86_64::debug as dbg;
                let bp_num = args.a2;
                let vaddr = args.a3;
                let ty = args.a4;
                let size = args.a5;
                // MR4 (rw) is in the invoker's IPC buffer (only 4 message
                // registers ride in CPU regs).
                let rw = {
                    let paddr = s.scheduler.slab.get(invoker).ipc_buffer_paddr;
                    if paddr == 0 {
                        0
                    } else {
                        let buf = (crate::arch::x86_64::paging::phys_to_lin(paddr) as *const u64)
                            .wrapping_add(1);
                        core::ptr::read_volatile(buf.add(4))
                    }
                };
                let err = |e| Err(KException::SyscallError(SyscallError::new(e)));
                // Validation order mirrors seL4 decodeSetBreakpoint.
                if vaddr >= 0x0000_8000_0000_0000 {
                    return err(seL4_Error::seL4_InvalidArgument);
                }
                if ty != dbg::SEL4_INSTRUCTION_BREAKPOINT && ty != dbg::SEL4_DATA_BREAKPOINT {
                    return err(seL4_Error::seL4_InvalidArgument);
                }
                if ty == dbg::SEL4_INSTRUCTION_BREAKPOINT {
                    if size != 0 {
                        return err(seL4_Error::seL4_InvalidArgument);
                    }
                    if rw != dbg::SEL4_BREAK_ON_READ {
                        return err(seL4_Error::seL4_InvalidArgument);
                    }
                } else if size == 0 {
                    return err(seL4_Error::seL4_InvalidArgument);
                }
                if rw > dbg::SEL4_BREAK_ON_READWRITE {
                    return err(seL4_Error::seL4_InvalidArgument);
                }
                if !matches!(size, 0 | 1 | 2 | 4 | 8) {
                    return err(seL4_Error::seL4_InvalidArgument);
                }
                if size > 0 && (vaddr & (size - 1)) != 0 {
                    return err(seL4_Error::seL4_AlignmentError);
                }
                if bp_num >= dbg::SEL4_NUM_HW_BREAKPOINTS as u64 {
                    return err(seL4_Error::seL4_RangeError);
                }
                dbg::set_breakpoint(
                    &mut s.scheduler.slab.get_mut(id).debug,
                    bp_num as usize,
                    vaddr,
                    ty,
                    size,
                    rw,
                );
                Ok(())
            }
            InvocationLabel::TCBGetBreakpoint => {
                use crate::arch::x86_64::debug as dbg;
                let bp_num = args.a2;
                if bp_num >= dbg::SEL4_NUM_HW_BREAKPOINTS as u64 {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_RangeError,
                    )));
                }
                let (vaddr, ty, size, rw, enabled) =
                    dbg::get_breakpoint(&s.scheduler.slab.get(id).debug, bp_num as usize);
                let inv = s.scheduler.slab.get_mut(invoker);
                inv.msg_regs[0] = vaddr;
                inv.msg_regs[1] = ty;
                inv.msg_regs[2] = size;
                inv.msg_regs[3] = rw;
                // MR4 (is_enabled) — the SysCall return fans
                // msg_regs[0..length] into the IPC buffer, so set it
                // here rather than writing the buffer directly.
                inv.msg_regs[4] = enabled;
                inv.ipc_length = 5;
                Ok(())
            }
            InvocationLabel::TCBUnsetBreakpoint => {
                use crate::arch::x86_64::debug as dbg;
                let bp_num = args.a2;
                if bp_num >= dbg::SEL4_NUM_HW_BREAKPOINTS as u64 {
                    return Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_RangeError,
                    )));
                }
                dbg::unset_breakpoint(&mut s.scheduler.slab.get_mut(id).debug, bp_num as usize);
                Ok(())
            }
            InvocationLabel::TCBConfigureSingleStepping => {
                use crate::arch::x86_64::debug as dbg;
                let _bp_num = args.a2; // ignored on x86 (TF-based)
                let n_instr = args.a3;
                let consumed = dbg::configure_single_stepping(
                    &mut s.scheduler.slab.get_mut(id).debug,
                    n_instr,
                );
                let t = s.scheduler.slab.get_mut(id);
                if n_instr == 0 {
                    // Disable: clear TF on the target's saved RFLAGS.
                    t.user_context.rflags &= !dbg::FLAGS_TF;
                } else {
                    // Enable: set TF so the thread single-steps when it
                    // next runs; force iretq resume so the rflags slot
                    // (not the sysret r11 path) carries it.
                    t.user_context.rflags |= dbg::FLAGS_TF;
                    t.use_iretq_resume = true;
                }
                let inv = s.scheduler.slab.get_mut(invoker);
                inv.msg_regs[0] = consumed as u64;
                inv.ipc_length = 1;
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
        pooled_retype_capacity_is_atomic();
        revoke_chain_clears_only_descendants();
        repeated_alloc_free_reclaims_untyped();
        cnode_copy_via_invocation();
        cnode_move_clears_source();
        cnode_move_reparents_direct_children();
        cnode_delete_splices_derivation_children();
        cnode_alias_delete_preserves_live_object();
        cnode_finalization_drains_deep_nesting();
        cnode_finalization_splices_external_derivation();
        cnode_revoke_zaps_descendants();
        mdb_records_retype_parent_link();
        mdb_revoke_walks_grandchildren();
        irq_control_issues_handler_cap();
        irq_handler_set_clear_ack();
        frame_map_unmap_get_address();
        zero_device_frame_get_address();
        paging_maps_reject_unassigned_explicit_vspace();
        paging_unmap_requires_exact_physical_identity();
        page_table_invocation_tracks_asid_and_detaches_hardware();
        page_table_map_updates_invoked_slot_not_first_alias();
        tcb_write_read_registers();
        tcb_read_debug_state_reports_scheduler_and_reply_binding();
        reply_delete_clears_receiver_call_state();
        tcb_set_space_and_bind_notification();
        tcb_set_space_pml4_pins_cr3();
        tcb_configure_one_shot_setup();
        asid_control_make_pool_then_assign();
        sched_context_bind_unbind();
        sched_context_consumed_and_runtime_reports();
        sched_control_configure_sets_period_budget();
        unsupported_label_returns_illegal();
        arch::log("Invocation tests completed\n");
    }

    static mut POOL_EXHAUSTION_SCRATCH: [u16; crate::kernel::MAX_DYNAMIC_CNODES] =
        [0; crate::kernel::MAX_DYNAMIC_CNODES];

    fn pooled_available(object_type: ObjectType) -> usize {
        unsafe {
            let s = KERNEL.get();
            match object_type {
                ObjectType::Tcb => s.scheduler.available_cap_tcbs(),
                ObjectType::Endpoint => s.available_endpoints(),
                ObjectType::Notification => s.available_notifications(),
                ObjectType::CapTable => s.available_dynamic_cnodes(),
                ObjectType::SchedContext => s.available_sched_contexts(),
                ObjectType::Reply => s.available_replies(),
                _ => unreachable!("non-pooled Retype object"),
            }
        }
    }

    unsafe fn pooled_alloc_one(object_type: ObjectType, ordinal: usize) -> Option<u16> {
        let s = KERNEL.get();
        match object_type {
            ObjectType::Tcb => s
                .scheduler
                .try_admit_cap(crate::tcb::Tcb {
                    state: crate::tcb::ThreadStateType::Inactive,
                    ..Default::default()
                })
                .map(|id| id.0),
            ObjectType::Endpoint => s.alloc_endpoint().map(|i| i as u16),
            ObjectType::Notification => s.alloc_notification().map(|i| i as u16),
            ObjectType::CapTable => {
                let paddr = 0x1800_0000 + (ordinal as u64) * 64;
                let backing = crate::arch::x86_64::paging::phys_to_lin(paddr) as *mut u8;
                core::ptr::write_bytes(backing, 0, 64);
                s.alloc_dynamic_cnode(paddr, 1)
                    .map(|i| u16::try_from(i).expect("CNode identity fits scratch"))
            }
            ObjectType::SchedContext => s.alloc_sched_context().map(|i| i as u16),
            ObjectType::Reply => s.alloc_reply().map(|i| i as u16),
            _ => unreachable!("non-pooled Retype object"),
        }
    }

    unsafe fn pooled_free_one(object_type: ObjectType, identity: u16) {
        let s = KERNEL.get();
        match object_type {
            ObjectType::Tcb => s.scheduler.slab.free(TcbId(identity)),
            ObjectType::Endpoint => s.free_endpoint(identity as usize),
            ObjectType::Notification => s.free_notification(identity as usize),
            ObjectType::CapTable => s.free_dynamic_cnode(identity as usize),
            ObjectType::SchedContext => s.free_sched_context(identity as usize),
            ObjectType::Reply => s.free_reply(identity as usize),
            _ => unreachable!("non-pooled Retype object"),
        }
    }

    fn assert_pooled_retype_capacity(object_type: ObjectType, size_bits: u32, base: u64) {
        let invoker = setup_invoker(0);
        let source = Cap::Untyped {
            ptr: PAddr::<crate::cap::UntypedStorage>::new(base),
            block_bits: 16,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            KERNEL.get().cnodes[0].0[0] = Cte::with_cap(&source);
        }

        let baseline = pooled_available(object_type);
        assert!(
            baseline >= 2,
            "pooled-object spec needs two free identities"
        );
        let scratch = unsafe { &mut *core::ptr::addr_of_mut!(POOL_EXHAUSTION_SCRATCH) };
        let mut owned = 0usize;
        while let Some(identity) = unsafe { pooled_alloc_one(object_type, owned) } {
            scratch[owned] = identity;
            owned += 1;
        }
        assert_eq!(owned, baseline);
        assert_eq!(pooled_available(object_type), 0);

        let mut args = SyscallArgs {
            a0: 0,
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: object_type.to_word(),
            a3: (u64::from(size_bits) << 32) | 1,
            a4: 4,
            ..Default::default()
        };
        let failed = decode_invocation(source, &args, invoker);
        assert!(matches!(
            failed,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_NotEnoughMemory
            }))
        ));
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.cnodes[0].0[0].cap(), source);
            assert_eq!(s.cnodes[0].0[0].child_count(), 0);
            for slot in 4..6 {
                assert!(s.cnodes[0].0[slot].cap().is_null());
                assert_eq!(s.cnodes[0].0[slot].parent(), None);
                assert_eq!(s.cnodes[0].0[slot].child_count(), 0);
                assert_eq!(s.cnodes[0].0[slot].revoke_epoch(), 0);
            }
        }

        owned -= 1;
        unsafe { pooled_free_one(object_type, scratch[owned]) };
        assert_eq!(pooled_available(object_type), 1);
        args.a3 = (u64::from(size_bits) << 32) | 2;
        let partial = decode_invocation(source, &args, invoker);
        assert!(matches!(
            partial,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_NotEnoughMemory
            }))
        ));
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.cnodes[0].0[0].cap(), source);
            assert_eq!(s.cnodes[0].0[0].child_count(), 0);
            assert!(s.cnodes[0].0[4].cap().is_null());
            assert!(s.cnodes[0].0[5].cap().is_null());
        }
        assert_eq!(pooled_available(object_type), 1);

        owned -= 1;
        unsafe { pooled_free_one(object_type, scratch[owned]) };
        assert_eq!(pooled_available(object_type), 2);
        decode_invocation(source, &args, invoker).expect("exact pool capacity Retype");
        assert_eq!(pooled_available(object_type), 0);
        unsafe {
            let s = KERNEL.get();
            assert!(!s.cnodes[0].0[4].cap().is_null());
            assert!(!s.cnodes[0].0[5].cap().is_null());
            assert_eq!(
                s.cnodes[0].0[4].parent(),
                Some(crate::cte::MdbId::pack(0, 0))
            );
            assert_eq!(
                s.cnodes[0].0[5].parent(),
                Some(crate::cte::MdbId::pack(0, 0))
            );
            assert_eq!(s.cnodes[0].0[0].child_count(), 2);
        }

        let root = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        for slot in 4..6 {
            let delete = SyscallArgs {
                a1: (InvocationLabel::CNodeDelete as u64) << 12,
                a2: slot,
                ..Default::default()
            };
            decode_invocation(root, &delete, invoker).expect("delete exact-fit pooled object");
        }
        assert_eq!(pooled_available(object_type), 2);

        for &identity in &scratch[..owned] {
            unsafe { pooled_free_one(object_type, identity) };
        }
        assert_eq!(pooled_available(object_type), baseline);
        teardown_invoker(invoker);
    }

    #[inline(never)]
    fn pooled_retype_capacity_is_atomic() {
        let cases = [
            (ObjectType::Tcb, 0, 0x0400_0000),
            (ObjectType::Endpoint, 0, 0x0401_0000),
            (ObjectType::Notification, 0, 0x0402_0000),
            (ObjectType::CapTable, 1, 0x0403_0000),
            (
                ObjectType::SchedContext,
                crate::object_type::MIN_SCHED_CONTEXT_BITS,
                0x0404_0000,
            ),
            (ObjectType::Reply, 0, 0x0405_0000),
        ];
        for (object_type, size_bits, base) in cases {
            assert_pooled_retype_capacity(object_type, size_bits, base);
        }
        arch::log("  \u{2713} pooled Untyped::Retype capacity failures are atomic\n");
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
                ptr: PAddr::<UntypedStorage>::new(0x0050_0000),
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
        unsafe {
            KERNEL.get().cnodes[0].0[6] = Cte::with_cap(&pml4_cap);
        }

        // AsidControl::MakePool — pool lands in slot 7.
        let args = SyscallArgs {
            a1: (InvocationLabel::X86ASIDControlMakePool as u64) << 12,
            a2: 5, // Untyped cap_ptr
            a3: 0, // dest_cnode (ignored — we use invoker's CSpace)
            a4: 7, // dest slot
            ..Default::default()
        };
        decode_invocation(Cap::AsidControl, &args, invoker).expect("MakePool ok");
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
        let assigned_asid = unsafe {
            match KERNEL.get().cnodes[0].0[6].cap() {
                Cap::PML4 { asid, .. } => asid,
                other => panic!("expected Cap::PML4, got {:?}", other),
            }
        };
        unsafe {
            match KERNEL.get().cnodes[0].0[6].cap() {
                Cap::PML4 { asid, .. } => {
                    assert!(asid != 0, "Assign should set a non-zero ASID, got {asid}");
                    assert!(
                        asid >= pool_base && asid < pool_base + 512,
                        "ASID {asid} should be within pool [{pool_base}, {pool_base}+512)"
                    );
                }
                other => panic!("expected Cap::PML4, got {:?}", other),
            }
        }
        assert_eq!(
            crate::asid::pml4_paddr(assigned_asid),
            0x0050_8000,
            "Assign should publish the ASID -> PML4 mapping"
        );
        assert_eq!(
            crate::asid::pml4_refcount(assigned_asid),
            1,
            "one live CSpace PML4 cap should hold one ASID reference"
        );

        // Re-assigning a PML4 that already has an ASID surfaces
        // InvalidCapability (upstream decodeX86ASIDPoolAssign;
        // VSPACE0002 asserts exactly this for the already-mapped
        // page_directory).
        let r = decode_invocation(pool, &args, invoker);
        assert!(
            matches!(
                r,
                Err(KException::SyscallError(SyscallError {
                    code: seL4_Error::seL4_InvalidCapability
                }))
            ),
            "second Assign on a non-zero-ASID PML4 should InvalidCapability"
        );

        unsafe {
            KERNEL.get().cnodes[0].0[6].set_cap(&Cap::Null);
        }
        assert_eq!(
            crate::asid::pml4_paddr(assigned_asid),
            0,
            "deleting the last PML4 cap should unpublish the ASID mapping"
        );
        assert_eq!(
            crate::asid::pml4_refcount(assigned_asid),
            0,
            "ASID refcount should drain when the PML4 cap is deleted"
        );

        teardown_invoker(invoker);
        arch::log("  ✓ AsidControl::MakePool + AsidPool::Assign\n");
    }

    /// Phase 30 — every cap retyped from an Untyped should record
    /// that Untyped's CTE as its MDB parent.
    #[inline(never)]
    fn mdb_records_retype_parent_link() {
        let invoker = setup_invoker(0);
        let ut_cap = Cap::Untyped {
            ptr: PAddr::<crate::cap::UntypedStorage>::new(0x0080_0000),
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
                assert_eq!(p, Some(expected), "slot {i}'s MDB parent should be (0, 0)");
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
            ptr: PAddr::<crate::cap::UntypedStorage>::new(0x0090_0000),
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
        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeCopy as u64) << 12,
            a2: 5,
            a3: 4,
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("copy");
        unsafe {
            let s = KERNEL.get();
            let original = crate::cte::MdbId::pack(0, 4);
            assert_eq!(
                s.cnodes[0].0[5].parent(),
                Some(original),
                "copy's MDB parent should be the original at slot 4"
            );
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
            assert!(
                matches!(s.cnodes[0].0[0].cap(), Cap::Untyped { .. }),
                "source Untyped should remain after revoke"
            );
            assert!(
                s.cnodes[0].0[4].cap().is_null(),
                "direct child should be revoked"
            );
            assert!(
                s.cnodes[0].0[5].cap().is_null(),
                "grandchild via Copy should be revoked transitively"
            );
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Revoke walks derivation graph transitively (MDB)\n");
    }

    #[inline(never)]
    fn paging_unmap_requires_exact_physical_identity() {
        #[repr(C, align(4096))]
        struct Table([u64; 512]);

        static mut PML4: Table = Table([0; 512]);
        static mut PDPT: Table = Table([0; 512]);
        static mut PD: Table = Table([0; 512]);
        static mut PT: Table = Table([0; 512]);

        use crate::arch::x86_64::paging::{
            kernel_virt_to_phys, PTE_PRESENT, PTE_PS, PTE_RW, PTE_USER,
        };
        use crate::arch::x86_64::usermode::{
            unmap_user_1g_in_pml4, unmap_user_2m_in_pml4, unmap_user_4k_in_pml4,
            unmap_user_table_in_paddr,
        };

        unsafe {
            let pml4 = core::ptr::addr_of_mut!(PML4) as *mut u64;
            let pdpt = core::ptr::addr_of_mut!(PDPT) as *mut u64;
            let pd = core::ptr::addr_of_mut!(PD) as *mut u64;
            let pt = core::ptr::addr_of_mut!(PT) as *mut u64;
            core::ptr::write_bytes(pml4, 0, 512);
            core::ptr::write_bytes(pdpt, 0, 512);
            core::ptr::write_bytes(pd, 0, 512);
            core::ptr::write_bytes(pt, 0, 512);

            let pml4_paddr = kernel_virt_to_phys(pml4 as u64);
            let pdpt_paddr = kernel_virt_to_phys(pdpt as u64);
            let pd_paddr = kernel_virt_to_phys(pd as u64);
            let pt_paddr = kernel_virt_to_phys(pt as u64);
            let flags = PTE_PRESENT | PTE_RW | PTE_USER;
            let vaddr = 0x0000_0080_4020_1000u64;
            let pml4_i = ((vaddr >> 39) & 0x1ff) as usize;
            let pdpt_i = ((vaddr >> 30) & 0x1ff) as usize;
            let pd_i = ((vaddr >> 21) & 0x1ff) as usize;
            let pt_i = ((vaddr >> 12) & 0x1ff) as usize;

            core::ptr::write_volatile(pml4.add(pml4_i), pdpt_paddr | flags);
            core::ptr::write_volatile(pdpt.add(pdpt_i), pd_paddr | flags);
            core::ptr::write_volatile(pd.add(pd_i), pt_paddr | flags);

            assert!(!unmap_user_table_in_paddr(
                pml4_paddr,
                1,
                vaddr,
                pt_paddr + 0x1000,
            ));
            assert_eq!(
                core::ptr::read_volatile(pd.add(pd_i)) & 0x000F_FFFF_FFFF_F000,
                pt_paddr,
            );
            assert!(unmap_user_table_in_paddr(pml4_paddr, 1, vaddr, pt_paddr,));

            core::ptr::write_volatile(pdpt.add(pdpt_i), pd_paddr | flags);
            assert!(!unmap_user_table_in_paddr(
                pml4_paddr,
                2,
                vaddr,
                pd_paddr + 0x1000,
            ));
            assert!(unmap_user_table_in_paddr(pml4_paddr, 2, vaddr, pd_paddr,));

            core::ptr::write_volatile(pml4.add(pml4_i), pdpt_paddr | flags);
            assert!(!unmap_user_table_in_paddr(
                pml4_paddr,
                3,
                vaddr,
                pdpt_paddr + 0x1000,
            ));
            assert!(unmap_user_table_in_paddr(pml4_paddr, 3, vaddr, pdpt_paddr,));

            core::ptr::write_volatile(pml4.add(pml4_i), pdpt_paddr | flags);
            core::ptr::write_volatile(pdpt.add(pdpt_i), pd_paddr | flags);
            core::ptr::write_volatile(pd.add(pd_i), pt_paddr | flags);
            let frame_4k = 0x0000_0000_0400_0000u64;
            core::ptr::write_volatile(pt.add(pt_i), frame_4k | flags);
            assert!(!unmap_user_4k_in_pml4(pml4_paddr, vaddr, frame_4k + 0x1000));
            assert!(unmap_user_4k_in_pml4(pml4_paddr, vaddr, frame_4k));

            let frame_2m = 0x0000_0000_0800_0000u64;
            core::ptr::write_volatile(pd.add(pd_i), frame_2m | flags | PTE_PS);
            assert!(!unmap_user_2m_in_pml4(
                pml4_paddr,
                vaddr,
                frame_2m + 0x20_0000
            ));
            assert!(unmap_user_2m_in_pml4(pml4_paddr, vaddr, frame_2m));

            let frame_1g = 0x0000_0000_4000_0000u64;
            core::ptr::write_volatile(pdpt.add(pdpt_i), frame_1g | flags | PTE_PS);
            assert!(!unmap_user_1g_in_pml4(
                pml4_paddr,
                vaddr,
                frame_1g + 0x4000_0000
            ));
            assert!(unmap_user_1g_in_pml4(pml4_paddr, vaddr, frame_1g));
        }

        arch::log("  ✓ paging unmap requires exact physical identity at every level\n");
    }

    #[inline(never)]
    fn page_table_invocation_tracks_asid_and_detaches_hardware() {
        #[repr(C, align(4096))]
        struct Table([u64; 512]);

        static mut PML4: Table = Table([0; 512]);
        static mut PDPT: Table = Table([0; 512]);
        static mut PD: Table = Table([0; 512]);
        static mut PT: Table = Table([0; 512]);

        use crate::arch::x86_64::paging::{kernel_virt_to_phys, PTE_PRESENT, PTE_RW, PTE_USER};
        use crate::cap::{PageTableStorage, Pml4Storage};

        const ASID: u16 = 4095;
        let invoker = setup_invoker(0);
        unsafe {
            let pml4 = core::ptr::addr_of_mut!(PML4) as *mut u64;
            let pdpt = core::ptr::addr_of_mut!(PDPT) as *mut u64;
            let pd = core::ptr::addr_of_mut!(PD) as *mut u64;
            let pt = core::ptr::addr_of_mut!(PT) as *mut u64;
            core::ptr::write_bytes(pml4, 0, 512);
            core::ptr::write_bytes(pdpt, 0, 512);
            core::ptr::write_bytes(pd, 0, 512);
            core::ptr::write_bytes(pt, 0, 512);

            let pml4_paddr = kernel_virt_to_phys(pml4 as u64);
            let pdpt_paddr = kernel_virt_to_phys(pdpt as u64);
            let pd_paddr = kernel_virt_to_phys(pd as u64);
            let pt_paddr = kernel_virt_to_phys(pt as u64);
            let flags = PTE_PRESENT | PTE_RW | PTE_USER;
            let vaddr = 0x0000_0090_4040_0000u64;
            let pml4_i = ((vaddr >> 39) & 0x1ff) as usize;
            let pdpt_i = ((vaddr >> 30) & 0x1ff) as usize;
            let pd_i = ((vaddr >> 21) & 0x1ff) as usize;
            core::ptr::write_volatile(pml4.add(pml4_i), pdpt_paddr | flags);
            core::ptr::write_volatile(pdpt.add(pdpt_i), pd_paddr | flags);

            crate::asid::register_boot_mapping(ASID, pml4_paddr);
            let pt_cap = Cap::PageTable {
                ptr: PPtr::<PageTableStorage>::new(pt_paddr).unwrap(),
                mapped: None,
                asid: 0,
            };
            let pml4_cap = Cap::PML4 {
                ptr: PPtr::<Pml4Storage>::new(pml4_paddr).unwrap(),
                mapped: true,
                asid: ASID,
            };
            KERNEL.get().cnodes[0].0[2] = Cte::with_cap(&pt_cap);
            KERNEL.get().cnodes[0].0[3] = Cte::with_cap(&pml4_cap);

            let map_args = SyscallArgs {
                a0: 2,
                a1: (InvocationLabel::X86PageTableMap as u64) << 12,
                a2: vaddr,
                a3: 3,
                ..Default::default()
            };
            decode_invocation(pt_cap, &map_args, invoker).expect("explicit PT map");
            assert_eq!(
                core::ptr::read_volatile(pd.add(pd_i)) & 0x000F_FFFF_FFFF_F000,
                pt_paddr,
            );
            let mapped_cap = KERNEL.get().cnodes[0].0[2].cap();
            assert!(matches!(
                mapped_cap,
                Cap::PageTable {
                    mapped: Some(v),
                    asid: ASID,
                    ..
                } if v == vaddr
            ));

            let root = KERNEL.get().scheduler.slab.get(invoker).cspace_root;
            let copy_args = SyscallArgs {
                a1: (InvocationLabel::CNodeCopy as u64) << 12,
                a2: 4,
                a3: 2,
                ..Default::default()
            };
            decode_invocation(root, &copy_args, invoker).expect("copy mapped PT cap");
            assert_eq!(KERNEL.get().cnodes[0].0[4].cap(), mapped_cap);

            let mut unmap_args = SyscallArgs {
                a0: 2,
                a1: (InvocationLabel::X86PageTableUnmap as u64) << 12,
                ..Default::default()
            };
            assert!(matches!(
                decode_invocation(mapped_cap, &unmap_args, invoker),
                Err(KException::SyscallError(SyscallError {
                    code: seL4_Error::seL4_RevokeFirst,
                }))
            ));
            let delete_args = SyscallArgs {
                a1: (InvocationLabel::CNodeDelete as u64) << 12,
                a2: 2,
                ..Default::default()
            };
            decode_invocation(root, &delete_args, invoker).expect("delete non-final PT alias");
            assert_eq!(
                core::ptr::read_volatile(pd.add(pd_i)) & 0x000F_FFFF_FFFF_F000,
                pt_paddr,
            );

            unmap_args.a0 = 4;
            decode_invocation(mapped_cap, &unmap_args, invoker).expect("unmap final PT alias");
            assert_eq!(core::ptr::read_volatile(pd.add(pd_i)), 0);
            assert!(matches!(
                KERNEL.get().cnodes[0].0[4].cap(),
                Cap::PageTable {
                    mapped: None,
                    asid: 0,
                    ..
                }
            ));

            let mut unmapped_copy_args = copy_args;
            unmapped_copy_args.a2 = 5;
            unmapped_copy_args.a3 = 4;
            assert!(matches!(
                decode_invocation(root, &unmapped_copy_args, invoker),
                Err(KException::SyscallError(SyscallError {
                    code: seL4_Error::seL4_IllegalOperation,
                }))
            ));

            let mut remap_args = map_args;
            remap_args.a0 = 4;
            let unmapped_cap = KERNEL.get().cnodes[0].0[4].cap();
            decode_invocation(unmapped_cap, &remap_args, invoker).expect("remap final PT cap");
            let remapped_cap = KERNEL.get().cnodes[0].0[4].cap();
            core::ptr::write_volatile(pd.add(pd_i), (pt_paddr + 0x1000) | flags);
            decode_invocation(remapped_cap, &unmap_args, invoker)
                .expect("stale parent edge does not block explicit PT unmap");
            assert_eq!(
                core::ptr::read_volatile(pd.add(pd_i)) & 0x000F_FFFF_FFFF_F000,
                pt_paddr + 0x1000,
            );
            assert!(matches!(
                KERNEL.get().cnodes[0].0[4].cap(),
                Cap::PageTable {
                    mapped: None,
                    asid: 0,
                    ..
                }
            ));
            core::ptr::write_volatile(pd.add(pd_i), 0);

            crate::asid::clear_pool(ASID & !0x1ff);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ PageTable Map/Unmap persists ASID and detaches hardware\n");
    }

    /// Page-structure map must update the cap slot the caller invoked, not the first sibling cap
    /// with the same object paddr. The NT rootserver keeps copied aliases and a large root CSpace; a
    /// full-CNode scan both mutates the wrong sibling and becomes a boot-time cliff.
    #[inline(never)]
    fn page_table_map_updates_invoked_slot_not_first_alias() {
        use crate::cap::PageTableStorage;
        let invoker = setup_invoker(0);
        let pt_paddr = 0x0000_0000_00B1_0000u64;
        let pt_cap = Cap::PageTable {
            ptr: PPtr::<PageTableStorage>::new(pt_paddr).unwrap(),
            mapped: None,
            asid: 0,
        };
        const EARLY_ALIAS_SLOT: usize = 2;
        const INVOKED_SLOT: usize = 28;
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[EARLY_ALIAS_SLOT] = Cte::with_cap(&pt_cap);
            s.cnodes[0].0[INVOKED_SLOT] = Cte::with_cap(&pt_cap);
        }

        let vaddr = 0x0000_0100_0140_0000u64;
        let args = SyscallArgs {
            a0: INVOKED_SLOT as u64,
            a1: (InvocationLabel::X86PageTableMap as u64) << 12,
            a2: vaddr,
            ..Default::default()
        };
        decode_invocation(pt_cap, &args, invoker).expect("PT map ok");

        unsafe {
            match KERNEL.get().cnodes[0].0[EARLY_ALIAS_SLOT].cap() {
                Cap::PageTable { mapped: None, .. } => {}
                other => panic!("early alias should remain unmapped, got {:?}", other),
            }
            match KERNEL.get().cnodes[0].0[INVOKED_SLOT].cap() {
                Cap::PageTable {
                    mapped: Some(v), ..
                } if v == vaddr => {}
                other => panic!("invoked slot should be mapped, got {:?}", other),
            }
        }

        teardown_invoker(invoker);
        arch::log("  ✓ Cap::PageTable Map updates invoked slot, not first alias\n");
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
                slot.set_parent(None);
                slot.set_child_count(0);
                slot.set_revoke_epoch(0);
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
            ptr: PAddr::<crate::cap::UntypedStorage>::new(untyped_base),
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
            a0: 0, // unused at this layer
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
                        assert!(
                            idx < crate::kernel::MAX_ENDPOINTS,
                            "ep index out of range: {}",
                            idx
                        );
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
            ptr: PAddr::<crate::cap::UntypedStorage>::new(untyped_base),
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
        let root_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
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
            | 6u64; // length = 6
        let args = SyscallArgs {
            a0: 0,
            a1: info_word,
            a2: ObjectType::Endpoint.to_word(),
            a3: 0, // size_bits (unused for Endpoint)
            a4: 0, // node_index = 0 (root cap IS dest CNode)
            a5: 0, // node_depth = 0 (root cap directly)
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
                    target_slot, other
                ),
            }
            // No collateral writes at slot 4 (the LEGACY-ABI default
            // dest_offset).
            assert!(
                s.cnodes[0].0[4].cap().is_null(),
                "slot 4 should remain Null when upstream ABI requests slot 0x{:x}",
                target_slot
            );
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
            ptr: PAddr::<crate::cap::UntypedStorage>::new(0x00A0_0000),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        // Plant an UNRELATED Untyped at slot 0x57f — must survive a
        // revoke of slot 0.
        let unrelated_ut = Cap::Untyped {
            ptr: PAddr::<crate::cap::UntypedStorage>::new(0x00B0_0000),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[0] = Cte::with_cap(&parent_ut);
            s.cnodes[0].0[0x57f] = Cte::with_cap(&unrelated_ut);
            // Default parent for the unrelated cap is None (sentinel).
            assert!(
                s.cnodes[0].0[0x57f].parent().is_none(),
                "fresh Cte::with_cap should have parent=None"
            );
        }
        // Retype parent into a sub-Untyped at slot 100, then sub into
        // an Endpoint at slot 200 (chained derivation). Both should
        // be revoked when we revoke slot 0; slot 0x57f must NOT be.
        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        // Legacy ABI: a3 = (size_bits << 32) | num_objects.
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: ObjectType::Untyped.to_word(),
            a3: (8u64 << 32) | 1, // size_bits=8 (256B), num=1
            a4: 100,              // dest_offset
            ..Default::default()
        };
        decode_invocation(parent_ut, &args, invoker).expect("retype sub-ut");

        // Snapshot the sub-Untyped cap.
        let sub_ut = unsafe { KERNEL.get().cnodes[0].0[100].cap() };
        let args = SyscallArgs {
            a0: 100,
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: ObjectType::Endpoint.to_word(),
            a3: 1,
            a4: 200,
            ..Default::default()
        };
        decode_invocation(sub_ut, &args, invoker).expect("retype ep");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.cnodes[0].0[200].parent(),
                Some(crate::cte::MdbId::pack(0, 100))
            );
            assert!(matches!(
                s.cnodes[0].0[0].cap(),
                Cap::Untyped {
                    free_index: 256,
                    ..
                }
            ));
            assert!(matches!(
                s.cnodes[0].0[100].cap(),
                Cap::Untyped { free_index: 16, .. }
            ));
        }

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
            assert!(
                matches!(s.cnodes[0].0[0].cap(), Cap::Untyped { .. }),
                "revoke source slot 0 should keep its cap"
            );
            // Both descendants gone.
            assert!(
                s.cnodes[0].0[100].cap().is_null(),
                "sub-Untyped at 100 should be nulled"
            );
            assert!(
                s.cnodes[0].0[200].cap().is_null(),
                "Endpoint at 200 should be nulled"
            );
            // The unrelated Untyped MUST survive.
            match s.cnodes[0].0[0x57f].cap() {
                Cap::Untyped { ptr, .. } => assert_eq!(
                    ptr.addr(),
                    0x00B0_0000,
                    "unrelated Untyped at 0x57f must survive an unrelated revoke"
                ),
                other => panic!("unrelated cap at 0x57f got nulled by revoke: {:?}", other),
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
            ptr: PAddr::<crate::cap::UntypedStorage>::new(0x00C0_0000),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[0] = Cte::with_cap(&ut_cap);
        }
        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
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
                panic!(
                    "retype failed at cycle {} (free_index didn't reclaim?)",
                    cycle
                );
            }
            // Confirm cap landed.
            unsafe {
                let s = KERNEL.get();
                assert!(
                    matches!(s.cnodes[0].0[4].cap(), Cap::Endpoint { .. }),
                    "endpoint missing at cycle {}",
                    cycle
                );
            }
            // Mirror vka_free_object: revoke then delete. Some
            // vka implementations only call cnode_delete; others
            // do revoke + delete. Either should work.
            let rev_args = SyscallArgs {
                a1: (InvocationLabel::CNodeRevoke as u64) << 12,
                a2: 4,
                ..Default::default()
            };
            decode_invocation(cnode_cap, &rev_args, invoker).expect("revoke ok");
            let del_args = SyscallArgs {
                a1: (InvocationLabel::CNodeDelete as u64) << 12,
                a2: 4,
                ..Default::default()
            };
            decode_invocation(cnode_cap, &del_args, invoker).expect("delete ok");
            unsafe {
                let s = KERNEL.get();
                assert!(
                    s.cnodes[0].0[4].cap().is_null(),
                    "slot 4 should be empty at cycle {}",
                    cycle
                );
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
                    can_send: true,
                    can_receive: false,
                    can_grant: false,
                    can_grant_reply: false,
                },
            });
        }

        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
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
        let parent = crate::cte::MdbId::pack(0, 5);
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[5] = Cte::with_cap(&Cap::Endpoint {
                ptr: PPtr::<EndpointObj>::new(3).unwrap(),
                badge: Badge(0),
                rights: EndpointRights::default(),
            });
            s.cnodes[0].0[1] = Cte::with_cap(&Cap::Endpoint {
                ptr: PPtr::<EndpointObj>::new(1).unwrap(),
                badge: Badge(0),
                rights: EndpointRights::default(),
            });
            s.cnodes[0].0[1].set_parent(Some(parent));
            s.cnodes[0].0[3].set_parent(Some(crate::cte::MdbId::pack(0, 7)));
            child_count_inc(parent, 1);
        }
        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        let scan_before = REPARENT_SCAN_SLOTS.load(core::sync::atomic::Ordering::Relaxed);
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeMove as u64) << 12,
            a2: 3, // dest
            a3: 1, // src
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("move ok");
        assert_eq!(
            REPARENT_SCAN_SLOTS.load(core::sync::atomic::Ordering::Relaxed),
            scan_before,
            "moving a leaf CTE must not scan the CNode registry"
        );
        unsafe {
            let s = KERNEL.get();
            assert!(s.cnodes[0].0[1].cap().is_null());
            assert_eq!(s.cnodes[0].0[1].parent(), None);
            assert!(matches!(s.cnodes[0].0[3].cap(), Cap::Endpoint { .. }));
            assert_eq!(s.cnodes[0].0[3].parent(), Some(parent));

            // Reuse the moved-from slot with an unrelated root cap. Revoking the old parent must
            // follow the moved MDB edge to slot 3, never the stale slot 1 location.
            s.cnodes[0].0[1].set_cap(&Cap::Endpoint {
                ptr: PPtr::<EndpointObj>::new(2).unwrap(),
                badge: Badge(0),
                rights: EndpointRights::default(),
            });
            s.cnodes[0].0[1].set_parent(None);
        }
        let revoke = SyscallArgs {
            a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: 5,
            ..Default::default()
        };
        decode_invocation(cnode_cap, &revoke, invoker).expect("revoke moved cap parent");
        unsafe {
            let s = KERNEL.get();
            assert!(matches!(s.cnodes[0].0[1].cap(), Cap::Endpoint { .. }));
            assert!(s.cnodes[0].0[3].cap().is_null());
            assert_eq!(s.cnodes[0].0[3].parent(), None);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ CNode::Move transfers cap + MDB ownership and zeroes source\n");
    }

    #[inline(never)]
    fn cnode_move_reparents_direct_children() {
        let invoker = setup_invoker(0);
        let source_id = crate::cte::MdbId::pack(0, 1);
        let destination_id = crate::cte::MdbId::pack(0, 2);
        unsafe {
            let s = KERNEL.get();
            let endpoint = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(s.alloc_endpoint().expect("moved endpoint")),
                badge: Badge(0),
                rights: EndpointRights::default(),
            };
            s.cnodes[0].0[1].set_cap(&endpoint);
            s.cnodes[0].0[1].set_child_count(1);
            s.cnodes[0].0[3].set_cap(&endpoint);
            s.cnodes[0].0[3].set_parent(Some(source_id));
        }

        let root = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        let mut args = SyscallArgs {
            a1: (InvocationLabel::CNodeMove as u64) << 12,
            a2: 2,
            a3: 1,
            ..Default::default()
        };
        decode_invocation(root, &args, invoker).expect("move cap with direct child");
        unsafe {
            let s = KERNEL.get();
            assert!(s.cnodes[0].0[1].cap().is_null());
            assert_eq!(s.cnodes[0].0[2].child_count(), 1);
            assert_eq!(s.cnodes[0].0[3].parent(), Some(destination_id));
        }

        args.a1 = (InvocationLabel::CNodeDelete as u64) << 12;
        args.a2 = 3;
        decode_invocation(root, &args, invoker).expect("delete moved cap child");
        args.a2 = 2;
        decode_invocation(root, &args, invoker).expect("delete moved cap");
        teardown_invoker(invoker);
        arch::log("  ✓ CNode::Move reparents exact direct descendants\n");
    }

    #[inline(never)]
    fn cnode_delete_splices_derivation_children() {
        let invoker = setup_invoker(0);
        let parent_id = crate::cte::MdbId::pack(0, 1);
        let middle_id = crate::cte::MdbId::pack(0, 2);
        unsafe {
            let s = KERNEL.get();
            let parent = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(s.alloc_endpoint().expect("parent endpoint")),
                badge: Badge(0),
                rights: EndpointRights::default(),
            };
            let middle = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(s.alloc_endpoint().expect("middle endpoint")),
                badge: Badge(0),
                rights: EndpointRights::default(),
            };
            let leaf = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(s.alloc_endpoint().expect("leaf endpoint")),
                badge: Badge(0),
                rights: EndpointRights::default(),
            };
            s.cnodes[0].0[1].set_cap(&parent);
            s.cnodes[0].0[1].set_child_count(1);
            s.cnodes[0].0[2].set_cap(&middle);
            s.cnodes[0].0[2].set_parent(Some(parent_id));
            s.cnodes[0].0[2].set_child_count(1);
            s.cnodes[0].0[3].set_cap(&leaf);
            s.cnodes[0].0[3].set_parent(Some(middle_id));
        }

        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        let mut args = SyscallArgs {
            a1: (InvocationLabel::CNodeDelete as u64) << 12,
            a2: 2,
            ..Default::default()
        };
        decode_invocation(cnode_cap, &args, invoker).expect("delete middle derivation cap");
        unsafe {
            let s = KERNEL.get();
            assert!(s.cnodes[0].0[2].cap().is_null());
            assert_eq!(s.cnodes[0].0[3].parent(), Some(parent_id));
            assert_eq!(s.cnodes[0].0[1].child_count(), 1);
        }
        args.a2 = 3;
        decode_invocation(cnode_cap, &args, invoker).expect("delete reparented leaf");
        args.a2 = 1;
        decode_invocation(cnode_cap, &args, invoker).expect("delete derivation parent");
        teardown_invoker(invoker);
        arch::log("  ✓ CNode::Delete splices surviving derivation children\n");
    }

    #[inline(never)]
    fn cnode_alias_delete_preserves_live_object() {
        use crate::cap::PageTableStorage;

        let invoker = setup_invoker(0);
        let vi = unsafe { KERNEL.get().alloc_small_cnode().expect("alias CNode") };
        let cnode = Cap::CNode {
            ptr: KernelState::cnode_ptr(vi),
            radix: 1,
            guard_size: 63,
            guard: 0,
        };
        let stale_mapping = Cap::PageTable {
            ptr: PPtr::<PageTableStorage>::new(0x00d0_0000).unwrap(),
            mapped: Some(0x0000_0100_2000_0000),
            asid: 0,
        };
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[1].set_cap(&cnode);
            s.cnodes[0].0[2].set_cap(&cnode);
            s.cnode_slot_mut(vi, 0)
                .expect("alias CNode slot")
                .set_cap(&stale_mapping);
        }

        let root = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        let mut args = SyscallArgs {
            a1: (InvocationLabel::CNodeDelete as u64) << 12,
            a2: 1,
            ..Default::default()
        };
        decode_invocation(root, &args, invoker).expect("delete non-final CNode alias");
        unsafe {
            let s = KERNEL.get();
            assert!(matches!(s.cnodes[0].0[2].cap(), Cap::CNode { .. }));
            assert_eq!(
                s.cnode_slot(vi, 0).expect("live alias contents").cap(),
                stale_mapping
            );
        }

        args.a2 = 2;
        decode_invocation(root, &args, invoker)
            .expect("delete final CNode with detached paging edge");
        unsafe {
            let s = KERNEL.get();
            assert!(s.cnodes[0].0[2].cap().is_null());
            assert!(s
                .cnode_slot(vi, 0)
                .expect("finalized CNode storage")
                .cap()
                .is_null());
        }
        teardown_invoker(invoker);
        arch::log("  ✓ final CNode deletion tolerates detached paging edges\n");
    }

    #[inline(never)]
    fn cnode_finalization_drains_deep_nesting() {
        const DEPTH: usize = 8;
        let invoker = setup_invoker(0);
        let mut nodes = [0usize; DEPTH];
        unsafe {
            let s = KERNEL.get();
            for node in &mut nodes {
                *node = s.alloc_small_cnode().expect("deep CNode");
            }
            for i in 0..DEPTH - 1 {
                s.cnode_slot_mut(nodes[i], 0)
                    .expect("deep CNode slot")
                    .set_cap(&Cap::CNode {
                        ptr: KernelState::cnode_ptr(nodes[i + 1]),
                        radix: 1,
                        guard_size: 63,
                        guard: 0,
                    });
            }
            s.cnodes[0].0[1].set_cap(&Cap::CNode {
                ptr: KernelState::cnode_ptr(nodes[0]),
                radix: 1,
                guard_size: 63,
                guard: 0,
            });
        }

        let root = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeDelete as u64) << 12,
            a2: 1,
            ..Default::default()
        };
        decode_invocation(root, &args, invoker).expect("delete deep CNode root");
        unsafe {
            let s = KERNEL.get();
            let mut recycled = [0usize; DEPTH];
            for node in &mut recycled {
                *node = s.alloc_small_cnode().expect("recycled deep CNode");
            }
            nodes.sort_unstable();
            recycled.sort_unstable();
            assert_eq!(
                recycled, nodes,
                "every deeply nested CNode must be reclaimed"
            );
            for node in recycled {
                s.free_cnode_virt(node);
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ CNode finalization drains nesting deeper than four levels\n");
    }

    #[inline(never)]
    fn cnode_finalization_splices_external_derivation() {
        let invoker = setup_invoker(0);
        let parent_id = crate::cte::MdbId::pack(0, 10);
        let vi = unsafe { KERNEL.get().alloc_small_cnode().expect("owned CNode") };
        let source_id = crate::cte::MdbId::pack(vi as u32, 0);
        unsafe {
            let s = KERNEL.get();
            let parent = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(s.alloc_endpoint().expect("derivation parent")),
                badge: Badge(0),
                rights: EndpointRights::default(),
            };
            let derived = Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(s.alloc_endpoint().expect("derived endpoint")),
                badge: Badge(0),
                rights: EndpointRights::default(),
            };
            s.cnodes[0].0[10].set_cap(&parent);
            s.cnodes[0].0[10].set_child_count(1);
            let source = s.cnode_slot_mut(vi, 0).expect("owned CNode source slot");
            source.set_cap(&derived);
            source.set_parent(Some(parent_id));
            source.set_child_count(1);
            s.cnodes[0].0[11].set_cap(&derived);
            s.cnodes[0].0[11].set_parent(Some(source_id));
            s.cnodes[0].0[1].set_cap(&Cap::CNode {
                ptr: KernelState::cnode_ptr(vi),
                radix: 1,
                guard_size: 63,
                guard: 0,
            });
        }

        let root = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
        let mut args = SyscallArgs {
            a1: (InvocationLabel::CNodeDelete as u64) << 12,
            a2: 1,
            ..Default::default()
        };
        decode_invocation(root, &args, invoker).expect("finalize CNode with external derivation");
        unsafe {
            let s = KERNEL.get();
            assert!(matches!(s.cnodes[0].0[11].cap(), Cap::Endpoint { .. }));
            assert_eq!(s.cnodes[0].0[11].parent(), Some(parent_id));
            assert_eq!(s.cnodes[0].0[10].child_count(), 1);
            let reused = s.alloc_small_cnode().expect("reused CNode descriptor");
            assert_eq!(reused, vi);
            assert_ne!(
                s.cnodes[0].0[11].parent(),
                Some(crate::cte::MdbId::pack(reused as u32, 0))
            );
            s.free_cnode_virt(reused);
        }
        args.a2 = 11;
        decode_invocation(root, &args, invoker).expect("delete surviving derived cap");
        args.a2 = 10;
        decode_invocation(root, &args, invoker).expect("delete derivation parent");
        teardown_invoker(invoker);
        arch::log("  ✓ CNode finalization preserves and reparents external derivations\n");
    }

    /// Revoke walks the cap tree and zeroes every derived cap.
    /// Source untyped is left intact; its children are deleted.
    #[inline(never)]
    fn cnode_revoke_zaps_descendants() {
        let invoker = setup_invoker(0);
        let untyped_base = 0x0080_0000u64;
        let ut_cap = Cap::Untyped {
            ptr: PAddr::<crate::cap::UntypedStorage>::new(untyped_base),
            block_bits: 14,
            free_index: 0,
            is_device: false,
        };
        unsafe {
            KERNEL.get().cnodes[0].0[0] = Cte::with_cap(&ut_cap);
        }

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
        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
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
                assert!(
                    s.cnodes[0].0[i].cap().is_null(),
                    "slot {i} should have been revoked"
                );
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
        decode_invocation(Cap::IrqControl, &args, invoker).expect("issue handler ok");
        unsafe {
            let s = KERNEL.get();
            match s.cnodes[0].0[2].cap() {
                Cap::IrqHandler { irq: 7 } => {}
                other => panic!("expected IrqHandler{{7}}, got {:?}", other),
            }
        }
        let duplicate = SyscallArgs {
            a1: (InvocationLabel::IRQIssueIRQHandler as u64) << 12,
            a2: 7,
            a3: 3,
            ..Default::default()
        };
        assert!(matches!(
            decode_invocation(Cap::IrqControl, &duplicate, invoker),
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_RevokeFirst
            }))
        ));
        teardown_invoker(invoker);
        arch::log("  ✓ IRQControl issues one exclusive handler per vector\n");
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
                    can_send: true,
                    can_receive: true,
                },
            });
        }

        // SetNotification: bind IRQ 9 to the ntfn cap at slot 5.
        let args = SyscallArgs {
            a1: (InvocationLabel::IRQSetIRQHandler as u64) << 12,
            a2: 5, // CPtr to ntfn cap
            ..Default::default()
        };
        decode_invocation(Cap::IrqHandler { irq: 9 }, &args, invoker).expect("set notification ok");
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
        decode_invocation(Cap::IrqHandler { irq: 9 }, &args, invoker).expect("ack ok");
        unsafe {
            let s = KERNEL.get();
            assert!(!s.irqs.get(9).unwrap().pending);
        }

        // Clear via invocation.
        let args = SyscallArgs {
            a1: (InvocationLabel::IRQClearIRQHandler as u64) << 12,
            ..Default::default()
        };
        decode_invocation(Cap::IrqHandler { irq: 9 }, &args, invoker).expect("clear ok");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(
                s.irqs.get(9).unwrap().state,
                crate::interrupt::IrqState::Inactive
            );
        }

        teardown_invoker(invoker);
        arch::log("  ✓ IRQHandler::Set/Ack/Clear cycle\n");
    }

    #[inline(never)]
    fn zero_device_frame_get_address() {
        use crate::cap::{FrameRights, FrameSize, FrameStorage};

        let invoker = setup_invoker(0);
        let frame_cap = Cap::Frame {
            ptr: PAddr::<FrameStorage>::new(0),
            size: FrameSize::Small,
            rights: FrameRights::ReadOnly,
            mapped: None,
            asid: 0,
            is_device: true,
            map_type: crate::cap::FrameMapType::None,
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::X86PageGetAddress as u64) << 12,
            ..Default::default()
        };
        decode_invocation(frame_cap, &args, invoker).expect("get page-zero address");
        unsafe {
            assert_eq!(KERNEL.get().scheduler.slab.get(invoker).msg_regs[0], 0);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ page-zero device frame GetAddress preserves physical zero\n");
    }

    #[inline(never)]
    fn frame_map_unmap_get_address() {
        use crate::cap::{FrameRights, FrameSize, FrameStorage};

        let invoker = setup_invoker(0);
        // Plant sibling Frame caps at slots 1 and 2 of CNode 0. Pick a paddr
        // safely past BOOTBOOT's identity range so map_user_4k
        // doesn't clash with the loader's 1 GiB pages, and a
        // vaddr in PML4[2] (= same place the user-mode demo uses).
        let paddr = 0x0000_0000_0090_0000u64;
        let frame_cap = Cap::Frame {
            ptr: PAddr::<FrameStorage>::new(paddr),
            size: FrameSize::Small,
            rights: FrameRights::ReadWrite,
            mapped: None,
            asid: 0,
            is_device: false,
            map_type: crate::cap::FrameMapType::None,
        };
        unsafe {
            KERNEL.get().cnodes[0].0[1] = Cte::with_cap(&frame_cap);
            KERNEL.get().cnodes[0].0[2] = Cte::with_cap(&frame_cap);
        }

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
            a0: 2,
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: vaddr,
            a3: FrameRights::ReadWrite.to_word(),
            ..Default::default()
        };
        decode_invocation(frame_cap, &args, invoker).expect("map ok");

        // The invoked sibling cap records the mapping; the source sibling remains unmapped and
        // copyable for later derivations.
        unsafe {
            match KERNEL.get().cnodes[0].0[1].cap() {
                Cap::Frame { mapped: None, .. } => {}
                other => panic!("source sibling should stay unmapped, got {:?}", other),
            }
            match KERNEL.get().cnodes[0].0[2].cap() {
                Cap::Frame {
                    mapped: Some(v),
                    rights: FrameRights::ReadWrite,
                    ..
                } if v == vaddr => {}
                other => panic!("expected mapped frame, got {:?}", other),
            }
        }

        // Verify the PTE actually went in by walking the live
        // page tables.
        let translated = crate::arch::x86_64::paging::live_virt_to_phys(vaddr);
        assert_eq!(translated, Some(paddr));

        // A stale cap that names a different physical frame at the same
        // virtual address must not clear the live leaf.
        let live_pml4 = crate::arch::x86_64::usermode::current_pml4_paddr();
        let stale_unmapped = unsafe {
            crate::arch::x86_64::usermode::unmap_user_4k_in_pml4(live_pml4, vaddr, paddr + 0x1000)
        };
        assert!(
            !stale_unmapped,
            "stale frame identity must not unmap a replacement leaf"
        );
        assert_eq!(
            crate::arch::x86_64::paging::live_virt_to_phys(vaddr),
            Some(paddr)
        );

        // Re-mapping at the SAME vaddr is a no-op (mirrors upstream
        // `decodeX86FrameMapInvocation`), so it should succeed.
        let args = SyscallArgs {
            a0: 2,
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: vaddr,
            a3: FrameRights::ReadWrite.to_word(),
            ..Default::default()
        };
        let now_cap = unsafe { KERNEL.get().cnodes[0].0[2].cap() };
        decode_invocation(now_cap, &args, invoker).expect("remap same vaddr ok");

        // Re-mapping at a DIFFERENT vaddr is rejected with DeleteFirst —
        // userspace must Unmap first.
        let other_vaddr = vaddr + 0x1000;
        let args = SyscallArgs {
            a0: 2,
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: other_vaddr,
            a3: FrameRights::ReadWrite.to_word(),
            ..Default::default()
        };
        let r = decode_invocation(now_cap, &args, invoker);
        assert!(matches!(
            r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_DeleteFirst
            }))
        ));

        // Unmap clears the mapping in the cap.
        let args = SyscallArgs {
            a0: 2,
            a1: (InvocationLabel::X86PageUnmap as u64) << 12,
            ..Default::default()
        };
        decode_invocation(now_cap, &args, invoker).expect("unmap ok");
        unsafe {
            match KERNEL.get().cnodes[0].0[1].cap() {
                Cap::Frame { mapped: None, .. } => {}
                other => panic!("source sibling should remain unmapped, got {:?}", other),
            }
            match KERNEL.get().cnodes[0].0[2].cap() {
                Cap::Frame { mapped: None, .. } => {}
                other => panic!("expected unmapped frame, got {:?}", other),
            }
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Frame::Map / Unmap / GetAddress round-trip\n");
    }

    /// Explicit frame maps need a real ASID so later unmap/delete can find the same VSpace.
    #[inline(never)]
    fn paging_maps_reject_unassigned_explicit_vspace() {
        use crate::cap::{FrameRights, FrameSize, FrameStorage, PageTableStorage, Pml4Storage};

        let invoker = setup_invoker(0);
        let frame_cap = Cap::Frame {
            ptr: PAddr::<FrameStorage>::new(0x0000_0000_0091_0000),
            size: FrameSize::Small,
            rights: FrameRights::ReadWrite,
            mapped: None,
            asid: 0,
            is_device: false,
            map_type: crate::cap::FrameMapType::None,
        };
        let pml4_cap = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(0x0000_0000_0092_0000).unwrap(),
            mapped: true,
            asid: 0,
        };
        let page_table_cap = Cap::PageTable {
            ptr: PPtr::<PageTableStorage>::new(0x0000_0000_0093_0000).unwrap(),
            mapped: None,
            asid: 0,
        };
        unsafe {
            KERNEL.get().cnodes[0].0[2] = Cte::with_cap(&frame_cap);
            KERNEL.get().cnodes[0].0[3] = Cte::with_cap(&pml4_cap);
            KERNEL.get().cnodes[0].0[4] = Cte::with_cap(&page_table_cap);
        }

        let args = SyscallArgs {
            a0: 2,
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: 0x0000_0100_0060_0000,
            a3: FrameRights::ReadWrite.to_word(),
            a4: 3,
            ..Default::default()
        };
        let result = decode_invocation(frame_cap, &args, invoker);
        assert!(matches!(
            result,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_InvalidCapability
            }))
        ));
        unsafe {
            assert!(matches!(
                KERNEL.get().cnodes[0].0[2].cap(),
                Cap::Frame { mapped: None, .. }
            ));
        }

        let page_table_args = SyscallArgs {
            a0: 4,
            a1: (InvocationLabel::X86PageTableMap as u64) << 12,
            a2: 0x0000_0100_0080_0000,
            a3: 3,
            ..Default::default()
        };
        let result = decode_invocation(page_table_cap, &page_table_args, invoker);
        assert!(matches!(
            result,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_InvalidCapability
            }))
        ));
        unsafe {
            assert!(matches!(
                KERNEL.get().cnodes[0].0[4].cap(),
                Cap::PageTable { mapped: None, .. }
            ));
        }

        teardown_invoker(invoker);
        arch::log("  ✓ paging maps reject an unassigned explicit VSpace\n");
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
    fn tcb_read_debug_state_reports_scheduler_and_reply_binding() {
        let invoker = setup_invoker(0);
        let reply_idx = 9usize;
        let target = unsafe {
            let s = KERNEL.get();
            let mut t = crate::tcb::Tcb::default();
            t.priority = 88;
            t.state = crate::tcb::ThreadStateType::BlockedOnReply;
            t.sc = Some(7);
            t.active_sc = Some(8);
            t.pending_reply = Some(11);
            t.reply_to = Some(invoker);
            t.bound_notification = Some(12);
            t.blocked_is_call = true;
            t.blocked_can_grant = true;
            t.donated_sc = Some(13);
            t.pending_fault = 6;
            t.hosted_syscalls = true;
            let target = s.scheduler.admit(t);
            s.cnodes[0].0[2] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.replies[reply_idx] = crate::reply::Reply {
                bound_tcb: Some(target),
            };
            s.scheduler.set_current(Some(invoker));
            target
        };
        let target_cap = Cap::Thread {
            tcb: crate::cap::PPtr::<crate::cap::Tcb>::new(target.0 as u64).unwrap(),
        };

        let args = SyscallArgs {
            a1: (InvocationLabel::TCBReadDebugState as u64) << 12,
            a2: 2,
            ..Default::default()
        };
        decode_invocation(target_cap, &args, invoker).expect("debug state");
        unsafe {
            let s = KERNEL.get();
            let inv = s.scheduler.slab.get(invoker);
            assert_eq!(inv.ipc_length, TCB_DEBUG_STATE_WORDS as u32);
            assert_eq!(
                inv.msg_regs[0],
                crate::tcb::ThreadStateType::BlockedOnReply as u64
            );
            assert_eq!(inv.msg_regs[1], 0);
            assert_eq!(inv.msg_regs[2], 0);
            assert_eq!(inv.msg_regs[3], 88);
            assert_eq!(inv.msg_regs[4], 7);
            assert_eq!(inv.msg_regs[5], 8);
            assert_eq!(inv.msg_regs[6], 11);
            assert_eq!(inv.msg_regs[7], invoker.0 as u64);
            assert_eq!(inv.msg_regs[8], 12);
            assert_eq!(inv.msg_regs[9], 1);
            assert_eq!(inv.msg_regs[10], 1);
            assert_eq!(inv.msg_regs[11], 13);
            assert_eq!(inv.msg_regs[12], 6);
            assert_eq!(inv.msg_regs[13], 1);
            assert_eq!(inv.msg_regs[14], target.0 as u64);
            assert_eq!(inv.msg_regs[15], invoker.0 as u64);
            assert_eq!(inv.msg_regs[16], target.0 as u64);
            assert_eq!(inv.msg_regs[17], TCB_DEBUG_NONE);
            assert_eq!(inv.msg_regs[18], 0);
            s.cnodes[0].0[2] = Cte::null();
            s.replies[reply_idx] = crate::reply::Reply::new();
            s.scheduler.slab.free(target);
            s.scheduler.set_current(None);
        }
        teardown_invoker(invoker);
        arch::log("  ✓ TCB::ReadDebugState reports scheduler and reply binding\n");
    }

    #[inline(never)]
    fn reply_delete_clears_receiver_call_state() {
        let invoker = setup_invoker(0);
        let reply_idx = 10usize;
        let caller_sc = 14usize;
        let server_sc = 15usize;
        let (caller, server) = unsafe {
            let s = KERNEL.get();
            s.scheduler.reset_queues();
            s.replies[reply_idx] = crate::reply::Reply::new();
            s.cnodes[0].0[4] = Cte::with_cap(&Cap::Reply {
                ptr: KernelState::reply_ptr(reply_idx),
                can_grant: true,
            });
            s.sched_contexts[caller_sc] =
                crate::sched_context::SchedContext::new(/* period */ 10, /* budget */ 10);
            s.sched_contexts[server_sc] =
                crate::sched_context::SchedContext::new(/* period */ 10, /* budget */ 10);

            let mut caller_t = crate::tcb::Tcb::default();
            caller_t.priority = 80;
            caller_t.state = crate::tcb::ThreadStateType::BlockedOnReply;
            caller_t.sc = Some(caller_sc as u16);
            let caller = s.scheduler.admit(caller_t);
            s.sched_contexts[caller_sc].bound_tcb = Some(caller);

            let mut server_t = crate::tcb::Tcb::default();
            server_t.priority = 100;
            server_t.state = crate::tcb::ThreadStateType::Running;
            server_t.sc = Some(server_sc as u16);
            server_t.active_sc = Some(caller_sc as u16);
            server_t.reply_to = Some(caller);
            let server = s.scheduler.admit(server_t);
            s.sched_contexts[server_sc].bound_tcb = Some(server);
            s.replies[reply_idx].bound_tcb = Some(caller);
            s.scheduler.set_current(Some(invoker));
            (caller, server)
        };

        let root_cnode = Cap::CNode {
            ptr: KernelState::cnode_ptr(0),
            radix: 5,
            guard_size: 59,
            guard: 0,
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeDelete as u64) << 12,
            a2: 4,
            ..Default::default()
        };
        decode_invocation(root_cnode, &args, invoker).expect("delete bound reply");
        unsafe {
            let s = KERNEL.get();
            let server_t = s.scheduler.slab.get(server);
            assert_eq!(server_t.reply_to, None);
            assert_eq!(server_t.active_sc, None);
            assert_eq!(server_t.sc, Some(server_sc as u16));
            assert_eq!(s.replies[reply_idx].bound_tcb, None);
            assert_eq!(s.scheduler.current(), Some(invoker));
            s.scheduler.slab.free(caller);
            s.scheduler.slab.free(server);
            s.sched_contexts[caller_sc] = crate::sched_context::SchedContext::new(0, 0);
            s.sched_contexts[server_sc] = crate::sched_context::SchedContext::new(0, 0);
            s.scheduler.reset_queues();
        }
        teardown_invoker(invoker);
        arch::log("  ✓ Reply delete clears receiver call state\n");
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
                radix: 5,
                guard_size: 59,
                guard: 0,
            };
            s.cnodes[0].0[1] = Cte::with_cap(&new_cnode_cap);
            s.cnodes[0].0[2] = Cte::with_cap(&Cap::Notification {
                ptr: KernelState::ntfn_ptr(5),
                badge: crate::cap::Badge(0),
                rights: crate::cap::NotificationRights {
                    can_send: true,
                    can_receive: true,
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
        assert!(matches!(
            r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_DeleteFirst
            }))
        ));

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
        use crate::cap::Pml4Storage;

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
        unsafe {
            KERNEL.get().cnodes[0].0[3] = Cte::with_cap(&pml4_cap);
        }

        // SetSpace(fault_ep=0, cnode_cptr=0, vspace_cptr=3)
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBSetSpace as u64) << 12,
            a2: 0,
            a3: 0,
            a4: 3,
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
                radix: 5,
                guard_size: 59,
                guard: 0,
            });
        }
        let args = SyscallArgs {
            a1: (InvocationLabel::TCBSetSpace as u64) << 12,
            a2: 0,
            a3: 0,
            a4: 4,
            ..Default::default()
        };
        let r = decode_invocation(target_cap, &args, invoker);
        assert!(matches!(
            r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_InvalidCapability
            }))
        ));
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
            radix: 5,
            guard_size: 59,
            guard: 0,
        };
        let pml4_paddr = 0x0000_0000_00DD_0000u64;
        let pml4_cap = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(pml4_paddr).unwrap(),
            mapped: true,
            asid: 0,
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
                ptr: PAddr::<UntypedStorage>::new(0x0060_0000),
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

        // Re-binding the SC (or another SC to this TCB) →
        // IllegalOperation (upstream decodeSchedContext_Bind;
        // SCHED_CONTEXT_0003).
        let r = decode_invocation(sc_cap, &args, invoker);
        assert!(matches!(
            r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_IllegalOperation
            }))
        ));

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

    #[inline(never)]
    fn sched_context_consumed_and_runtime_reports() {
        let invoker = setup_invoker(0);
        let (sc_idx, sc_cap) = unsafe {
            let s = KERNEL.get();
            let sc_idx = s.alloc_sched_context().expect("SC pool");
            let sc = &mut s.sched_contexts[sc_idx];
            *sc = crate::sched_context::SchedContext::new(10, 10);
            sc.consumed = 9;
            sc.bound_consumed = 7;
            sc.donated_consumed = 2;
            (
                sc_idx,
                Cap::SchedContext {
                    ptr: KernelState::sched_context_ptr(sc_idx),
                    size_bits: crate::object_type::MIN_SCHED_CONTEXT_BITS as u8,
                },
            )
        };

        let consumed = SyscallArgs {
            a1: (InvocationLabel::SchedContextConsumed as u64) << 12,
            ..Default::default()
        };
        decode_invocation(sc_cap, &consumed, invoker).expect("Consumed");
        unsafe {
            let s = KERNEL.get();
            let inv = s.scheduler.slab.get(invoker);
            assert_eq!(inv.ipc_length, 1);
            assert_eq!(inv.msg_regs[0], 9_000);
            assert_eq!(s.sched_contexts[sc_idx].consumed, 0);
            assert_eq!(s.sched_contexts[sc_idx].bound_consumed, 7);
            assert_eq!(s.sched_contexts[sc_idx].donated_consumed, 2);
        }

        let runtime = SyscallArgs {
            a1: (InvocationLabel::SchedContextReadRuntime as u64) << 12,
            ..Default::default()
        };
        decode_invocation(sc_cap, &runtime, invoker).expect("ReadRuntime");
        unsafe {
            let s = KERNEL.get();
            let inv = s.scheduler.slab.get(invoker);
            assert_eq!(inv.ipc_length, 2);
            assert_eq!(inv.msg_regs[0], 7_000);
            assert_eq!(inv.msg_regs[1], 2_000);
            s.free_sched_context(sc_idx);
        }

        teardown_invoker(invoker);
        arch::log("  ✓ SchedContext consumed reset + cumulative runtime split\n");
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
                ptr: PAddr::<UntypedStorage>::new(0x0070_0000),
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
            KERNEL.get().cnodes[0].0[9] = Cte::with_cap(&Cap::SchedControl { core: 0 });
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
            Cap::SchedContext { ptr, .. } => KernelState::sched_context_index(ptr),
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
        assert!(matches!(
            r,
            Err(KException::SyscallError(SyscallError {
                code: seL4_Error::seL4_RangeError
            }))
        ));

        teardown_invoker(invoker);
        arch::log("  ✓ SchedControl::ConfigureFlags sets period/budget\n");
    }

    #[inline(never)]
    fn unsupported_label_returns_illegal() {
        let invoker = setup_invoker(0);
        let cnode_cap = unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root };
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
