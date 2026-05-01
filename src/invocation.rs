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
        let mut emit_idx = dest_offset;
        let result = crate::untyped::retype(
            &mut state, object_type, size_bits, num_objects,
            |cap| {
                cnode_slots[emit_idx].set_cap(&cap);
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

/// CNode::Revoke — delete every cap "derived from" the cap at
/// `(target_cnode, src_index)`. Without a full MDB we identify
/// descendants by inspecting cap contents: anything that points
/// at the same kernel object (or, for Untyped, falls inside the
/// untyped's physical range) is a descendant. The source slot
/// itself is left intact — Revoke deletes the children only;
/// callers use CNodeDelete to remove the source.
fn cnode_revoke(target: Cap, args: &SyscallArgs, _invoker: TcbId) -> KResult<()> {
    let src_index = args.a2 as usize;
    let cnode_ptr = match target {
        Cap::CNode { ptr, .. } => ptr,
        _ => unreachable!(),
    };
    unsafe {
        let s = KERNEL.get();
        let cnode_idx = KernelState::cnode_index(cnode_ptr);
        let source_cap = if src_index < s.cnodes[cnode_idx].0.len() {
            s.cnodes[cnode_idx].0[src_index].cap()
        } else {
            return Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_RangeError,
            )));
        };

        // Walk every CTE in every CNode in the slab. For each cap
        // that "is_derived_from" the source, zero it. Skip the
        // source slot itself.
        for ci in 0..s.cnodes.len() {
            for si in 0..s.cnodes[ci].0.len() {
                if ci == cnode_idx && si == src_index {
                    continue;
                }
                let cap = s.cnodes[ci].0[si].cap();
                if is_derived_from(&cap, &source_cap) {
                    s.cnodes[ci].0[si].set_cap(&Cap::Null);
                }
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
                Reply { tcb, .. } => inside(tcb.addr()),
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
    _invoker: TcbId,
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
        unsupported_label_returns_illegal();
        arch::log("Invocation tests completed\n");
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

        // Slots 4..7 each hold an Endpoint cap.
        unsafe {
            let s = KERNEL.get();
            for i in 4..8 {
                match s.cnodes[0].0[i].cap() {
                    Cap::Endpoint { ptr, .. } => {
                        // Endpoints sit at base + i*16.
                        let expect = untyped_base + ((i - 4) as u64) * 16;
                        assert_eq!(ptr.addr(), expect);
                    }
                    other => panic!("expected endpoint at {i}, got {:?}", other),
                }
            }
            // The Untyped's free_index advanced.
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

        // Retype 4 endpoints into slots 4..7.
        let args = SyscallArgs {
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: ObjectType::Endpoint.to_word(),
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
