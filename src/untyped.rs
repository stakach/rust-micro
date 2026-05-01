//! Untyped retype — the algorithmic core of seL4's memory allocator.
//!
//! An `Untyped` cap is a chunk of contiguous physical memory the
//! kernel hasn't yet committed to a specific object type. The user
//! invokes `Retype` on the cap to carve out N children of a chosen
//! type and have caps to them written into a target CNode.
//!
//! This module implements the carving math and the per-type cap
//! construction. Memory access (writing the resulting caps into
//! destination CTEs) happens in the caller — the function takes a
//! callback so it can be exercised from specs without exposing real
//! pointers.
//!
//! Mirrors `seL4/src/object/untyped.c::Untyped_Retype` plus the
//! validation in `decodeUntypedInvocation`.

use crate::cap::{
    Cap, CNodeStorage, EndpointObj, EndpointRights, NotificationObj,
    NotificationRights, PPtr, Tcb, UntypedStorage, Badge,
};
use crate::object_type::{size_in_bits, ObjectType, SizeError};
use crate::region::align_up;
use crate::types::seL4_Word as Word;

/// Mutable state of an Untyped that callers must update on success.
/// Mirrors the `capFreeIndex` / `capBlockSize` / `capIsDevice` /
/// `capPtr` fields of `untyped_cap`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct UntypedState {
    pub base: u64,
    pub block_bits: u32,
    /// Bytes consumed so far from `base`. Always ≤ `1 << block_bits`.
    pub free_index_bytes: u64,
    pub is_device: bool,
}

impl UntypedState {
    pub const fn new(base: u64, block_bits: u32, is_device: bool) -> Self {
        Self { base, block_bits, free_index_bytes: 0, is_device }
    }
    pub const fn total_bytes(&self) -> u64 {
        1u64 << self.block_bits
    }
    pub const fn remaining_bytes(&self) -> u64 {
        self.total_bytes() - self.free_index_bytes
    }
    /// Encode back into a `Cap::Untyped`.
    pub fn to_cap(&self) -> Cap {
        // PPtr requires non-zero, but a 0-base untyped is degenerate
        // and only used in tests. Force a sentinel to keep the type
        // total. Callers should never construct an Untyped at addr 0
        // in production.
        let ptr = PPtr::<UntypedStorage>::new(self.base.max(1)).unwrap();
        Cap::Untyped {
            ptr,
            block_bits: self.block_bits as u8,
            free_index: self.free_index_bytes,
            is_device: self.is_device,
        }
    }
    pub fn from_cap(cap: &Cap) -> Option<Self> {
        match cap {
            Cap::Untyped { ptr, block_bits, free_index, is_device } => Some(Self {
                base: ptr.addr(),
                block_bits: *block_bits as u32,
                free_index_bytes: *free_index,
                is_device: *is_device,
            }),
            _ => None,
        }
    }
}

/// Errors `retype` can return. Map directly onto seL4 syscall errors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RetypeError {
    /// `user_size_bits` outside the legal range for the requested
    /// type, or `num_objects` exceeds the type's range.
    RangeError,
    /// We don't yet support retyping to this type.
    InvalidArgument,
    /// `num_objects << size_bits` would overflow a `u64`, or the
    /// requested layout doesn't fit in the untyped.
    NotEnoughMemory,
    /// Device-memory untypeds can only produce sub-untyped or frame
    /// caps; everything else needs ordinary RAM.
    IllegalOperationDeviceMemory,
}

impl From<SizeError> for RetypeError {
    fn from(e: SizeError) -> Self {
        match e {
            SizeError::OutOfRange { .. } => RetypeError::RangeError,
            SizeError::Unsupported => RetypeError::InvalidArgument,
        }
    }
}

/// Carve `num_objects` children of size `user_size_bits` (where
/// applicable) out of `untyped`. On success, `emit_child` is called
/// once per child with the constructed cap, in slot order.
///
/// On any error, `untyped`'s state is left untouched.
pub fn retype(
    untyped: &mut UntypedState,
    obj_ty: ObjectType,
    user_size_bits: u32,
    num_objects: u64,
    mut emit_child: impl FnMut(Cap),
) -> Result<(), RetypeError> {
    if num_objects == 0 {
        // seL4 treats this as a successful no-op, but we keep it as
        // a hard reject so callers don't accidentally request zero.
        // It's cheaper to fail loudly here than to debug an empty
        // CNode later.
        return Err(RetypeError::RangeError);
    }
    let obj_bits = size_in_bits(obj_ty, user_size_bits)?;

    // Device memory may only produce sub-untypeds (and, in a future
    // phase, Frame caps that propagate the device flag).
    if untyped.is_device && !matches!(obj_ty, ObjectType::Untyped) {
        return Err(RetypeError::IllegalOperationDeviceMemory);
    }

    // Total bytes needed = num_objects * 2^obj_bits. Check both for
    // overflow of u64 and for fit inside the untyped block.
    let per_object = checked_pow2(obj_bits)?;
    let total = num_objects
        .checked_mul(per_object)
        .ok_or(RetypeError::NotEnoughMemory)?;
    let total_max = checked_pow2(untyped.block_bits)?;
    if total > total_max {
        return Err(RetypeError::NotEnoughMemory);
    }

    // Align the next-free pointer up to the object's natural
    // alignment. For 2^N-sized objects, alignment is 2^N — a no-op
    // when retype starts at offset 0 from a fresh untyped.
    let aligned_offset = align_up(untyped.free_index_bytes, obj_bits);
    let new_free_index = aligned_offset
        .checked_add(total)
        .ok_or(RetypeError::NotEnoughMemory)?;
    if new_free_index > total_max {
        return Err(RetypeError::NotEnoughMemory);
    }

    // Looks good — build child caps, then commit free_index.
    for i in 0..num_objects {
        let offset_in_untyped = aligned_offset + i * per_object;
        let object_addr = untyped.base + offset_in_untyped;
        let cap = make_object_cap(obj_ty, user_size_bits, object_addr, untyped.is_device)?;
        emit_child(cap);
    }
    untyped.free_index_bytes = new_free_index;
    Ok(())
}

/// Construct the cap for a freshly-retyped object. Defaults match
/// what seL4 stamps for newly created caps:
///   - full rights everywhere
///   - badge 0
///   - mapped/unmapped flags cleared
///   - sub-untypeds inherit the parent's device flag and start at
///     free_index = 0.
fn make_object_cap(
    ty: ObjectType,
    user_size_bits: u32,
    obj_addr: u64,
    parent_is_device: bool,
) -> Result<Cap, RetypeError> {
    match ty {
        ObjectType::Untyped => {
            let ptr = PPtr::<UntypedStorage>::new(obj_addr)
                .ok_or(RetypeError::InvalidArgument)?;
            Ok(Cap::Untyped {
                ptr,
                block_bits: user_size_bits as u8,
                free_index: 0,
                is_device: parent_is_device,
            })
        }
        ObjectType::CapTable => {
            let ptr = PPtr::<CNodeStorage>::new(obj_addr)
                .ok_or(RetypeError::InvalidArgument)?;
            Ok(Cap::CNode {
                ptr,
                radix: user_size_bits as u8,
                guard_size: 0,
                guard: 0,
            })
        }
        ObjectType::Tcb => {
            let tcb = PPtr::<Tcb>::new(obj_addr)
                .ok_or(RetypeError::InvalidArgument)?;
            Ok(Cap::Thread { tcb })
        }
        ObjectType::Endpoint => {
            let ptr = PPtr::<EndpointObj>::new(obj_addr)
                .ok_or(RetypeError::InvalidArgument)?;
            Ok(Cap::Endpoint {
                ptr,
                badge: Badge(0),
                rights: EndpointRights {
                    can_send: true,
                    can_receive: true,
                    can_grant: true,
                    can_grant_reply: true,
                },
            })
        }
        ObjectType::Notification => {
            let ptr = PPtr::<NotificationObj>::new(obj_addr)
                .ok_or(RetypeError::InvalidArgument)?;
            Ok(Cap::Notification {
                ptr,
                badge: Badge(0),
                rights: NotificationRights {
                    can_send: true,
                    can_receive: true,
                },
            })
        }
        ObjectType::SchedContext | ObjectType::Reply => {
            Err(RetypeError::InvalidArgument)
        }
        ObjectType::Arch(t) => {
            // x86_64 frame types — see object_type::X86_* constants.
            use crate::cap::{FrameRights, FrameSize, FrameStorage};
            use crate::object_type::{X86_1G, X86_2M, X86_4K};
            let size = match t {
                X86_4K => FrameSize::Small,
                X86_2M => FrameSize::Large,
                X86_1G => FrameSize::Huge,
                _ => return Err(RetypeError::InvalidArgument),
            };
            let ptr = PPtr::<FrameStorage>::new(obj_addr)
                .ok_or(RetypeError::InvalidArgument)?;
            Ok(Cap::Frame {
                ptr,
                size,
                // Newly retyped frames have full rights; mapping
                // narrows them.
                rights: FrameRights::ReadWrite,
                mapped: None,
                asid: 0,
                is_device: parent_is_device,
            })
        }
    }
}

/// Compute `1 << bits` with overflow checking. `bits == 64` overflows
/// a `u64`; we treat that as a NotEnoughMemory error since no
/// practical untyped is that large.
fn checked_pow2(bits: u32) -> Result<u64, RetypeError> {
    if bits >= 64 {
        Err(RetypeError::NotEnoughMemory)
    } else {
        Ok(1u64 << bits)
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::cap::{Cap, CNodeStorage, EndpointObj, EndpointRights, PPtr, Badge};
    use crate::cspace::{lookup_cap, CSpace};
    use crate::cte::Cte;

    pub fn test_untyped() {
        arch::log("Running untyped retype tests...\n");

        retype_into_endpoints();
        retype_into_cnode_then_lookup();
        free_index_alignment();
        not_enough_memory();
        device_memory_restrictions();
        zero_objects_rejected();

        arch::log("Untyped retype tests completed\n");
    }

    fn retype_into_endpoints() {
        // 4 KiB untyped at 0x100_000. Carve out 8 endpoints
        // (16 bytes each = 128 bytes total).
        let mut ut = UntypedState::new(0x0010_0000, 12, false);
        let mut caps: [Cap; 8] = [Cap::Null; 8];
        let mut idx = 0;
        retype(&mut ut, ObjectType::Endpoint, 0, 8, |cap| {
            caps[idx] = cap;
            idx += 1;
        })
        .expect("retype to endpoints");
        assert_eq!(idx, 8);
        // Each child sits at base + i*16.
        for (i, cap) in caps.iter().enumerate() {
            match cap {
                Cap::Endpoint { ptr, badge, rights } => {
                    assert_eq!(ptr.addr(), 0x0010_0000 + (i as u64) * 16);
                    assert_eq!(*badge, Badge(0));
                    // Newly retyped endpoints have all rights.
                    assert!(rights.can_send && rights.can_receive
                            && rights.can_grant && rights.can_grant_reply);
                }
                _ => panic!("expected endpoint, got {:?}", cap),
            }
        }
        // Free index advanced by exactly 128 bytes.
        assert_eq!(ut.free_index_bytes, 128);
        arch::log("  ✓ retype produces N endpoint caps with full rights\n");
    }

    fn retype_into_cnode_then_lookup() {
        // Real-world flow: retype an untyped into a CNode cap, set
        // up a CSpace pointing at a real backing store at the
        // freshly-allocated address, write a cap into one of its
        // slots, look it up.
        let cnode_base: u64 = 0x0020_0000;
        let mut ut = UntypedState::new(cnode_base, 12, false);

        // Retype 1 CNode of radix 4 (16 slots, 512 bytes total = 9 bits).
        let mut produced: Option<Cap> = None;
        retype(&mut ut, ObjectType::CapTable, 4, 1, |cap| produced = Some(cap))
            .expect("retype to CNode");
        let cnode_cap = produced.unwrap();
        let (ptr, radix) = match cnode_cap {
            Cap::CNode { ptr, radix, .. } => (ptr, radix),
            _ => panic!("expected CNode cap"),
        };
        assert_eq!(ptr.addr(), cnode_base);
        assert_eq!(radix, 4);
        assert_eq!(ut.free_index_bytes, 512);

        // Build the backing CTE store and a TestCSpace mapping the
        // returned PPtr → those slots.
        let mut slots = [Cte::null(); 16];
        let target = Cap::Endpoint {
            ptr: PPtr::<EndpointObj>::new(0xFFFF_8000_BABE_0000).unwrap(),
            badge: Badge(0xC0FFEE),
            rights: EndpointRights {
                can_send: true, can_receive: true,
                can_grant: false, can_grant_reply: false,
            },
        };
        slots[3] = Cte::with_cap(&target);

        struct OneNode<'a> {
            ptr: PPtr<CNodeStorage>,
            slots: &'a [Cte],
        }
        impl<'a> CSpace for OneNode<'a> {
            fn cnode_at(&self, ptr: PPtr<CNodeStorage>, _: usize) -> Option<&[Cte]> {
                if ptr == self.ptr { Some(self.slots) } else { None }
            }
        }
        let cspace = OneNode { ptr, slots: &slots };

        // Use the freshly retyped CNode as the root of a tiny CSpace
        // and look up slot 3. With radix=4 / guard_size=60 / guard=0
        // and n_bits=64, levelBits=64, so the index uses the low 4
        // bits of the cptr. CPtr=3 picks slot 3.
        let root = Cap::CNode { ptr, radix: 4, guard_size: 60, guard: 0 };
        let found = lookup_cap(&cspace, &root, 3).expect("lookup ok");
        assert_eq!(found, target);
        arch::log("  ✓ retype → CNode → write slot → lookup_cap end-to-end\n");
    }

    fn free_index_alignment() {
        // After carving 1 endpoint (16 bytes) from a fresh 4 KiB
        // untyped, retype a second time for a notification (32 byte
        // alignment): the next-free pointer must round UP to 32.
        let mut ut = UntypedState::new(0x0030_0000, 12, false);
        let mut sink = |_| {};
        retype(&mut ut, ObjectType::Endpoint, 0, 1, &mut sink).unwrap();
        assert_eq!(ut.free_index_bytes, 16);
        retype(&mut ut, ObjectType::Notification, 0, 1, &mut sink).unwrap();
        // Notification is 32 bytes, must align to 32 → carve at 32.
        // free_index becomes 32 + 32 = 64.
        assert_eq!(ut.free_index_bytes, 64);
        arch::log("  ✓ free index re-aligned for next type\n");
    }

    fn not_enough_memory() {
        // 4 KiB untyped (12 bits). Asking for 1 endpoint of 4 KiB
        // size has no slack, but 5 KiB does — request something we
        // know overflows.
        let mut ut = UntypedState::new(0x0040_0000, 12, false);
        let err = retype(&mut ut, ObjectType::Endpoint, 0, /* num */ 257, |_| {})
            .unwrap_err();
        assert_eq!(err, RetypeError::NotEnoughMemory);
        // Untyped state untouched on failure.
        assert_eq!(ut.free_index_bytes, 0);
        arch::log("  ✓ NotEnoughMemory leaves the untyped untouched\n");
    }

    fn device_memory_restrictions() {
        let mut ut = UntypedState::new(0xFEC0_0000, 12, /* is_device */ true);
        // Endpoint, TCB, etc. cannot come from device memory.
        assert_eq!(
            retype(&mut ut, ObjectType::Endpoint, 0, 1, |_| {}).unwrap_err(),
            RetypeError::IllegalOperationDeviceMemory,
        );
        assert_eq!(
            retype(&mut ut, ObjectType::CapTable, 4, 1, |_| {}).unwrap_err(),
            RetypeError::IllegalOperationDeviceMemory,
        );
        // A sub-untyped IS allowed and inherits the device flag.
        let mut child = None;
        retype(&mut ut, ObjectType::Untyped, 8, 1, |c| child = Some(c)).unwrap();
        match child.unwrap() {
            Cap::Untyped { is_device: true, block_bits: 8, .. } => {}
            other => panic!("expected device sub-untyped, got {:?}", other),
        }
        arch::log("  ✓ device memory restricts to Untyped descendants only\n");
    }

    fn zero_objects_rejected() {
        let mut ut = UntypedState::new(0x0050_0000, 12, false);
        assert_eq!(
            retype(&mut ut, ObjectType::Endpoint, 0, 0, |_| {}).unwrap_err(),
            RetypeError::RangeError,
        );
        arch::log("  ✓ num_objects = 0 rejected as RangeError\n");
    }
}
