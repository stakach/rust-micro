//! Object types and their sizes.
//!
//! When userspace asks an Untyped to `Retype` into N children, it
//! supplies an `ObjectType` (e.g. `Endpoint`, `CapTable`) and a
//! `user_size_bits` that's only meaningful for variable-sized
//! objects. The kernel's job is to translate that into a concrete
//! size in bits-of-bytes, then reserve `num_objects << size_bits`
//! bytes from the untyped's free range.
//!
//! This module owns that translation. Numeric tag values match
//! `seL4_ObjectType` so userspace passes them straight through; the
//! arch-specific tags above `seL4_NonArchObjectTypeCount` are handled
//! by a future arch dispatcher and currently surface as
//! `ObjectType::Arch(raw)`.

use crate::types::seL4_Word as Word;

// ---------------------------------------------------------------------------
// Per-type constant sizes. See seL4/include/object/structures.h and the
// arch-specific structures.h for the C-side equivalents. We only
// need the non-arch sizes here; arch types lands in Phase 8.
// ---------------------------------------------------------------------------

/// log2(bytes) of a TCB. seL4's tcb_t is 2 KiB (11 bits) on x86_64
/// without MCS; the half above the TCB pointer holds the kernel-side
/// part, the half below holds the user-saved registers.
pub const TCB_SIZE_BITS: u32 = 11;

/// log2(bytes) of an Endpoint.
pub const ENDPOINT_SIZE_BITS: u32 = 4;

/// log2(bytes) of a Notification (non-MCS).
pub const NOTIFICATION_SIZE_BITS: u32 = 5;

/// log2(bytes) of one CTE.
pub const CTE_SIZE_BITS: u32 = 5;

/// Smallest CNode (radix 1, two slots).
pub const MIN_CNODE_SIZE_BITS: u32 = 1;

/// Largest meaningful CNode size — half the address space minus
/// CTE_SIZE_BITS (a sane upper bound; seL4 enforces this via
/// CONFIG-driven limit, we use 38 bits for now to avoid overflow).
pub const MAX_CNODE_SIZE_BITS: u32 = 38;

/// Smallest legal Untyped: 4 bytes (libsel4 enforces ≥ word).
pub const MIN_UNTYPED_SIZE_BITS: u32 = 4;
/// Largest legal Untyped — the full virtual word size.
pub const MAX_UNTYPED_SIZE_BITS: u32 = 47;

/// Phase 32b — minimum size for a SchedContext object. seL4 uses 8
/// bits (256 bytes) as the smallest size that fits the SC header
/// plus a couple of refills.
pub const MIN_SCHED_CONTEXT_BITS: u32 = 8;
/// Largest sensible SchedContext — bounded to keep the field width
/// (`capSCSizeBits`, 6 bits) addressable.
pub const MAX_SCHED_CONTEXT_BITS: u32 = 16;

// x86_64 arch object types — these sit above
// `seL4_NonArchObjectTypeCount` in libsel4. Numbered to match
// seL4's `seL4_X86_*Object` ordering.
pub const X86_4K: u64 = 7;
pub const X86_2M: u64 = 8;
pub const X86_1G: u64 = 9;
/// 4 KiB page table — backs `Cap::PageTable` (PT, 512 PTEs).
pub const X86_PAGE_TABLE: u64 = 10;
/// 4 KiB page directory — backs `Cap::PageDirectory` (PD, 512 PDEs).
pub const X86_PAGE_DIRECTORY: u64 = 11;
/// 4 KiB page-directory-pointer table — backs `Cap::Pdpt`.
pub const X86_PDPT: u64 = 12;
/// 4 KiB page-map-level-4 — backs `Cap::PML4` (vspace root).
pub const X86_PML4: u64 = 13;

// ---------------------------------------------------------------------------
// ObjectType enum.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ObjectType {
    Untyped,
    Tcb,
    Endpoint,
    Notification,
    /// CNode (a.k.a. CapTable). Variable size — caller supplies
    /// `user_size_bits` = log2(slot_count).
    CapTable,
    /// MCS only — placeholder so the discriminants line up.
    SchedContext,
    /// MCS only.
    Reply,
    /// Arch-specific tag, kept opaque until Phase 8 lands the arch
    /// retype dispatcher.
    Arch(Word),
}

impl ObjectType {
    /// Decode the user-supplied tag word. Mirrors seL4's
    /// `Arch_isFrameType` / object type dispatch — values 0..6 match
    /// `seL4_ObjectType` exactly; everything else falls through to
    /// `Arch`.
    pub const fn from_word(t: Word) -> Self {
        match t {
            0 => ObjectType::Untyped,
            1 => ObjectType::Tcb,
            2 => ObjectType::Endpoint,
            3 => ObjectType::Notification,
            4 => ObjectType::CapTable,
            5 => ObjectType::SchedContext,
            6 => ObjectType::Reply,
            t => ObjectType::Arch(t),
        }
    }

    pub const fn to_word(self) -> Word {
        match self {
            ObjectType::Untyped => 0,
            ObjectType::Tcb => 1,
            ObjectType::Endpoint => 2,
            ObjectType::Notification => 3,
            ObjectType::CapTable => 4,
            ObjectType::SchedContext => 5,
            ObjectType::Reply => 6,
            ObjectType::Arch(t) => t,
        }
    }

    /// True for object types whose size depends on `user_size_bits`
    /// rather than a fixed constant. Used to validate user input
    /// before retype.
    pub const fn is_variable_sized(self) -> bool {
        matches!(self, ObjectType::Untyped | ObjectType::CapTable)
    }
}

/// Reasons `size_in_bits` may reject the request.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SizeError {
    /// `user_size_bits` is outside the legal range for this type.
    OutOfRange { min: u32, max: u32 },
    /// We don't yet support retyping to this object type.
    Unsupported,
}

/// Translate `(object_type, user_size_bits) → size_in_bits` (i.e.
/// log2(bytes-per-object)). For fixed-size objects `user_size_bits`
/// is ignored.
pub fn size_in_bits(ty: ObjectType, user_size_bits: u32) -> Result<u32, SizeError> {
    match ty {
        ObjectType::Untyped => bounds_check(user_size_bits, MIN_UNTYPED_SIZE_BITS, MAX_UNTYPED_SIZE_BITS),
        ObjectType::CapTable => {
            bounds_check(user_size_bits, MIN_CNODE_SIZE_BITS, MAX_CNODE_SIZE_BITS)?;
            // The CTE is 2^5 bytes; total bytes = 2^(user_size_bits +
            // CTE_SIZE_BITS).
            Ok(user_size_bits + CTE_SIZE_BITS)
        }
        ObjectType::Tcb => Ok(TCB_SIZE_BITS),
        ObjectType::Endpoint => Ok(ENDPOINT_SIZE_BITS),
        ObjectType::Notification => Ok(NOTIFICATION_SIZE_BITS),
        // Phase 32b — SchedContext is variable-sized: caller supplies
        // `user_size_bits` (= log2(bytes), at least
        // `MIN_SCHED_CONTEXT_BITS`). seL4's minimum is 8 (256 B);
        // the budget rises with size because each refill is ~16 B.
        ObjectType::SchedContext => {
            bounds_check(user_size_bits, MIN_SCHED_CONTEXT_BITS, MAX_SCHED_CONTEXT_BITS)
        }
        ObjectType::Reply => Err(SizeError::Unsupported),
        ObjectType::Arch(t) => match t {
            X86_4K => Ok(12),
            X86_2M => Ok(21),
            X86_1G => Ok(30),
            // PT/PD/PDPT/PML4 are each one 4 KiB page of bitfield entries.
            X86_PAGE_TABLE | X86_PAGE_DIRECTORY | X86_PDPT | X86_PML4 => Ok(12),
            _ => Err(SizeError::Unsupported),
        },
    }
}

fn bounds_check(value: u32, min: u32, max: u32) -> Result<u32, SizeError> {
    if value < min || value > max {
        Err(SizeError::OutOfRange { min, max })
    } else {
        Ok(value)
    }
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_object_type() {
        arch::log("Running object_type tests...\n");
        roundtrip();
        sizes();
        bounds();
        arch::log("object_type tests completed\n");
    }

    fn roundtrip() {
        for w in 0u64..7 {
            assert_eq!(ObjectType::from_word(w).to_word(), w);
        }
        // Arch passes through.
        assert_eq!(ObjectType::from_word(99).to_word(), 99);
        match ObjectType::from_word(99) {
            ObjectType::Arch(99) => {}
            _ => panic!("Arch passthrough failed"),
        }
        arch::log("  ✓ ObjectType from_word/to_word round-trip\n");
    }

    fn sizes() {
        assert_eq!(size_in_bits(ObjectType::Endpoint, 0), Ok(ENDPOINT_SIZE_BITS));
        assert_eq!(size_in_bits(ObjectType::Notification, 0), Ok(NOTIFICATION_SIZE_BITS));
        assert_eq!(size_in_bits(ObjectType::Tcb, 0), Ok(TCB_SIZE_BITS));
        // CapTable: total = user_size_bits + 5 (CTE = 32 bytes).
        // Radix 4 → 16 slots → 16 * 32 = 512 bytes → 9 bits.
        assert_eq!(size_in_bits(ObjectType::CapTable, 4), Ok(9));
        assert_eq!(size_in_bits(ObjectType::Untyped, 12), Ok(12));
        arch::log("  ✓ size_in_bits matches seL4's per-type sizes\n");
    }

    fn bounds() {
        // CNode of radix 0 is illegal (would be a 32-byte block with
        // a single slot — seL4 rejects it).
        assert!(matches!(
            size_in_bits(ObjectType::CapTable, 0),
            Err(SizeError::OutOfRange { .. })
        ));
        // Untyped of size_bits 1 is below the 4-bit minimum.
        assert!(matches!(
            size_in_bits(ObjectType::Untyped, 1),
            Err(SizeError::OutOfRange { .. })
        ));
        // Phase 32b — SchedContext is variable-sized. user_size_bits
        // below `MIN_SCHED_CONTEXT_BITS` is rejected as OutOfRange;
        // legal sizes return the size_bits unchanged.
        assert!(matches!(
            size_in_bits(ObjectType::SchedContext, 0),
            Err(SizeError::OutOfRange { .. })
        ));
        assert_eq!(
            size_in_bits(ObjectType::SchedContext, MIN_SCHED_CONTEXT_BITS),
            Ok(MIN_SCHED_CONTEXT_BITS)
        );
        // Reply still has no Untyped::Retype path (kernel allocates).
        assert!(matches!(
            size_in_bits(ObjectType::Reply, 0),
            Err(SizeError::Unsupported)
        ));
        arch::log("  ✓ size_in_bits rejects out-of-range and unsupported\n");
    }
}
