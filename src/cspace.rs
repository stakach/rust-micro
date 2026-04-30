//! CSpace lookup. Mirrors `seL4/src/kernel/cspace.c`'s
//! `resolveAddressBits`, `lookupSlot`, `lookupCap`.
//!
//! A CPtr is a 64-bit address into a tree of CNodes. Each level of
//! the tree consumes `guard_size + radix` bits: `guard_size` of guard
//! pattern (which must match the CNode's recorded guard exactly), and
//! `radix` of slot index.
//!
//! Memory access is abstracted via the `CSpace` trait: callers
//! provide a function from `PPtr<CNodeStorage>` to `&[Cte]`. In the
//! production kernel that becomes a single small `unsafe` helper that
//! turns a kernel-mapped address into a slice. The specs implement
//! the trait with a static table — no `unsafe` needed in this
//! module's logic, only in callers that bridge from raw pointers.

use crate::cap::{Cap, CNodeStorage, PPtr};
use crate::cte::Cte;
use crate::types::seL4_Word as Word;

pub const WORD_BITS: u32 = 64;

/// `lookup_fault_t` from libsel4. Mirrors the four variants the
/// kernel manual documents.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum LookupFault {
    /// Root cap was not a CNode.
    InvalidRoot,
    /// We bottomed out before consuming all the address bits, with
    /// `bits_left` still to go.
    MissingCapability { bits_left: u32 },
    /// The remaining bits aren't enough to cover the next level
    /// (`bits_found = guard_size + radix`).
    DepthMismatch { bits_left: u32, bits_found: u32 },
    /// The CPtr's guard portion didn't match the CNode's recorded
    /// guard. The lookup fault carries the *expected* guard from
    /// the cap, not what the CPtr supplied.
    GuardMismatch { bits_left: u32, guard_found: Word, guard_size: u32 },
}

/// Result of a successful (or partially-successful) address-bits
/// resolution. `bits_remaining > 0` means we stopped early at a
/// non-CNode cap — the caller decides whether that's an error in
/// context.
#[derive(Copy, Clone, Debug)]
pub struct ResolveResult {
    pub slot_ptr: PPtr<CNodeStorage>,
    pub slot_index: usize,
    pub bits_remaining: u32,
    /// Slot count of the CNode the slot lives in (= 1 << radix).
    /// Useful so the caller can re-fetch the slice without re-walking
    /// the tree.
    pub slot_count: usize,
}

/// Pluggable CNode storage backend.
pub trait CSpace {
    /// Return the CTE slice backing the CNode at `ptr`. The caller
    /// guarantees `count == 1 << radix` for a CNode whose `radix`
    /// matches the cap that named this storage.
    fn cnode_at(&self, ptr: PPtr<CNodeStorage>, count: usize) -> Option<&[Cte]>;
}

/// Mirrors seL4's `resolveAddressBits`. Walks the CSpace tree from
/// `node_cap` (which must be a CNode cap), consuming `n_bits` of
/// `cptr` from the most-significant end downward.
pub fn resolve_address_bits<C: CSpace>(
    cspace: &C,
    node_cap: &Cap,
    cptr: Word,
    n_bits: u32,
) -> Result<ResolveResult, LookupFault> {
    let (mut node_ptr, mut radix, mut guard_size, mut guard) = match *node_cap {
        Cap::CNode { ptr, radix, guard_size, guard } => {
            (ptr, radix as u32, guard_size as u32, guard)
        }
        _ => return Err(LookupFault::InvalidRoot),
    };
    let mut n_bits = n_bits;

    loop {
        let level_bits = radix + guard_size;
        // Per seL4: every CNode must resolve at least one bit, or the
        // walk would loop forever.
        debug_assert!(level_bits != 0, "CNode resolves zero bits");

        // Guard check. `guardBits > n_bits` means the CPtr can't
        // possibly carry enough high bits to match the guard.
        if guard_size > n_bits {
            return Err(LookupFault::GuardMismatch {
                bits_left: n_bits,
                guard_found: guard,
                guard_size,
            });
        }
        // Extract the guard bits from cptr's high end. Avoid the
        // `>> 64` C-undefined-behaviour case the seL4 source guards
        // against by checking guard_size == 0 first.
        let cptr_guard = if guard_size == 0 {
            0
        } else {
            (cptr >> (n_bits - guard_size)) & mask(guard_size)
        };
        if cptr_guard != guard {
            return Err(LookupFault::GuardMismatch {
                bits_left: n_bits,
                guard_found: guard,
                guard_size,
            });
        }

        if level_bits > n_bits {
            return Err(LookupFault::DepthMismatch {
                bits_left: n_bits,
                bits_found: level_bits,
            });
        }

        // Compute the slot index from the next `radix` bits.
        let offset_shift = n_bits - level_bits;
        let radix_mask = mask(radix);
        let offset = ((cptr >> offset_shift) & radix_mask) as usize;

        let slot_count = 1usize << radix;
        let slots = cspace
            .cnode_at(node_ptr, slot_count)
            .ok_or(LookupFault::InvalidRoot)?;
        debug_assert_eq!(slots.len(), slot_count);
        let slot = &slots[offset];

        if level_bits == n_bits {
            // Exact match — we landed on the requested slot.
            return Ok(ResolveResult {
                slot_ptr: node_ptr,
                slot_index: offset,
                bits_remaining: 0,
                slot_count,
            });
        }

        // Descend if the new slot holds another CNode; otherwise stop
        // and return the slot we ended at, with bits left over. The
        // caller (e.g. `lookup_slot_for_cnode_op`) decides whether
        // leftover bits are an error.
        n_bits -= level_bits;
        match slot.cap() {
            Cap::CNode { ptr, radix: r, guard_size: gs, guard: g } => {
                node_ptr = ptr;
                radix = r as u32;
                guard_size = gs as u32;
                guard = g;
            }
            _ => {
                return Ok(ResolveResult {
                    slot_ptr: node_ptr,
                    slot_index: offset,
                    bits_remaining: n_bits,
                    slot_count,
                });
            }
        }
    }
}

/// Convenience wrapper: resolve a full `WORD_BITS`-deep CPtr starting
/// from the given root cap, then fetch the cap stored at that slot.
pub fn lookup_cap<C: CSpace>(
    cspace: &C,
    root: &Cap,
    cptr: Word,
) -> Result<Cap, LookupFault> {
    let res = resolve_address_bits(cspace, root, cptr, WORD_BITS)?;
    if res.bits_remaining != 0 {
        // Per seL4 `lookupSlotForCNodeOp`, leftover bits with a slot
        // resolution count as a depth mismatch from the user's POV.
        return Err(LookupFault::DepthMismatch {
            bits_left: 0,
            bits_found: res.bits_remaining,
        });
    }
    let slots = cspace
        .cnode_at(res.slot_ptr, res.slot_count)
        .ok_or(LookupFault::InvalidRoot)?;
    Ok(slots[res.slot_index].cap())
}

#[inline]
const fn mask(bits: u32) -> Word {
    if bits >= WORD_BITS {
        Word::MAX
    } else {
        (1u64 << bits) - 1
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    //! Build a small CSpace by hand and exercise every branch of
    //! `resolve_address_bits`.

    use super::*;
    use crate::arch;
    use crate::cap::{Cap, CNodeStorage, EndpointObj, EndpointRights, PPtr, Badge};
    use crate::cte::Cte;

    /// Test backing-store: a fixed pair of CNodes, addressed by the
    /// `PPtr` we hand out for each.
    struct TestCSpace<'a> {
        nodes: &'a [(PPtr<CNodeStorage>, &'a [Cte])],
    }

    impl<'a> CSpace for TestCSpace<'a> {
        fn cnode_at(&self, ptr: PPtr<CNodeStorage>, _count: usize) -> Option<&[Cte]> {
            self.nodes
                .iter()
                .find(|(p, _)| *p == ptr)
                .map(|(_, slots)| *slots)
        }
    }

    pub fn test_cspace_lookup() {
        arch::log("Running CSpace lookup tests...\n");

        single_level_hit();
        guard_mismatch_returns_fault();
        depth_mismatch_returns_fault();
        invalid_root_returns_fault();
        two_level_lookup();
        non_cnode_stops_early_with_remaining_bits();

        arch::log("CSpace lookup tests completed\n");
    }

    /// Build an endpoint cap (handy as a known-distinct payload).
    fn ep_cap(addr: u64, badge: u64) -> Cap {
        Cap::Endpoint {
            ptr: PPtr::<EndpointObj>::new(addr).unwrap(),
            badge: Badge(badge),
            rights: EndpointRights {
                can_send: true,
                can_receive: true,
                can_grant: false,
                can_grant_reply: false,
            },
        }
    }

    fn single_level_hit() {
        // CNode of radix 4 (16 slots), guard_size 60, guard 0.
        // n_bits = 64 → level_bits = 64 → exact match.
        const RADIX: u8 = 4;
        const GUARD_SIZE: u8 = 60;
        let cnode_ptr = PPtr::<CNodeStorage>::new(0xCafe_0000).unwrap();

        // Populate slot 5 with a known endpoint cap.
        let mut slots = [Cte::null(); 16];
        let target = ep_cap(0xFFFF_8000_DEAD_B000, 0x1234);
        slots[5] = Cte::with_cap(&target);

        let cspace = TestCSpace { nodes: &[(cnode_ptr, &slots)] };
        let root = Cap::CNode {
            ptr: cnode_ptr,
            radix: RADIX,
            guard_size: GUARD_SIZE,
            guard: 0,
        };

        // CPtr layout: [60 guard bits=0][4 index bits=5]
        let cptr: Word = 0x0000_0000_0000_0005;
        let cap = lookup_cap(&cspace, &root, cptr).expect("lookup ok");
        assert_eq!(cap, target);
        arch::log("  ✓ single-level lookup hits the right slot\n");
    }

    fn guard_mismatch_returns_fault() {
        // guard_size 4, expected guard = 0xA. CPtr supplies a
        // different guard — must fault.
        let cnode_ptr = PPtr::<CNodeStorage>::new(0xC0DE_0000).unwrap();
        let slots = [Cte::null(); 16];
        let cspace = TestCSpace { nodes: &[(cnode_ptr, &slots)] };
        let root = Cap::CNode {
            ptr: cnode_ptr,
            radix: 4,
            guard_size: 4,
            // levelBits = 8, top 4 bits of cptr must equal 0xA.
            guard: 0xA,
        };
        // Top 4 bits = 0x5 → mismatch.
        let cptr: Word = 0x5 << 60;
        match resolve_address_bits(&cspace, &root, cptr, 8) {
            Err(LookupFault::GuardMismatch { guard_size: 4, guard_found: 0xA, .. }) => {}
            other => panic!("expected GuardMismatch, got {:?}", other),
        }
        arch::log("  ✓ guard mismatch surfaces as LookupFault::GuardMismatch\n");
    }

    fn depth_mismatch_returns_fault() {
        // levelBits = radix(4) + guard_size(4) = 8, but n_bits = 4.
        let cnode_ptr = PPtr::<CNodeStorage>::new(0xDEAD_0000).unwrap();
        let slots = [Cte::null(); 16];
        let cspace = TestCSpace { nodes: &[(cnode_ptr, &slots)] };
        let root = Cap::CNode {
            ptr: cnode_ptr,
            radix: 4,
            guard_size: 4,
            guard: 0,
        };
        match resolve_address_bits(&cspace, &root, 0, 4) {
            Err(LookupFault::DepthMismatch { bits_left: 4, bits_found: 8 }) => {}
            other => panic!("expected DepthMismatch, got {:?}", other),
        }
        arch::log("  ✓ depth mismatch surfaces as LookupFault::DepthMismatch\n");
    }

    fn invalid_root_returns_fault() {
        // Pass a non-CNode cap as root.
        let cspace = TestCSpace { nodes: &[] };
        let root = ep_cap(0xFFFF_8000_AAAA_0000, 0);
        match resolve_address_bits(&cspace, &root, 0, 64) {
            Err(LookupFault::InvalidRoot) => {}
            other => panic!("expected InvalidRoot, got {:?}", other),
        }
        arch::log("  ✓ non-CNode root surfaces as LookupFault::InvalidRoot\n");
    }

    fn two_level_lookup() {
        // Layered CSpace: root CNode of radix 4 / guard 0 holds a
        // child CNode cap at slot 2; child CNode has radix 4, guard
        // size 0, guard 0 → resolves the remaining 4 bits. Lookup
        // CPtr that selects root-slot 2, then child-slot 7.
        let root_ptr = PPtr::<CNodeStorage>::new(0x4000_0000).unwrap();
        let child_ptr = PPtr::<CNodeStorage>::new(0x5000_0000).unwrap();

        let target = ep_cap(0xFFFF_8000_BEEF_0000, 0xAB);
        let mut child_slots = [Cte::null(); 16];
        child_slots[7] = Cte::with_cap(&target);

        let mut root_slots = [Cte::null(); 16];
        root_slots[2] = Cte::with_cap(&Cap::CNode {
            ptr: child_ptr,
            radix: 4,
            guard_size: 0,
            guard: 0,
        });

        let cspace = TestCSpace {
            nodes: &[(root_ptr, &root_slots), (child_ptr, &child_slots)],
        };
        let root = Cap::CNode {
            ptr: root_ptr,
            radix: 4,
            // levelBits = 4+56 = 60. Then child_radix=4 → total 64.
            guard_size: 56,
            guard: 0,
        };

        // CPtr: high 56 bits 0 (root guard), next 4 bits = 2 (root
        // index), next 4 bits = 7 (child index).
        let cptr: Word = (2u64 << 4) | 7;
        let cap = lookup_cap(&cspace, &root, cptr).expect("lookup ok");
        assert_eq!(cap, target);
        arch::log("  ✓ two-level CSpace lookup descends correctly\n");
    }

    fn non_cnode_stops_early_with_remaining_bits() {
        // Same root setup, but instead of nesting another CNode at
        // root-slot 2, store an endpoint cap. With n_bits=64 and the
        // root level consuming 60 bits, lookup should return early
        // with bits_remaining = 4.
        let root_ptr = PPtr::<CNodeStorage>::new(0x4000_1000).unwrap();
        let target = ep_cap(0xFFFF_8000_F00D_0000, 0xCD);

        let mut root_slots = [Cte::null(); 16];
        root_slots[2] = Cte::with_cap(&target);

        let cspace = TestCSpace { nodes: &[(root_ptr, &root_slots)] };
        let root = Cap::CNode {
            ptr: root_ptr,
            radix: 4,
            guard_size: 56,
            guard: 0,
        };
        let cptr: Word = (2u64 << 4) | 7;
        let res = resolve_address_bits(&cspace, &root, cptr, 64).unwrap();
        assert_eq!(res.bits_remaining, 4);
        // The slot we stopped at IS the slot holding the endpoint.
        let slots = cspace.cnode_at(res.slot_ptr, 16).unwrap();
        assert_eq!(slots[res.slot_index].cap(), target);

        // And `lookup_cap` itself rejects this with a depth mismatch.
        match lookup_cap(&cspace, &root, cptr) {
            Err(LookupFault::DepthMismatch { bits_left: 0, bits_found: 4 }) => {}
            other => panic!("expected DepthMismatch from lookup_cap, got {:?}", other),
        }
        arch::log("  ✓ traversal stops early at non-CNode caps\n");
    }
}
