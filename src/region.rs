//! Memory region types — half-open intervals over physical and
//! virtual addresses. Mirrors seL4's `region_t` / `p_region_t` /
//! `v_region_t` structs but with the type tag baked into the Rust
//! type rather than relying on convention.
//!
//! Used by:
//!   - the boot phase to describe the BOOTBOOT memory map after
//!     conversion to seL4's representation,
//!   - untyped retype to bound checks,
//!   - the rootserver placement code (in a later phase) to find a
//!     contiguous free range big enough for the kernel's initial
//!     objects.

use crate::types::seL4_Word as Word;

/// Half-open physical-address interval `[start, end)`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct PRegion {
    pub start: u64,
    pub end: u64,
}

/// Half-open virtual-address interval `[start, end)`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct VRegion {
    pub start: u64,
    pub end: u64,
}

impl PRegion {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }
    pub const fn size(self) -> u64 {
        if self.is_empty() { 0 } else { self.end - self.start }
    }
    pub const fn contains(self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
    pub const fn covers(self, other: PRegion) -> bool {
        self.start <= other.start && other.end <= self.end
    }
    /// True iff `[a..b)` and `[c..d)` share at least one byte.
    pub const fn overlaps(self, other: PRegion) -> bool {
        self.start < other.end && other.start < self.end
    }
}

impl VRegion {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }
    pub const fn size(self) -> u64 {
        if self.is_empty() { 0 } else { self.end - self.start }
    }
}

/// Round `addr` up to the next multiple of `1 << bits`. Saturating —
/// returns `Word::MAX` if it would overflow rather than wrapping.
pub const fn align_up(addr: Word, bits: u32) -> Word {
    let alignment = 1u64 << bits;
    let mask = alignment - 1;
    match addr.checked_add(mask) {
        Some(v) => v & !mask,
        None => Word::MAX,
    }
}

/// Round `addr` down to the previous multiple of `1 << bits`.
pub const fn align_down(addr: Word, bits: u32) -> Word {
    let alignment = 1u64 << bits;
    addr & !(alignment - 1)
}

/// True when `addr` is already a multiple of `1 << bits`.
pub const fn is_aligned(addr: Word, bits: u32) -> bool {
    let mask = (1u64 << bits) - 1;
    (addr & mask) == 0
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_region() {
        arch::log("Running region tests...\n");
        empty_region();
        contains_and_covers();
        overlap();
        alignment_helpers();
        arch::log("Region tests completed\n");
    }

    fn empty_region() {
        assert!(PRegion::new(10, 10).is_empty());
        assert_eq!(PRegion::new(10, 10).size(), 0);
        // Reverse range counts as empty too — never let arithmetic
        // wrap into a giant size.
        assert!(PRegion::new(20, 10).is_empty());
        assert_eq!(PRegion::new(20, 10).size(), 0);
        arch::log("  ✓ empty / inverted regions\n");
    }

    fn contains_and_covers() {
        let r = PRegion::new(0x1000, 0x2000);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
        assert!(r.covers(PRegion::new(0x1100, 0x1900)));
        assert!(!r.covers(PRegion::new(0x1100, 0x2100)));
        arch::log("  ✓ contains / covers semantics\n");
    }

    fn overlap() {
        let a = PRegion::new(0, 10);
        let b = PRegion::new(5, 15);
        let c = PRegion::new(10, 20);
        assert!(a.overlaps(b));
        // Touching at a single boundary point does NOT overlap
        // (half-open).
        assert!(!a.overlaps(c));
        arch::log("  ✓ overlap is strict on the upper bound\n");
    }

    fn alignment_helpers() {
        assert_eq!(align_up(0x1001, 12), 0x2000);
        assert_eq!(align_up(0x1000, 12), 0x1000);
        assert_eq!(align_down(0x1FFF, 12), 0x1000);
        assert!(is_aligned(0x2000, 12));
        assert!(!is_aligned(0x2001, 12));
        // Saturation: align_up should not overflow.
        assert_eq!(align_up(u64::MAX - 1, 12), u64::MAX);
        arch::log("  ✓ align_up / align_down saturate cleanly\n");
    }
}
