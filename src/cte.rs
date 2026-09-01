//! Capability Table Entry — the in-memory cell that stores one cap
//! plus its mapping-database bookkeeping. Mirrors seL4's `cte_t`
//! byte-for-byte:
//!
//!     struct cte {
//!         cap_t cap;            // 16 bytes
//!         mdb_node_t cteMDBNode; // 16 bytes
//!     };  // 32 bytes total
//!
//! The on-the-wire layout is the two raw words for each member; the
//! enum form (`Cap`) is a transient view materialised by `Cte::cap()`
//! and serialised back by `Cte::set_cap()`.

use crate::cap::{from_words, to_words, Cap};
use crate::structures::MdbNode;
use crate::types::seL4_Word as Word;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Cte {
    /// Two-word `cap_t` storage — accessed via the typed `cap()`/
    /// `set_cap()` helpers below.
    pub cap_words: [Word; 2],
    /// Two-word `mdb_node_t` storage — see `mdb()` / `set_mdb()`.
    pub mdb_words: [Word; 2],
}

impl Cte {
    pub const SIZE_BYTES: usize = 32;

    /// A null CTE: null cap, parent = None. The all-zero byte pattern is canonical so large CNode
    /// pools can live in `.bss`; parent ids stored in MDB words are biased by one to keep
    /// `(cnode 0, slot 0)` representable without making zero mean a real parent.
    pub const fn null() -> Self {
        Self {
            cap_words: [0; 2],
            mdb_words: [MdbId::STORED_NONE as u64, 0],
        }
    }

    /// Convenience constructor used by the specs.
    pub fn with_cap(cap: &Cap) -> Self {
        let mut c = Self::null();
        c.set_cap(cap);
        c
    }

    /// Decode the stored cap into the typed enum.
    pub fn cap(&self) -> Cap {
        from_words(self.cap_words)
    }

    /// Write a cap back to the bitfield words.
    ///
    /// Phase 44 — when this CTE lives inside a kernel CNode pool,
    /// the overwrite is noted in the per-object refcounts (old cap
    /// −1, new cap +1). Stack-built `Cte` temporaries (specs,
    /// `with_cap`) fall outside the pool address ranges and are
    /// not counted; boot-era writes are absorbed by the
    /// `recount_refcounts()` sweep at production start.
    pub fn set_cap(&mut self, cap: &Cap) {
        if crate::kernel::slot_in_pools(self as *const _ as usize) {
            let old = self.cap();
            crate::kernel::note_cap_write(&old, cap);
            crate::asid::note_cap_write(&old, cap);
        }
        self.cap_words = to_words(cap);
    }

    pub fn mdb(&self) -> MdbNode {
        MdbNode {
            words: self.mdb_words,
        }
    }

    pub fn set_mdb(&mut self, mdb: MdbNode) {
        self.mdb_words = mdb.words;
    }

    // -- Phase 30 — minimal MDB tracking ------------------------------------
    //
    // We store the cap's *parent* (the CTE it was derived from) packed
    // into `mdb_words[0]` low bits. seL4's full MDB is a doubly-
    // linked list with prev/next + revocable/firstBadged flags; we
    // start with just the parent edge because that's enough to walk
    // descendants and exactly that walk is what `Revoke` needs. Phase
    // 30+ can grow the encoding to use the rest of `mdb_words`.
    //
    // Encoding: low `MdbId::MASK` bits of `mdb_words[0]` = packed `MdbId + 1`.
    // Stored zero means "no parent" (a root cap, an empty CTE, or one that predates the MDB), while
    // `MdbId::pack(0, 0)` stores as one and remains a valid parent.

    pub fn parent(&self) -> Option<MdbId> {
        let raw = self.mdb_words[0] & MdbId::MASK;
        if raw == MdbId::STORED_NONE {
            None
        } else {
            Some(MdbId(raw - 1))
        }
    }

    pub fn set_parent(&mut self, parent: Option<MdbId>) {
        let raw = parent.map_or(MdbId::STORED_NONE, |p| p.0 + 1);
        self.mdb_words[0] = (self.mdb_words[0] & !MdbId::MASK) | raw;
    }

    /// Number of direct descendants whose MDB parent is this CTE. Keeping the count with the
    /// parent makes CNode Move transfer the complete derivation identity and avoids a kernel-image
    /// side array sized for every possible CSpace slot.
    pub const fn child_count(&self) -> u32 {
        self.mdb_words[1] as u32
    }

    pub fn set_child_count(&mut self, count: u32) {
        self.mdb_words[1] = (self.mdb_words[1] & 0xffff_ffff_0000_0000) | count as u64;
    }

    pub fn increment_child_count(&mut self, by: u32) {
        self.set_child_count(self.child_count().saturating_add(by));
    }

    pub fn decrement_child_count(&mut self) -> u32 {
        let remaining = self.child_count().saturating_sub(1);
        self.set_child_count(remaining);
        remaining
    }

    /// Transient generation used by one BKL-serialized revoke walk. A generation mark avoids a
    /// second bitmap proportional to total CSpace capacity; it has no meaning after that walk.
    pub const fn revoke_epoch(&self) -> u32 {
        (self.mdb_words[1] >> 32) as u32
    }

    pub fn set_revoke_epoch(&mut self, epoch: u32) {
        self.mdb_words[1] = (self.mdb_words[1] & 0x0000_0000_ffff_ffff) | ((epoch as u64) << 32);
    }
}

/// Packed (cnode_idx, slot) handle on a CTE somewhere in
/// `KernelState`'s CNode registry. The complete 52-bit identity lives in the
/// first 64-bit MDB word, leaving the second word for per-CTE ownership state.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct MdbId(pub u64);

impl MdbId {
    pub const SLOT_BITS: u32 = 20;
    pub const SLOT_MASK: u64 = (1u64 << Self::SLOT_BITS) - 1;
    pub const CNODE_IDX_BITS: u32 = 32;
    pub const MASK: u64 = (1u64 << (Self::CNODE_IDX_BITS + Self::SLOT_BITS)) - 1;
    pub const STORED_NONE: u64 = 0;

    /// Kept as a storage-level alias for older comments/tests that referred to "sentinel"; raw
    /// zero is no-parent, while `MdbId(0)` is a valid encoded parent and stores as one.
    pub const SENTINEL: u64 = Self::STORED_NONE;

    /// `cnode_idx` is a descriptor identity; `slot` supports CNodes through radix 20.
    pub const fn pack(cnode_idx: u32, slot: u32) -> Self {
        Self(((cnode_idx as u64) << Self::SLOT_BITS) | ((slot as u64) & Self::SLOT_MASK))
    }
    pub const fn cnode_idx(self) -> u32 {
        (self.0 >> Self::SLOT_BITS) as u32
    }
    pub const fn slot(self) -> u32 {
        (self.0 & Self::SLOT_MASK) as u32
    }
}

const _: () = assert!(core::mem::size_of::<Cte>() == Cte::SIZE_BYTES);
