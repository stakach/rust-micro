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

    /// A null CTE: null cap, default MDB node.
    pub const fn null() -> Self {
        Self { cap_words: [0; 2], mdb_words: [0; 2] }
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
    pub fn set_cap(&mut self, cap: &Cap) {
        self.cap_words = to_words(cap);
    }

    pub fn mdb(&self) -> MdbNode {
        MdbNode { words: self.mdb_words }
    }

    pub fn set_mdb(&mut self, mdb: MdbNode) {
        self.mdb_words = mdb.words;
    }

    // -- Phase 30 — minimal MDB tracking ------------------------------------
    //
    // We store the cap's *parent* (the CTE it was derived from) packed
    // into `mdb_words[0]` low 16 bits. seL4's full MDB is a doubly-
    // linked list with prev/next + revocable/firstBadged flags; we
    // start with just the parent edge because that's enough to walk
    // descendants and exactly that walk is what `Revoke` needs. Phase
    // 30+ can grow the encoding to use the rest of `mdb_words`.
    //
    // Encoding: low 16 bits of `mdb_words[0]` = packed `MdbId` (see
    // `mdb_id_pack`). Sentinel `0xFFFF` = "no parent" (a root cap, or
    // one that pre-dates the MDB).

    pub fn parent(&self) -> Option<MdbId> {
        let raw = (self.mdb_words[0] & 0xFFFF) as u16;
        if raw == 0xFFFF { None } else { Some(MdbId(raw)) }
    }

    pub fn set_parent(&mut self, parent: Option<MdbId>) {
        let raw = parent.map_or(0xFFFFu16, |p| p.0);
        self.mdb_words[0] = (self.mdb_words[0] & !0xFFFFu64) | (raw as u64);
    }
}

/// Packed (cnode_idx, slot) handle on a CTE somewhere in
/// `KernelState::cnodes`. 4 bits cnode_idx (up to 16 cnodes; we
/// have MAX_CNODES=4) + 12 bits slot (up to 4096; CNodes are
/// radix-5 = 32 slots today).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct MdbId(pub u16);

impl MdbId {
    /// `cnode_idx`: 0..16, `slot`: 0..4096.
    pub const fn pack(cnode_idx: u8, slot: u16) -> Self {
        Self(((cnode_idx as u16 & 0xF) << 12) | (slot & 0xFFF))
    }
    pub const fn cnode_idx(self) -> u8 { (self.0 >> 12) as u8 }
    pub const fn slot(self) -> u16 { self.0 & 0xFFF }
}

const _: () = assert!(core::mem::size_of::<Cte>() == Cte::SIZE_BYTES);
