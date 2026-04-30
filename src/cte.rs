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
}

const _: () = assert!(core::mem::size_of::<Cte>() == Cte::SIZE_BYTES);
