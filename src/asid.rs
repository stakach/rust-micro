//! ASID-to-vspace bookkeeping for x86_64.
//!
//! seL4 keeps ASID pool state separately from the CSpace, so looking up
//! the PML4 for an ASID is an indexed operation. Mirroring that here
//! avoids scanning every CNode slot during frame unmap/delete paths.

use crate::cap::Cap;

pub const ASIDS_PER_POOL: usize = 1 << 9;
pub const MAX_ASID_POOLS: usize = 1 << 3;
const MAX_ASIDS: usize = ASIDS_PER_POOL * MAX_ASID_POOLS;

#[allow(clippy::declare_interior_mutable_const)]
static PML4_BY_ASID: [core::sync::atomic::AtomicU64; MAX_ASIDS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; MAX_ASIDS]
};

#[allow(clippy::declare_interior_mutable_const)]
static PML4_REFS_BY_ASID: [core::sync::atomic::AtomicU16; MAX_ASIDS] = {
    const Z: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
    [Z; MAX_ASIDS]
};

fn asid_index(asid: u16) -> Option<usize> {
    let idx = asid as usize;
    if idx == 0 || idx >= MAX_ASIDS {
        return None;
    }
    Some(idx)
}

pub fn pml4_paddr(asid: u16) -> u64 {
    use core::sync::atomic::Ordering;
    asid_index(asid)
        .map(|idx| PML4_BY_ASID[idx].load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn asid_for_pml4(pml4_paddr: u64) -> Option<u16> {
    use core::sync::atomic::Ordering;
    if pml4_paddr == 0 {
        return None;
    }
    (1..MAX_ASIDS)
        .find(|&idx| PML4_BY_ASID[idx].load(Ordering::Relaxed) == pml4_paddr)
        .map(|idx| idx as u16)
}

pub fn reset() {
    use core::sync::atomic::Ordering;
    for idx in 0..MAX_ASIDS {
        PML4_BY_ASID[idx].store(0, Ordering::Relaxed);
        PML4_REFS_BY_ASID[idx].store(0, Ordering::Relaxed);
    }
}

pub fn register_boot_mapping(asid: u16, pml4_paddr: u64) {
    use core::sync::atomic::Ordering;
    if pml4_paddr == 0 {
        return;
    }
    if let Some(idx) = asid_index(asid) {
        PML4_BY_ASID[idx].store(pml4_paddr, Ordering::Relaxed);
        PML4_REFS_BY_ASID[idx].store(1, Ordering::Relaxed);
    }
}

pub fn clear_pool(asid_base: u16) {
    use core::sync::atomic::Ordering;
    let start = asid_base as usize;
    if start >= MAX_ASIDS {
        return;
    }
    let end = core::cmp::min(start + ASIDS_PER_POOL, MAX_ASIDS);
    for idx in start..end {
        PML4_BY_ASID[idx].store(0, Ordering::Relaxed);
        PML4_REFS_BY_ASID[idx].store(0, Ordering::Relaxed);
    }
}

pub fn note_cap_write(old: &Cap, new: &Cap) {
    if let Cap::PML4 { ptr, asid, .. } = old {
        remove_pml4_ref(*asid, ptr.addr());
    }
    if let Cap::PML4 { ptr, asid, .. } = new {
        add_pml4_ref(*asid, ptr.addr());
    }
}

fn add_pml4_ref(asid: u16, pml4_paddr: u64) {
    use core::sync::atomic::Ordering;
    if pml4_paddr == 0 {
        return;
    }
    let Some(idx) = asid_index(asid) else {
        return;
    };
    PML4_BY_ASID[idx].store(pml4_paddr, Ordering::Relaxed);
    let refs = PML4_REFS_BY_ASID[idx].load(Ordering::Relaxed);
    PML4_REFS_BY_ASID[idx].store(refs.saturating_add(1), Ordering::Relaxed);
}

fn remove_pml4_ref(asid: u16, pml4_paddr: u64) {
    use core::sync::atomic::Ordering;
    let Some(idx) = asid_index(asid) else {
        return;
    };
    let refs = PML4_REFS_BY_ASID[idx].load(Ordering::Relaxed);
    if refs == 0 {
        return;
    }
    let next = refs - 1;
    PML4_REFS_BY_ASID[idx].store(next, Ordering::Relaxed);
    if next == 0 && PML4_BY_ASID[idx].load(Ordering::Relaxed) == pml4_paddr {
        PML4_BY_ASID[idx].store(0, Ordering::Relaxed);
    }
}

#[cfg(feature = "spec")]
pub fn pml4_refcount(asid: u16) -> u16 {
    use core::sync::atomic::Ordering;
    asid_index(asid)
        .map(|idx| PML4_REFS_BY_ASID[idx].load(Ordering::Relaxed))
        .unwrap_or(0)
}
