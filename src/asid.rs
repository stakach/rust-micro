//! Canonical ASID pool and VSpace assignments.
//!
//! Installation is explicit and checked. CTE and TCB writes retain existing assignments but
//! cannot create them. All mutation is serialized by the kernel lock (or quiescent bootstrap).

use crate::cap::Cap;
use core::sync::atomic::{AtomicU64, Ordering};

pub const ASIDS_PER_POOL: usize = 1 << 9;
#[cfg(target_arch = "x86_64")]
pub const MAX_ASID_POOLS: usize = 1 << 3;
#[cfg(target_arch = "aarch64")]
pub const MAX_ASID_POOLS: usize = 1 << 7;
const MAX_ASIDS: usize = ASIDS_PER_POOL * MAX_ASID_POOLS;

struct Assignment {
    physical: AtomicU64,
    references: AtomicU64,
}

impl Assignment {
    const EMPTY: Self = Self {
        physical: AtomicU64::new(0),
        references: AtomicU64::new(0),
    };
}

static POOLS: [Assignment; MAX_ASID_POOLS] =
    [const { Assignment::EMPTY }; MAX_ASID_POOLS];
static ROOTS: [Assignment; MAX_ASIDS] = [const { Assignment::EMPTY }; MAX_ASIDS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogError {
    InvalidPool,
    InvalidRoot,
    MissingPool,
    PoolMismatch,
    Occupied,
    Exhausted,
    RootAlreadyAssigned,
}

fn pool_index(base: u16) -> Result<usize, CatalogError> {
    let base = base as usize;
    if base % ASIDS_PER_POOL != 0 || base / ASIDS_PER_POOL >= MAX_ASID_POOLS {
        return Err(CatalogError::InvalidPool);
    }
    Ok(base / ASIDS_PER_POOL)
}

fn valid_physical(physical: u64) -> bool {
    physical != 0 && physical & 0xfff == 0
}

fn asid_index(asid: u16) -> Option<usize> {
    let index = asid as usize;
    (index != 0 && index < MAX_ASIDS).then_some(index)
}

pub fn pml4_paddr(asid: u16) -> u64 {
    asid_index(asid)
        .map(|index| ROOTS[index].physical.load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn asid_for_pml4(physical: u64) -> Option<u16> {
    if !valid_physical(physical) {
        return None;
    }
    (1..MAX_ASIDS)
        .find(|&index| ROOTS[index].physical.load(Ordering::Relaxed) == physical)
        .map(|index| index as u16)
}

pub fn root_is_current(cap: &Cap) -> bool {
    matches!(cap, Cap::PML4 { ptr, mapped: true, asid }
        if *asid != 0 && pml4_paddr(*asid) == ptr.addr())
}

pub fn first_free_pool_base() -> Option<u16> {
    (0..MAX_ASID_POOLS)
        .find(|&index| POOLS[index].physical.load(Ordering::Relaxed) == 0)
        .map(|index| (index * ASIDS_PER_POOL) as u16)
}

/// Install a newly owned pool after the caller has preflighted its exact source and destination
/// CTEs. The subsequent CTE publication acquires the first reference; no reference is invented.
pub fn install_pool(base: u16, physical: u64) -> Result<(), CatalogError> {
    let index = pool_index(base)?;
    if !valid_physical(physical) {
        return Err(CatalogError::InvalidPool);
    }
    if POOLS[index].physical.load(Ordering::Relaxed) != 0
        || POOLS.iter().any(|pool| pool.physical.load(Ordering::Relaxed) == physical)
    {
        return Err(CatalogError::Occupied);
    }
    assert_eq!(POOLS[index].references.load(Ordering::Relaxed), 0);
    let start = index * ASIDS_PER_POOL;
    assert!(ROOTS[start..start + ASIDS_PER_POOL].iter().all(|root|
        root.physical.load(Ordering::Relaxed) == 0
            && root.references.load(Ordering::Relaxed) == 0));
    POOLS[index].physical.store(physical, Ordering::Relaxed);
    Ok(())
}

pub fn pool_status(base: u16, physical: u64) -> Result<(), CatalogError> {
    let index = pool_index(base)?;
    if !valid_physical(physical) {
        return Err(CatalogError::InvalidPool);
    }
    match POOLS[index].physical.load(Ordering::Relaxed) {
        0 => Err(CatalogError::MissingPool),
        current if current != physical => Err(CatalogError::PoolMismatch),
        _ => Ok(()),
    }
}

pub fn first_free_asid(base: u16, pool: u64) -> Result<u16, CatalogError> {
    pool_status(base, pool)?;
    let start = base as usize;
    (start..start + ASIDS_PER_POOL)
        .find(|&index| index != 0 && ROOTS[index].physical.load(Ordering::Relaxed) == 0)
        .map(|index| index as u16)
        .ok_or(CatalogError::Exhausted)
}

/// Publish one exact assignment. Under the kernel lock the caller must immediately commit the
/// prevalidated source CTE, whose write acquires its real reference.
pub fn install_root(base: u16, pool: u64, asid: u16, root: u64) -> Result<(), CatalogError> {
    pool_status(base, pool)?;
    let index = asid_index(asid).ok_or(CatalogError::InvalidRoot)?;
    if index < base as usize || index >= base as usize + ASIDS_PER_POOL
        || !valid_physical(root)
    {
        return Err(CatalogError::InvalidRoot);
    }
    if ROOTS[index].physical.load(Ordering::Relaxed) != 0 {
        return Err(CatalogError::Occupied);
    }
    if asid_for_pml4(root).is_some() {
        return Err(CatalogError::RootAlreadyAssigned);
    }
    assert_eq!(ROOTS[index].references.load(Ordering::Relaxed), 0);
    ROOTS[index].physical.store(root, Ordering::Relaxed);
    Ok(())
}

fn root_identity(cap: &Cap) -> Option<(u16, u64)> {
    match cap {
        Cap::PML4 { ptr, mapped: true, asid } if *asid != 0 => Some((*asid, ptr.addr())),
        _ => None,
    }
}

fn pool_identity(cap: &Cap) -> Option<(u16, u64)> {
    match cap {
        Cap::AsidPool { ptr, asid_base } => Some((*asid_base, ptr.addr())),
        _ => None,
    }
}

fn add_reference(assignment: &Assignment, physical: u64) {
    if physical == 0 || assignment.physical.load(Ordering::Relaxed) != physical {
        return;
    }
    let count = assignment.references.load(Ordering::Relaxed);
    // The bounded CSpace and TCB slab cannot contain u64::MAX references.
    assignment.references.store(count.checked_add(1).expect("ASID reference count overflow"),
        Ordering::Relaxed);
}

fn remove_reference(assignment: &Assignment, physical: u64) -> bool {
    if physical == 0 || assignment.physical.load(Ordering::Relaxed) != physical {
        return false;
    }
    let count = assignment.references.load(Ordering::Relaxed);
    let next = count.checked_sub(1).expect("registered ASID reference must be owned");
    assignment.references.store(next, Ordering::Relaxed);
    next == 0
}

fn invalidate_root(asid: u16, root: u64) {
    // Invalidate while the canonical assignment is still available to architecture code.
    #[cfg(target_arch = "x86_64")]
    crate::smp::retire_vspace_assignment(root);
    #[cfg(target_arch = "aarch64")]
    unsafe { crate::arch::aarch64::vspace::flush_vspace(); }
    assert_eq!(pml4_paddr(asid), root);
    let entry = &ROOTS[asid as usize];
    entry.physical.store(0, Ordering::Relaxed);
    entry.references.store(0, Ordering::Relaxed);
}

fn release_root(asid: u16, root: u64) {
    if let Some(index) = asid_index(asid) {
        if remove_reference(&ROOTS[index], root) {
            invalidate_root(asid, root);
        }
    }
}

fn release_pool(base: u16, physical: u64) {
    let Ok(index) = pool_index(base) else { return; };
    if !remove_reference(&POOLS[index], physical) {
        return;
    }
    // Pool deletion withdraws every assignment, including roots retained in TCBs. Those stale
    // caps remain owned objects but no longer authorize hardware VSpace activation.
    for asid in base as usize..base as usize + ASIDS_PER_POOL {
        let root = ROOTS[asid].physical.load(Ordering::Relaxed);
        if root != 0 {
            invalidate_root(asid as u16, root);
        }
    }
    POOLS[index].physical.store(0, Ordering::Relaxed);
}

/// Exact reference accounting only. A stale or fabricated cap cannot publish an assignment or
/// subtract from a different current owner. Incoming references precede outgoing finalization.
pub fn note_cap_write(old: &Cap, new: &Cap) {
    let old_root = root_identity(old);
    let new_root = root_identity(new);
    let old_pool = pool_identity(old);
    let new_pool = pool_identity(new);
    if old_root != new_root {
        if let Some((asid, root)) = new_root {
            if let Some(index) = asid_index(asid) { add_reference(&ROOTS[index], root); }
        }
    }
    if old_pool != new_pool {
        if let Some((base, pool)) = new_pool {
            if let Ok(index) = pool_index(base) { add_reference(&POOLS[index], pool); }
        }
    }
    if old_root != new_root {
        if let Some((asid, root)) = old_root { release_root(asid, root); }
    }
    if old_pool != new_pool {
        if let Some((base, pool)) = old_pool { release_pool(base, pool); }
    }
}

/// Real retained TCB root copies participate in the same reference count as CSpace copies.
pub fn note_tcb_root_write(old: &Cap, new: &Cap) {
    assert!(matches!(old, Cap::Null | Cap::PML4 { .. }));
    assert!(matches!(new, Cap::Null | Cap::PML4 { .. }));
    note_cap_write(old, new);
}

/// Bootstrap/spec reset only, while no old assignment can execute or be published again.
pub fn reset() {
    for row in POOLS.iter().chain(ROOTS.iter()) {
        row.physical.store(0, Ordering::Relaxed);
        row.references.store(0, Ordering::Relaxed);
    }
}

#[cfg(feature = "spec")]
pub fn pml4_refcount(asid: u16) -> u64 {
    asid_index(asid).map(|index| ROOTS[index].references.load(Ordering::Relaxed)).unwrap_or(0)
}

#[cfg(feature = "spec")]
pub fn pool_refcount(base: u16) -> u64 {
    pool_index(base).map(|index| POOLS[index].references.load(Ordering::Relaxed)).unwrap_or(0)
}

#[cfg(feature = "spec")]
#[path = "asid_specs.rs"]
pub mod spec;
