use super::*;
use crate::cap::{AsidPoolStorage, PPtr, Pml4Storage};

#[repr(C, align(4096))]
struct FixturePoolPage([u8; 4096]);

static mut FIXTURE_POOLS: [FixturePoolPage; MAX_ASID_POOLS] =
    [const { FixturePoolPage([0; 4096]) }; MAX_ASID_POOLS];

/// Real CTE owners for architectural identity fixtures. The fixture must outlive
/// its TCBs, and callers must serialize construction/destruction with the BKL or
/// the pre-user spec phase. Existing roots also retain their owning pool.
pub struct RootOwners {
    cnode: usize,
    base: u16,
    pool: u64,
    next_slot: usize,
}

impl RootOwners {
    pub fn new() -> Self {
        let base = first_free_pool_base().expect("fixture ASID pool capacity");
        let page = unsafe { &raw const FIXTURE_POOLS[base as usize / ASIDS_PER_POOL] } as u64;
        let physical = crate::arch::virt_to_phys(page);
        let cnode = unsafe { crate::kernel::KERNEL.get().alloc_small_cnode() }
            .expect("fixture CNode capacity");
        install_pool(base, physical).expect("fixture pool backing is exclusive");
        unsafe {
            crate::kernel::KERNEL.get().cnode_slots_at_mut(cnode).unwrap()[0]
                .set_cap(&pool(base, physical));
        }
        Self { cnode, base, pool: physical, next_slot: 1 }
    }

    pub fn root(&mut self, physical: u64) -> Cap {
        unsafe {
            let slots = crate::kernel::KERNEL.get().cnode_slots_at_mut(self.cnode).unwrap();
            for slot in slots[1..self.next_slot].iter() {
                let cap = slot.cap();
                if let Cap::PML4 { ptr, .. } = cap {
                    if ptr.addr() == physical {
                        assert!(root_is_current(&cap));
                        return cap;
                    }
                }
            }
        }
        assert!(self.next_slot + 2 <= crate::kernel::SMALL_CNODE_SLOTS);
        let asid = match asid_for_pml4(physical) {
            Some(asid) => asid,
            None => {
                let asid = first_free_asid(self.base, self.pool).unwrap();
                install_root(self.base, self.pool, asid, physical).unwrap();
                asid
            }
        };
        let base = (asid as usize / ASIDS_PER_POOL * ASIDS_PER_POOL) as u16;
        let physical_pool = POOLS[base as usize / ASIDS_PER_POOL].physical.load(Ordering::Acquire);
        let cap = root(asid, physical);
        unsafe {
            let slots = crate::kernel::KERNEL.get().cnode_slots_at_mut(self.cnode).unwrap();
            slots[self.next_slot].set_cap(&pool(base, physical_pool));
            slots[self.next_slot + 1].set_cap(&cap);
        }
        self.next_slot += 2;
        cap
    }
}

impl Drop for RootOwners {
    fn drop(&mut self) {
        unsafe {
            let state = crate::kernel::KERNEL.get();
            let slots = state.cnode_slots_at_mut(self.cnode).unwrap();
            for i in (2..self.next_slot).step_by(2) {
                slots[i].set_cap(&Cap::Null);
            }
            for i in (1..self.next_slot).step_by(2) {
                slots[i].set_cap(&Cap::Null);
            }
            slots[0].set_cap(&Cap::Null);
            state.free_small_cnode(self.cnode);
        }
    }
}

fn pool(base: u16, physical: u64) -> Cap {
    Cap::AsidPool { ptr: PPtr::<AsidPoolStorage>::new(physical).unwrap(), asid_base: base }
}

fn root(asid: u16, physical: u64) -> Cap {
    Cap::PML4 { ptr: PPtr::<Pml4Storage>::new(physical).unwrap(), mapped: true, asid }
}

fn own_pool(base: u16, physical: u64) -> Cap {
    install_pool(base, physical).unwrap();
    assert_eq!(pool_refcount(base), 0, "installation is not a fabricated cap reference");
    let cap = pool(base, physical);
    note_cap_write(&Cap::Null, &cap);
    cap
}

fn own_root(base: u16, pool: u64, asid: u16, physical: u64) -> Cap {
    install_root(base, pool, asid, physical).unwrap();
    assert_eq!(pml4_refcount(asid), 0, "installation precedes CTE publication");
    let cap = root(asid, physical);
    note_cap_write(&Cap::Null, &cap);
    cap
}

#[inline(never)]
fn explicit_installation_is_the_only_authority() {
    reset();
    let unregistered = root(1, 0x2000);
    note_cap_write(&Cap::Null, &unregistered);
    assert_eq!(pml4_paddr(1), 0);
    assert_eq!(pml4_refcount(1), 0);
    note_cap_write(&unregistered, &Cap::Null);
    assert_eq!(pool_status(0, 0x1000), Err(CatalogError::MissingPool));
    assert_eq!(install_pool(1, 0x1000), Err(CatalogError::InvalidPool));
    assert_eq!(install_pool(0, 0), Err(CatalogError::InvalidPool));
    assert_eq!(install_pool(0, 0x1001), Err(CatalogError::InvalidPool));
    let p = own_pool(0, 0x1000);
    assert_eq!(install_pool(0, 0x3000), Err(CatalogError::Occupied));
    assert_eq!(install_pool(512, 0x1000), Err(CatalogError::Occupied));
    assert_eq!(pool_status(0, 0x3000), Err(CatalogError::PoolMismatch));
    assert_eq!(install_root(0, 0x3000, 1, 0x2000), Err(CatalogError::PoolMismatch));
    assert_eq!(install_root(0, 0x1000, 0, 0x2000), Err(CatalogError::InvalidRoot));
    assert_eq!(install_root(0, 0x1000, 512, 0x2000), Err(CatalogError::InvalidRoot));
    assert_eq!(install_root(0, 0x1000, 1, 0), Err(CatalogError::InvalidRoot));
    assert_eq!(install_root(0, 0x1000, 1, 0x2001), Err(CatalogError::InvalidRoot));
    assert_eq!(first_free_asid(0, 0x1000), Ok(1));
    let r = own_root(0, 0x1000, 1, 0x2000);
    assert_eq!(install_root(0, 0x1000, 1, 0x4000), Err(CatalogError::Occupied));
    assert_eq!(install_root(0, 0x1000, 2, 0x2000), Err(CatalogError::RootAlreadyAssigned));
    assert_eq!(pml4_paddr(1), 0x2000);
    assert_eq!(pml4_refcount(1), 1);
    assert_eq!(first_free_asid(0, 0x1000), Ok(2));
    let invalid = Cap::PML4 {
        ptr: PPtr::<Pml4Storage>::new(0x2000).unwrap(), mapped: false, asid: 1,
    };
    note_cap_write(&Cap::Null, &invalid);
    note_cap_write(&invalid, &Cap::Null);
    assert!(!root_is_current(&invalid));
    assert!(root_is_current(&r));
    assert_eq!(pml4_refcount(1), 1);
    note_cap_write(&r, &Cap::Null);
    note_cap_write(&p, &Cap::Null);
    assert_eq!(first_free_pool_base(), Some(0));
}

#[inline(never)]
fn exact_reference_lifetimes() {
    reset();
    let p = own_pool(0, 0x1000);
    let r = own_root(0, 0x1000, 1, 0x2000);
    note_cap_write(&r, &r);
    note_cap_write(&p, &p);
    assert_eq!(pml4_refcount(1), 1);
    assert_eq!(pool_refcount(0), 1);
    note_cap_write(&Cap::Null, &r);
    note_tcb_root_write(&Cap::Null, &r);
    assert_eq!(pml4_refcount(1), 3);
    note_cap_write(&r, &Cap::Null);
    note_cap_write(&r, &Cap::Null);
    assert_eq!(pml4_refcount(1), 1, "TCB is an independent retained root copy");
    assert!(root_is_current(&r));
    note_tcb_root_write(&r, &Cap::Null);
    assert_eq!(pml4_paddr(1), 0);
    assert_eq!(pml4_refcount(1), 0);
    note_cap_write(&Cap::Null, &r);
    assert_eq!(pml4_paddr(1), 0, "stale copy cannot recreate an assignment");
    note_cap_write(&r, &Cap::Null);
    note_cap_write(&p, &Cap::Null);
}

#[inline(never)]
fn pool_aliases_and_stale_references() {
    reset();
    let p = own_pool(0, 0x1000);
    let r = own_root(0, 0x1000, 1, 0x2000);
    note_cap_write(&Cap::Null, &p);
    note_tcb_root_write(&Cap::Null, &r);
    note_cap_write(&p, &Cap::Null);
    assert_eq!(pool_refcount(0), 1);
    assert_eq!(pml4_refcount(1), 2);
    assert!(root_is_current(&r));
    note_cap_write(&p, &Cap::Null);
    assert_eq!(pool_status(0, 0x1000), Err(CatalogError::MissingPool));
    assert!(!root_is_current(&r));
    assert_eq!(pml4_refcount(1), 0);
    let replacement_pool = own_pool(0, 0x3000);
    let replacement_root = own_root(0, 0x3000, 1, 0x4000);
    note_cap_write(&Cap::Null, &p);
    note_cap_write(&p, &Cap::Null);
    note_cap_write(&Cap::Null, &r);
    note_cap_write(&r, &Cap::Null);
    note_tcb_root_write(&r, &Cap::Null);
    assert_eq!(pool_refcount(0), 1, "stale pool cannot subtract replacement references");
    assert_eq!(pml4_refcount(1), 1, "stale root cannot subtract replacement references");
    assert!(root_is_current(&replacement_root));
    assert_eq!(pml4_paddr(1), 0x4000);
    note_cap_write(&replacement_root, &Cap::Null);
    note_cap_write(&replacement_pool, &Cap::Null);
}

#[inline(never)]
fn full_pool_and_freed_slot_reuse() {
    reset();
    let p = own_pool(0, 0x1000);
    for asid in 1..ASIDS_PER_POOL as u16 {
        assert_eq!(first_free_asid(0, 0x1000), Ok(asid));
        let _ = own_root(0, 0x1000, asid, 0x1000_0000 + u64::from(asid) * 0x1000);
    }
    assert_eq!(first_free_asid(0, 0x1000), Err(CatalogError::Exhausted));
    assert_eq!(pml4_paddr(0), 0);
    let old = root(123, 0x1000_0000 + 123 * 0x1000);
    note_cap_write(&old, &Cap::Null);
    assert_eq!(first_free_asid(0, 0x1000), Ok(123));
    let replacement = own_root(0, 0x1000, 123, 0x2000_0000);
    assert_eq!(first_free_asid(0, 0x1000), Err(CatalogError::Exhausted));
    assert_eq!(pml4_paddr(1), 0x1000_1000, "exhaustion cannot overwrite the initial root");
    note_cap_write(&old, &Cap::Null);
    assert_eq!(pml4_refcount(123), 1);
    assert!(root_is_current(&replacement));
    note_cap_write(&p, &Cap::Null);
    for asid in 1..ASIDS_PER_POOL as u16 { assert_eq!(pml4_paddr(asid), 0); }
}

#[inline(never)]
fn repeated_assignment_never_wraps_into_live_roots() {
    reset();
    let p = own_pool(0, 0x1000);
    let boot = own_root(0, 0x1000, 1, 0x2000);
    for cycle in 0..1024u64 {
        let asid = first_free_asid(0, 0x1000).unwrap();
        assert_eq!(asid, 2);
        let transient = own_root(0, 0x1000, asid, 0x2000_0000 + cycle * 0x1000);
        assert_eq!(pml4_paddr(1), 0x2000);
        note_cap_write(&transient, &Cap::Null);
        assert_eq!(pml4_paddr(asid), 0);
    }
    note_cap_write(&boot, &Cap::Null);
    note_cap_write(&p, &Cap::Null);
}

#[inline(never)]
fn full_architecture_extent() {
    reset();
    for index in 0..MAX_ASID_POOLS {
        let base = (index * ASIDS_PER_POOL) as u16;
        assert_eq!(first_free_pool_base(), Some(base));
        let physical = 0x1000_0000 + index as u64 * 0x1000;
        let _ = own_pool(base, physical);
    }
    assert_eq!(first_free_pool_base(), None);
    let base = ((MAX_ASID_POOLS - 1) * ASIDS_PER_POOL) as u16;
    let pool_physical = 0x1000_0000 + (MAX_ASID_POOLS - 1) as u64 * 0x1000;
    let final_asid = (MAX_ASIDS - 1) as u16;
    let last = own_root(base, pool_physical, final_asid, 0x3000_0000);
    assert!(root_is_current(&last));
    note_cap_write(&last, &Cap::Null);
    for index in 0..MAX_ASID_POOLS {
        note_cap_write(&pool((index * ASIDS_PER_POOL) as u16,
            0x1000_0000 + index as u64 * 0x1000), &Cap::Null);
    }
    assert_eq!(first_free_pool_base(), Some(0));
}

pub fn test_asid() {
    let _guard = crate::spec::KernelGuard::acquire();
    explicit_installation_is_the_only_authority();
    exact_reference_lifetimes();
    pool_aliases_and_stale_references();
    full_pool_and_freed_slot_reuse();
    repeated_assignment_never_wraps_into_live_roots();
    full_architecture_extent();
    reset();
    crate::arch::log("  ASID catalog retains exact assignments and rejects stale publication\n");
}
