//! Actual CTE and TCB ownership, without manually seeded reference counts.
use super::{Tcb, TcbSlab, MAX_TCBS};
use crate::cap::{AsidPoolStorage, Cap, PPtr, Pml4Storage};
use crate::kernel::KERNEL;

#[repr(C, align(4096))]
struct Page([u8; 4096]);

static POOL: Page = Page([0; 4096]);
static FIRST_ROOT: Page = Page([0; 4096]);
static SECOND_ROOT: Page = Page([0; 4096]);

fn physical(page: &Page) -> u64 {
    let address = page as *const Page as u64;
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::paging::kernel_virt_to_phys(address)
    }
    #[cfg(target_arch = "aarch64")]
    {
        address
    }
}

struct Fixture {
    cnode: usize,
    first_asid: u16,
    second_asid: u16,
}

impl Fixture {
    fn new() -> Self {
        let base = crate::asid::first_free_pool_base().expect("free spec ASID pool");
        let cnode = unsafe {
            KERNEL
                .get()
                .alloc_cnode()
                .expect("registered fixture CNode")
        };
        let pool = physical(&POOL);
        crate::asid::install_pool(base, pool).unwrap();
        let pool_cap = Cap::AsidPool {
            ptr: PPtr::<AsidPoolStorage>::new(pool).unwrap(),
            asid_base: base,
        };
        unsafe {
            KERNEL.get().cnodes[cnode].0[0].set_cap(&pool_cap);
        }
        let first_asid = base + 1;
        let second_asid = base + 2;
        Self::root(
            cnode,
            1,
            base,
            physical(&POOL),
            first_asid,
            physical(&FIRST_ROOT),
        );
        Self::root(
            cnode,
            2,
            base,
            physical(&POOL),
            second_asid,
            physical(&SECOND_ROOT),
        );
        Self {
            cnode,
            first_asid,
            second_asid,
        }
    }

    fn root(cnode: usize, slot: usize, base: u16, pool: u64, asid: u16, address: u64) {
        crate::asid::install_root(base, pool, asid, address).unwrap();
        let cap = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(address).unwrap(),
            mapped: true,
            asid,
        };
        unsafe {
            KERNEL.get().cnodes[cnode].0[slot].set_cap(&cap);
        }
    }

    fn cap(&self, slot: usize) -> Cap {
        unsafe { KERNEL.get().cnodes[self.cnode].0[slot].cap() }
    }

    fn clear(&mut self, slot: usize) {
        unsafe {
            KERNEL.get().cnodes[self.cnode].0[slot].set_cap(&Cap::Null);
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.clear(1);
        self.clear(2);
        self.clear(0);
        unsafe {
            KERNEL.get().free_cnode(self.cnode);
        }
    }
}

pub(super) fn run() {
    held_root_survives_last_cte_and_drains_on_slab_free();
    replacement_and_rejected_root_are_failure_atomic();
    failed_slab_admission_releases_owned_input();
    whole_tcb_replacement_releases_root();
    pool_retirement_invalidates_held_root_without_reviving_it();
    #[cfg(target_arch = "x86_64")]
    cached_cr3_is_never_vspace_authority();
    crate::arch::log("  TCB VSpace references retain exact roots and reject stale activation\n");
}

#[inline(never)]
fn held_root_survives_last_cte_and_drains_on_slab_free() {
    let mut fixture = Fixture::new();
    let root = fixture.cap(1);
    let mut thread = Tcb::default();
    assert!(thread.set_vspace_root(root));
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    let mut slab = TcbSlab::new();
    let id = slab.alloc(thread).unwrap();
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    fixture.clear(1);
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
    assert!(crate::asid::root_is_current(&slab.get(id).vspace_root()));
    slab.free(id);
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 0);
    assert!(!crate::asid::root_is_current(&root));
}

fn replacement_and_rejected_root_are_failure_atomic() {
    let fixture = Fixture::new();
    let mut thread = Tcb::default();
    assert!(thread.set_vspace_root(fixture.cap(1)));
    assert!(thread.set_vspace_root(fixture.cap(1)));
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    let old_address = thread.cpu_context.cr3;
    assert!(!thread.set_vspace_root(fixture.cap(0)));
    let invalid = Cap::PML4 {
        ptr: PPtr::<Pml4Storage>::new(physical(&FIRST_ROOT)).unwrap(),
        mapped: false,
        asid: fixture.first_asid,
    };
    assert!(!thread.set_vspace_root(invalid));
    assert_eq!(thread.cpu_context.cr3, old_address);
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    assert_eq!(crate::asid::pml4_refcount(fixture.second_asid), 1);
    assert!(thread.set_vspace_root(fixture.cap(2)));
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
    assert_eq!(crate::asid::pml4_refcount(fixture.second_asid), 2);
    assert!(thread.set_vspace_root(Cap::Null));
    assert_eq!(crate::asid::pml4_refcount(fixture.second_asid), 1);
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        thread.vm_root_cr3(),
        crate::arch::x86_64::paging::kernel_root_cr3()
    );
}

#[inline(never)]
fn failed_slab_admission_releases_owned_input() {
    let fixture = Fixture::new();
    let mut slab = TcbSlab::new();
    for _ in 0..MAX_TCBS {
        assert!(slab.alloc(Tcb::default()).is_some());
    }
    let mut thread = Tcb::default();
    assert!(thread.set_vspace_root(fixture.cap(1)));
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    assert!(slab.alloc(thread).is_none());
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
}

#[inline(never)]
fn whole_tcb_replacement_releases_root() {
    let fixture = Fixture::new();
    let mut thread = Tcb::default();
    assert!(thread.set_vspace_root(fixture.cap(1)));
    let mut slab = TcbSlab::new();
    let id = slab.alloc(thread).unwrap();
    *slab.get_mut(id) = Tcb::default();
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
}

fn pool_retirement_invalidates_held_root_without_reviving_it() {
    let mut fixture = Fixture::new();
    let root = fixture.cap(1);
    let mut thread = Tcb::default();
    assert!(thread.set_vspace_root(root));
    fixture.clear(0);
    assert!(!crate::asid::root_is_current(&root));
    assert_eq!(crate::asid::pml4_paddr(fixture.first_asid), 0);
    assert!(!thread.set_vspace_root(root));
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        thread.vm_root_cr3(),
        crate::arch::x86_64::paging::kernel_root_cr3()
    );
    drop(thread);
    assert_eq!(crate::asid::pml4_paddr(fixture.first_asid), 0);
}

#[cfg(target_arch = "x86_64")]
fn cached_cr3_is_never_vspace_authority() {
    let fixture = Fixture::new();
    let mut unconfigured = Tcb::default();
    unconfigured.cpu_context.cr3 = physical(&FIRST_ROOT);
    assert!(!unconfigured.has_current_vspace());
    assert_eq!(
        unconfigured.vm_root_cr3(),
        crate::arch::x86_64::paging::kernel_root_cr3()
    );
    let mut configured = Tcb::default();
    assert!(configured.set_vspace_root(fixture.cap(1)));
    configured.cpu_context.cr3 = physical(&SECOND_ROOT);
    assert!(configured.has_current_vspace());
    assert_eq!(configured.vm_root_cr3(), physical(&FIRST_ROOT));
}
