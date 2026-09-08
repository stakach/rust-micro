//! Actual CTE and TCB ownership, without manually seeded reference counts.
use super::{Tcb, TcbId, MAX_TCBS};
use crate::cap::{AsidPoolStorage, Cap, PPtr, Pml4Storage};
use crate::cte::{MdbId, TcbSlot};
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
            crate::invocation::delete_cap_slot(KERNEL.get(), self.source(slot)).unwrap();
        }
    }

    fn source(&self, slot: usize) -> MdbId {
        MdbId::pack(self.cnode as u32, slot as u32)
    }

    fn bind(&self, thread: TcbId, slot: Option<usize>) -> crate::error::KResult<()> {
        unsafe {
            crate::invocation::derive_tcb_cap(KERNEL.get(), thread, TcbSlot::VSpace,
                slot.map(|slot| self.source(slot)), 0)
        }
    }
}

fn admit() -> TcbId {
    unsafe { KERNEL.get().scheduler.admit(Tcb::default()) }
}

fn retire(thread: TcbId) {
    unsafe { crate::invocation::retire_tcb(KERNEL.get(), thread); }
}

fn thread_root(thread: TcbId) -> Cap {
    unsafe { KERNEL.get().scheduler.slab.get(thread).vspace_root() }
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
    held_root_survives_source_delete_and_drains_on_retirement();
    replacement_and_rejected_root_are_failure_atomic();
    failed_slab_admission_cannot_acquire_root();
    owned_tcb_retirement_unlinks_root();
    pool_retirement_invalidates_held_root_without_reviving_it();
    #[cfg(target_arch = "x86_64")]
    cached_cr3_is_never_vspace_authority();
    crate::arch::log("  TCB VSpace references retain exact roots and reject stale activation\n");
}

#[inline(never)]
fn held_root_survives_source_delete_and_drains_on_retirement() {
    let mut fixture = Fixture::new();
    let root = fixture.cap(1);
    let thread = admit();
    fixture.bind(thread, Some(1)).unwrap();
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    fixture.clear(1);
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
    assert!(crate::asid::root_is_current(&thread_root(thread)));
    retire(thread);
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 0);
    assert!(!crate::asid::root_is_current(&root));
}

fn replacement_and_rejected_root_are_failure_atomic() {
    let fixture = Fixture::new();
    let thread = admit();
    fixture.bind(thread, Some(1)).unwrap();
    fixture.bind(thread, Some(1)).unwrap();
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    let old_root = thread_root(thread);
    assert!(fixture.bind(thread, Some(0)).is_err());
    assert_eq!(thread_root(thread), old_root);
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 2);
    assert_eq!(crate::asid::pml4_refcount(fixture.second_asid), 1);
    fixture.bind(thread, Some(2)).unwrap();
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
    assert_eq!(crate::asid::pml4_refcount(fixture.second_asid), 2);
    fixture.bind(thread, None).unwrap();
    assert_eq!(crate::asid::pml4_refcount(fixture.second_asid), 1);
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        unsafe { KERNEL.get().scheduler.slab.get(thread).vm_root_cr3() },
        crate::arch::x86_64::paging::kernel_root_cr3()
    );
    retire(thread);
}

#[inline(never)]
fn failed_slab_admission_cannot_acquire_root() {
    let fixture = Fixture::new();
    let mut admitted = [None; MAX_TCBS];
    unsafe {
        let state = KERNEL.get();
        for slot in admitted.iter_mut() {
            *slot = state.scheduler.try_admit_cap(Tcb::default());
            if slot.is_none() {
                break;
            }
        }
        assert!(state.scheduler.try_admit_cap(Tcb::default()).is_none());
        assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
        for thread in admitted.into_iter().flatten() {
            crate::invocation::retire_tcb(state, thread);
        }
    }
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
}

#[inline(never)]
fn owned_tcb_retirement_unlinks_root() {
    let fixture = Fixture::new();
    let thread = admit();
    fixture.bind(thread, Some(1)).unwrap();
    assert_eq!(unsafe { KERNEL.get().cnodes[fixture.cnode].0[1].child_count() }, 1);
    retire(thread);
    assert!(unsafe { KERNEL.get().scheduler.slab.entries[thread.0 as usize].is_none() });
    assert_eq!(unsafe { KERNEL.get().cnodes[fixture.cnode].0[1].child_count() }, 0);
    assert_eq!(crate::asid::pml4_refcount(fixture.first_asid), 1);
}

fn pool_retirement_invalidates_held_root_without_reviving_it() {
    let mut fixture = Fixture::new();
    let root = fixture.cap(1);
    let thread = admit();
    fixture.bind(thread, Some(1)).unwrap();
    fixture.clear(0);
    assert!(!crate::asid::root_is_current(&root));
    assert_eq!(crate::asid::pml4_paddr(fixture.first_asid), 0);
    assert!(fixture.bind(thread, Some(1)).is_err());
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        unsafe { KERNEL.get().scheduler.slab.get(thread).vm_root_cr3() },
        crate::arch::x86_64::paging::kernel_root_cr3()
    );
    retire(thread);
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
    let configured = admit();
    fixture.bind(configured, Some(1)).unwrap();
    unsafe {
        let thread = KERNEL.get().scheduler.slab.get_mut(configured);
        thread.cpu_context.cr3 = physical(&SECOND_ROOT);
        assert!(thread.has_current_vspace());
        assert_eq!(thread.vm_root_cr3(), physical(&FIRST_ROOT));
    }
    retire(configured);
}
