mod mapping_catalog_specs {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::arch::x86_64::paging::kernel_virt_to_phys;
    use crate::cap::{AsidPoolStorage, Pml4Storage};

    #[repr(C, align(4096))]
    struct Pool([u8; 4096]);
    static mut POOL: Pool = Pool([0; 4096]);
    pub(super) const POOL_SLOT: usize = 31;

    /// Register actual fixture owners through the same checked catalog as bootstrap/Assign.
    /// The caller starts with setup_invoker(0); CTE cleanup releases all catalog references.
    pub(super) unsafe fn root(asid: u16, physical: u64, slot: usize) -> Cap {
        if crate::asid::pml4_paddr(asid) != physical {
            let base = asid & !0x1ff;
            let address = core::ptr::addr_of!(POOL) as u64;
            #[cfg(target_arch = "x86_64")]
            let pool_physical = kernel_virt_to_phys(address);
            #[cfg(target_arch = "aarch64")]
            let pool_physical = address;
            let pool = Cap::AsidPool {
                ptr: PPtr::<AsidPoolStorage>::new(pool_physical).unwrap(),
                asid_base: base,
            };
            if KERNEL.get().cnodes[0].0[POOL_SLOT].cap().is_null() {
                crate::asid::install_pool(base, pool_physical).expect("fixture pool is unowned");
                KERNEL.get().cnodes[0].0[POOL_SLOT].set_cap(&pool);
            } else {
                assert_eq!(KERNEL.get().cnodes[0].0[POOL_SLOT].cap(), pool);
            }
            crate::asid::install_root(base, pool_physical, asid, physical)
                .expect("fixture ASID and physical root are unassigned");
        }
        let cap = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(physical).unwrap(),
            mapped: true,
            asid,
        };
        KERNEL.get().cnodes[0].0[slot].set_cap(&cap);
        cap
    }

    pub(super) unsafe fn withdraw_pool() {
        assert!(!KERNEL.get().cnodes[0].0[POOL_SLOT].cap().is_null());
        KERNEL.get().cnodes[0].0[POOL_SLOT].set_cap(&Cap::Null);
    }
}
