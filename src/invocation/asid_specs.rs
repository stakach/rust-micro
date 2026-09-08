mod asid_specs {
    use super::*;
    use crate::cap::{AsidPoolStorage, Pml4Storage, UntypedStorage};

    #[repr(C, align(4096))]
    struct Page([u64; 512]);
    static mut POOL: Page = Page([0; 512]);
    static mut REPLACEMENT: Page = Page([0; 512]);
    static mut ROOT: Page = Page([0; 512]);
    static mut OTHER_ROOT: Page = Page([0; 512]);
    static mut IPC: Page = Page([0; 512]);

    #[cfg(target_arch = "x86_64")]
    const MAKE: InvocationLabel = InvocationLabel::X86ASIDControlMakePool;
    #[cfg(target_arch = "aarch64")]
    const MAKE: InvocationLabel = InvocationLabel::ARMASIDControlMakePool;
    #[cfg(target_arch = "x86_64")]
    const ASSIGN: InvocationLabel = InvocationLabel::X86ASIDPoolAssign;
    #[cfg(target_arch = "aarch64")]
    const ASSIGN: InvocationLabel = InvocationLabel::ARMASIDPoolAssign;

    struct Fixture {
        invoker: TcbId,
        pool_pa: u64,
        root_pa: u64,
    }

    impl Fixture {
        unsafe fn new() -> Self {
            let invoker = setup_invoker(0);
            let pool_pa = arch::virt_to_phys(core::ptr::addr_of!(POOL) as u64);
            let root_pa = arch::virt_to_phys(core::ptr::addr_of!(ROOT) as u64);
            for page in [core::ptr::addr_of_mut!(POOL), core::ptr::addr_of_mut!(ROOT),
                core::ptr::addr_of_mut!(OTHER_ROOT), core::ptr::addr_of_mut!(IPC)] {
                core::ptr::write_bytes(page as *mut u8, 0, 4096);
            }
            let cspace = KERNEL.get().scheduler.slab.get(invoker).cspace_root;
            KERNEL.get().scheduler.slab.get_mut(invoker).ipc_buffer_paddr =
                arch::virt_to_phys(core::ptr::addr_of!(IPC) as u64);
            let f = Self { invoker, pool_pa, root_pa };
            f.put(0, cspace);
            f.put(1, Cap::AsidControl);
            f.put(2, cspace);
            f.put(5, Self::untyped(pool_pa));
            f.put(6, Self::root(root_pa));
            f
        }

        fn untyped(physical: u64) -> Cap {
            Cap::Untyped {
                ptr: PAddr::<UntypedStorage>::new(physical), block_bits: 12,
                free_index: 0, is_device: false,
            }
        }

        fn root(physical: u64) -> Cap {
            Cap::PML4 { ptr: PPtr::<Pml4Storage>::new(physical).unwrap(), mapped: false, asid: 0 }
        }

        unsafe fn put(&self, slot: usize, cap: Cap) {
            KERNEL.get().cnodes[0].0[slot].set_cap(&cap);
        }

        unsafe fn cap(&self, slot: usize) -> Cap {
            KERNEL.get().cnodes[0].0[slot].cap()
        }

        unsafe fn stage(&self, caps: &[Cap], cptrs: &[u64]) {
            let tcb = KERNEL.get().scheduler.slab.get_mut(self.invoker);
            tcb.pending_extra_caps_count = caps.len() as u8;
            for (i, cap) in caps.iter().enumerate() {
                tcb.pending_extra_caps[i] = *cap;
            }
            let ipc = core::ptr::addr_of_mut!(IPC) as *mut u64;
            for (i, cptr) in cptrs.iter().enumerate() {
                ipc.add(crate::ipc_buffer::CAPS_OR_BADGES_OFFSET + i).write(*cptr);
            }
        }

        unsafe fn make(&self, upstream: bool) -> KResult<()> {
            let args = if upstream {
                self.stage(&[self.cap(5), self.cap(2)], &[5, 2]);
                SyscallArgs { a0: 1, a1: ((MAKE as u64) << 12) | (2 << 7) | 2,
                    a2: 7, a3: 64, ..Default::default() }
            } else {
                SyscallArgs { a0: 1, a1: (MAKE as u64) << 12,
                    a2: 5, a3: 0, a4: 7, ..Default::default() }
            };
            decode_invocation(Cap::AsidControl, &args, self.invoker)
        }

        unsafe fn assign(&self, pool_slot: usize, upstream: bool) -> KResult<()> {
            let args = if upstream {
                self.stage(&[self.cap(6)], &[6]);
                SyscallArgs { a0: pool_slot as u64, a1: ((ASSIGN as u64) << 12) | (1 << 7),
                    ..Default::default() }
            } else {
                SyscallArgs { a0: pool_slot as u64, a1: (ASSIGN as u64) << 12,
                    a2: 6, ..Default::default() }
            };
            decode_invocation(self.cap(pool_slot), &args, self.invoker)
        }

        unsafe fn copy(&self, source: usize, dest: usize) -> KResult<()> {
            decode_invocation(self.cap(0), &SyscallArgs {
                a1: (InvocationLabel::CNodeCopy as u64) << 12,
                a2: dest as u64, a3: source as u64, ..Default::default()
            }, self.invoker)
        }

        unsafe fn finish(self) {
            for slot in KERNEL.get().cnodes[0].0.iter_mut() {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
                slot.set_child_count(0);
            }
            teardown_invoker(self.invoker);
        }
    }

    fn error(result: KResult<()>, code: seL4_Error) {
        assert!(matches!(result, Err(KException::SyscallError(SyscallError { code: actual }))
            if actual == code));
    }

    pub(super) fn run() {
        unsafe {
            for upstream in [false, true] {
                create_assign_aliases_and_reuse(upstream);
                rejected_make_has_no_effects(upstream);
            }
            exact_staged_sources_and_pool_authority();
            cross_cnode_source_parentage();
        }
        arch::log("  ASID invocation authority, alias lifetime, and exact source publication\n");
    }

    unsafe fn create_assign_aliases_and_reuse(upstream: bool) {
        let f = Fixture::new();
        error(f.copy(6, 9), seL4_Error::seL4_IllegalOperation);
        f.make(upstream).unwrap();
        let Cap::AsidPool { asid_base: base, .. } = f.cap(7) else { panic!("pool missing") };
        assert_eq!(KERNEL.get().cnodes[0].0[7].parent(), Some(crate::cte::MdbId::pack(0, 5)));
        assert_eq!(KERNEL.get().cnodes[0].0[5].child_count(), 1);
        assert!(matches!(f.cap(5), Cap::Untyped { free_index: 4096, .. }));
        f.copy(7, 8).unwrap();
        f.put(7, Cap::Null);
        assert_eq!(crate::asid::pool_status(base, f.pool_pa), Ok(()));
        f.assign(8, upstream).unwrap();
        let assigned = f.cap(6);
        let Cap::PML4 { asid, .. } = assigned else { panic!("root missing") };
        assert_ne!(asid, 0);
        assert_eq!(crate::asid::pml4_paddr(asid), f.root_pa);
        f.copy(6, 9).unwrap();
        f.put(6, Cap::Null);
        assert_eq!(crate::asid::pml4_paddr(asid), f.root_pa);
        f.put(9, Cap::Null);
        assert_eq!(crate::asid::pml4_paddr(asid), 0);
        f.put(6, Fixture::root(f.root_pa));
        f.assign(8, upstream).unwrap();
        assert_eq!(f.cap(6), assigned, "first freed ASID must be reused, without a wrapping allocator");
        error(f.assign(8, upstream), seL4_Error::seL4_InvalidCapability);
        let stale_pool = f.cap(8);
        f.put(8, Cap::Null);
        assert_eq!(crate::asid::pml4_paddr(asid), 0, "final pool retirement invalidates assigned roots");
        f.put(9, stale_pool);
        f.put(6, Fixture::root(f.root_pa));
        error(f.assign(9, upstream), seL4_Error::seL4_FailedLookup);
        let replacement = arch::virt_to_phys(core::ptr::addr_of!(REPLACEMENT) as u64);
        f.put(5, Fixture::untyped(replacement));
        KERNEL.get().cnodes[0].0[5].set_child_count(0);
        f.make(upstream).unwrap();
        assert!(matches!(f.cap(7), Cap::AsidPool { asid_base, .. } if asid_base == base));
        error(f.assign(9, upstream), seL4_Error::seL4_InvalidCapability);
        f.put(9, Cap::Null);
        assert_eq!(crate::asid::pool_status(base, replacement), Ok(()));
        f.finish();
    }

    unsafe fn rejected_make_has_no_effects(upstream: bool) {
        for invalid in 0..4 {
            let f = Fixture::new();
            match invalid {
                0 => f.put(5, Cap::Untyped { ptr: PAddr::new(f.pool_pa), block_bits: 14,
                    free_index: 0, is_device: false }),
                1 => f.put(5, Cap::Untyped { ptr: PAddr::new(f.pool_pa), block_bits: 12,
                    free_index: 0, is_device: true }),
                2 => KERNEL.get().cnodes[0].0[5].set_child_count(1),
                _ => f.put(7, Cap::AsidControl),
            }
            let before = f.cap(5);
            let destination = f.cap(7);
            let free_pool = crate::asid::first_free_pool_base();
            (core::ptr::addr_of_mut!(POOL) as *mut u64).write(0xfeed);
            error(f.make(upstream), match invalid {
                2 => seL4_Error::seL4_RevokeFirst,
                3 => seL4_Error::seL4_DeleteFirst,
                _ => seL4_Error::seL4_InvalidCapability,
            });
            assert_eq!(f.cap(5), before);
            assert_eq!(f.cap(7), destination);
            assert_eq!(crate::asid::first_free_pool_base(), free_pool);
            assert_eq!((core::ptr::addr_of!(POOL) as *const u64).read(), 0xfeed);
            f.finish();
        }
    }

    unsafe fn exact_staged_sources_and_pool_authority() {
        let f = Fixture::new();
        let source = f.cap(5);
        f.stage(&[Fixture::untyped(arch::virt_to_phys(core::ptr::addr_of!(REPLACEMENT) as u64)), f.cap(2)], &[5, 2]);
        let make = SyscallArgs { a0: 1, a1: ((MAKE as u64) << 12) | (2 << 7) | 2,
            a2: 7, a3: 64, ..Default::default() };
        error(decode_invocation(Cap::AsidControl, &make, f.invoker), seL4_Error::seL4_InvalidCapability);
        assert_eq!(f.cap(5), source);
        assert!(f.cap(7).is_null());
        f.make(true).unwrap();
        let root = f.cap(6);
        f.stage(&[Fixture::root(arch::virt_to_phys(core::ptr::addr_of!(OTHER_ROOT) as u64))], &[6]);
        let assign = SyscallArgs { a0: 7, a1: ((ASSIGN as u64) << 12) | (1 << 7), ..Default::default() };
        error(decode_invocation(f.cap(7), &assign, f.invoker), seL4_Error::seL4_InvalidCapability);
        assert_eq!(f.cap(6), root);
        assert_eq!(crate::asid::asid_for_pml4(f.root_pa), None);
        let Cap::AsidPool { asid_base, .. } = f.cap(7) else { panic!("pool missing") };
        let forged = Cap::AsidPool { ptr: PPtr::<AsidPoolStorage>::new(
            arch::virt_to_phys(core::ptr::addr_of!(REPLACEMENT) as u64)).unwrap(), asid_base };
        f.stage(&[root], &[6]);
        error(decode_invocation(forged, &assign, f.invoker), seL4_Error::seL4_InvalidCapability);
        assert_eq!(f.cap(6), root);
        f.finish();
    }

    unsafe fn cross_cnode_source_parentage() {
        let f = Fixture::new();
        for slot in KERNEL.get().cnodes[1].0.iter_mut() {
            slot.set_cap(&Cap::Null);
            slot.set_parent(None);
            slot.set_child_count(0);
        }
        f.put(2, Cap::CNode { ptr: KernelState::cnode_ptr(1), radix: 5, guard_size: 59, guard: 0 });
        f.make(true).unwrap();
        assert!(matches!(KERNEL.get().cnodes[1].0[7].cap(), Cap::AsidPool { .. }));
        assert_eq!(KERNEL.get().cnodes[1].0[7].parent(), Some(crate::cte::MdbId::pack(0, 5)));
        assert!(matches!(f.cap(5), Cap::Untyped { free_index: 4096, .. }));
        assert_eq!(KERNEL.get().cnodes[0].0[5].child_count(), 1);
        KERNEL.get().cnodes[1].0[7].set_cap(&Cap::Null);
        KERNEL.get().cnodes[1].0[7].set_parent(None);
        f.finish();
    }
}
