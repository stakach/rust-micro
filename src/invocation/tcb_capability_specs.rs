#[cfg(target_arch = "x86_64")]
mod tcb_capability_specs {
    use super::*;
    use crate::cap::UntypedStorage;
    use crate::cte::{MdbId, TcbSlot};

    #[repr(C, align(4096))]
    struct Page([u8; 4096]);
    static mut POOL: Page = Page([0; 4096]);
    static mut FIRST: Page = Page([0; 4096]);
    static mut SECOND: Page = Page([0; 4096]);
    static mut MAPPING_PAGES: [Page; 4] = [const { Page([0; 4096]) }; 4];
    const MAPPED_ADDRESS: u64 = (129 << 39) | (3 << 30) | (5 << 21) | (7 << 12);

    struct ReleaseObservation {
        source: MdbId,
        online: u32,
        flushes: [u32; crate::smp::MAX_CPUS],
        observed: bool,
    }

    static mut RELEASE_OBSERVATION: Option<ReleaseObservation> = None;

    /// Called while the source CTE is borrowed; this must never access KernelState.
    pub(super) fn observe_untyped_release(parent_id: MdbId) {
        unsafe {
            let Some(observation) = (&mut *core::ptr::addr_of_mut!(RELEASE_OBSERVATION)).as_mut()
                else { return; };
            if observation.source != parent_id { return; }
            let (_, flushes, active) = crate::smp::retirement_spec_snapshot();
            assert!(!active, "Untyped reset must follow retirement completion");
            for cpu in 0..crate::smp::MAX_CPUS {
                if observation.online & (1 << cpu) != 0 {
                    assert!(flushes[cpu] > observation.flushes[cpu],
                        "every online CPU must flush before physical backing is reusable");
                }
            }
            observation.observed = true;
        }
    }

    unsafe fn observe_release_of(source: usize) {
        assert!((&*core::ptr::addr_of!(RELEASE_OBSERVATION)).is_none());
        let (online, flushes, active) = crate::smp::retirement_spec_snapshot();
        assert!(!active);
        core::ptr::write(core::ptr::addr_of_mut!(RELEASE_OBSERVATION), Some(ReleaseObservation {
            source: MdbId::pack(0, source as u32), online, flushes, observed: false,
        }));
    }

    unsafe fn assert_release_observed() {
        let observation = (&mut *core::ptr::addr_of_mut!(RELEASE_OBSERVATION)).take().unwrap();
        assert!(observation.observed, "the actual Untyped release hook must execute");
    }

    struct Fixture {
        invoker: TcbId,
        targets: [TcbId; 2],
        cspace: Cap,
        first: u64,
    }

    impl Fixture {
        unsafe fn new() -> Self {
            let invoker = setup_invoker(0);
            let state = KERNEL.get();
            let cspace = state.scheduler.slab.get(invoker).cspace_root();
            let targets = [
                state.scheduler.admit(crate::tcb::Tcb::default()),
                state.scheduler.admit(crate::tcb::Tcb::default()),
            ];
            let first = arch::virt_to_phys(core::ptr::addr_of!(FIRST) as u64);
            let f = Self { invoker, targets, cspace, first };
            f.put(1, cspace);
            f.put(2, Cap::AsidControl);
            f.put(3, Self::untyped(arch::virt_to_phys(core::ptr::addr_of!(POOL) as u64)));
            f.put(5, Self::untyped(first));
            f.put(7, Self::untyped(arch::virt_to_phys(core::ptr::addr_of!(SECOND) as u64)));
            f
        }

        fn untyped(physical: u64) -> Cap {
            Cap::Untyped {
                ptr: PAddr::<UntypedStorage>::new(physical), block_bits: 12,
                free_index: 0, is_device: false,
            }
        }

        unsafe fn put(&self, slot: usize, cap: Cap) {
            KERNEL.get().cnodes[0].0[slot].set_cap(&cap);
        }

        unsafe fn cap(&self, slot: usize) -> Cap {
            KERNEL.get().cnodes[0].0[slot].cap()
        }

        unsafe fn retype(&self, source: usize, dest: usize, kind: ObjectType, bits: u32) {
            decode_invocation(self.cap(source), &SyscallArgs {
                a0: source as u64,
                a1: (InvocationLabel::UntypedRetype as u64) << 12,
                a2: kind.to_word(), a3: ((bits as u64) << 32) | 1,
                a4: dest as u64, ..Default::default()
            }, self.invoker).unwrap();
        }

        unsafe fn cnode(&self, label: InvocationLabel, source: usize, dest: usize) {
            decode_invocation(self.cspace, &SyscallArgs {
                a0: 1, a1: (label as u64) << 12,
                a2: if label == InvocationLabel::CNodeMove { dest } else { source } as u64,
                a3: source as u64, ..Default::default()
            }, self.invoker).unwrap();
        }

        unsafe fn bind(&self, target: usize, slot: TcbSlot, source: usize, data: u64) {
            derive_tcb_cap(KERNEL.get(), self.targets[target], slot,
                Some(MdbId::pack(0, source as u32)), data).unwrap();
        }

        unsafe fn internal(&self, target: usize, slot: TcbSlot) -> Cap {
            KERNEL.get().cte(MdbId::tcb(self.targets[target], slot)).unwrap().cap()
        }

        unsafe fn make_pool(&self) {
            decode_invocation(self.cap(2), &SyscallArgs {
                a0: 2, a1: (InvocationLabel::X86ASIDControlMakePool as u64) << 12,
                a2: 3, a3: 0, a4: 4, ..Default::default()
            }, self.invoker).unwrap();
        }

        unsafe fn assign(&self, root: usize) -> u16 {
            decode_invocation(self.cap(4), &SyscallArgs {
                a0: 4, a1: (InvocationLabel::X86ASIDPoolAssign as u64) << 12,
                a2: root as u64, ..Default::default()
            }, self.invoker).unwrap();
            let Cap::PML4 { asid, .. } = self.cap(root) else { panic!("assigned root"); };
            asid
        }

        unsafe fn assert_reclaimed(&self, source: usize) {
            assert!(matches!(self.cap(source), Cap::Untyped { free_index: 0, .. }));
            assert_eq!(KERNEL.get().cnodes[0].0[source].child_count(), 0);
        }

        unsafe fn finish(self) {
            let state = KERNEL.get();
            for target in self.targets {
                retire_tcb(state, target);
            }
            for slot in 0..32 {
                delete_cap_slot(state, MdbId::pack(0, slot)).unwrap();
            }
            teardown_invoker(self.invoker);
        }
    }

    pub(super) fn run() {
        unsafe {
            root_move_delete_revoke_precedes_backing_reuse();
            cspace_retention_and_ancestor_revoke();
            fault_and_timeout_revoke_withdraws_authority();
            ipc_frame_revoke_clears_byte_access_before_retype();
            mapped_frame_revoke_flushes_before_backing_reuse();
            mapped_table_revoke_flushes_before_backing_reuse();
            revoke_source_inside_derived_cnode(false);
            revoke_source_inside_derived_cnode(true);
        }
        arch::log("  TCB internal capabilities follow real Untyped derivation and revocation\n");
    }

    unsafe fn root_move_delete_revoke_precedes_backing_reuse() {
        let f = Fixture::new();
        f.make_pool();
        f.retype(5, 6, ObjectType::Arch(crate::object_type::X86_PML4), 0);
        f.retype(7, 8, ObjectType::Arch(crate::object_type::X86_PML4), 0);
        let first_asid = f.assign(6);
        let other_asid = f.assign(8);
        f.bind(0, TcbSlot::VSpace, 6, 0);
        f.bind(1, TcbSlot::VSpace, 8, 0);
        assert_eq!(crate::asid::pml4_refcount(first_asid), 2);
        let internal = MdbId::tcb(f.targets[0], TcbSlot::VSpace);
        assert_eq!(KERNEL.get().cte(internal).unwrap().parent(), Some(MdbId::pack(0, 6)));

        f.cnode(InvocationLabel::CNodeMove, 6, 9);
        assert!(f.cap(6).is_null());
        assert_eq!(KERNEL.get().cte(internal).unwrap().parent(), Some(MdbId::pack(0, 9)));
        f.cnode(InvocationLabel::CNodeDelete, 9, 0);
        assert_eq!(KERNEL.get().cte(internal).unwrap().parent(), Some(MdbId::pack(0, 5)));
        assert_eq!(crate::asid::pml4_refcount(first_asid), 1);
        assert!(KERNEL.get().scheduler.slab.get(f.targets[0]).has_current_vspace());

        let other = f.internal(1, TcbSlot::VSpace);
        f.cnode(InvocationLabel::CNodeRevoke, 5, 0);
        assert!(f.internal(0, TcbSlot::VSpace).is_null());
        assert_eq!(crate::asid::pml4_paddr(first_asid), 0);
        assert_eq!(KERNEL.get().scheduler.slab.get(f.targets[0]).vm_root_cr3(),
            crate::arch::x86_64::paging::kernel_root_cr3());
        assert_eq!(f.internal(1, TcbSlot::VSpace), other);
        assert_eq!(crate::asid::pml4_refcount(other_asid), 2);
        f.assert_reclaimed(5);

        f.retype(5, 16, ObjectType::Arch(crate::object_type::X86_PML4), 0);
        let Cap::PML4 { ptr, .. } = f.cap(16) else { panic!("retyped root"); };
        assert_eq!(ptr.addr(), f.first);
        f.assign(16);
        assert!(!KERNEL.get().scheduler.slab.get(f.targets[0]).has_current_vspace());
        assert!(KERNEL.get().scheduler.slab.get(f.targets[1]).has_current_vspace());
        f.finish();
    }

    unsafe fn cspace_retention_and_ancestor_revoke() {
        let f = Fixture::new();
        f.retype(5, 6, ObjectType::CapTable, 2);
        f.bind(0, TcbSlot::CSpace, 6, 0);
        let cap = f.cap(6);
        let Cap::CNode { ptr, .. } = cap else { panic!("retyped CNode"); };
        let index = KernelState::cnode_index(ptr);
        f.cnode(InvocationLabel::CNodeDelete, 6, 0);
        assert_eq!(f.internal(0, TcbSlot::CSpace), cap);
        assert!(KERNEL.get().cnode_slots_at(index).is_some());
        f.cnode(InvocationLabel::CNodeRevoke, 5, 0);
        assert!(f.internal(0, TcbSlot::CSpace).is_null());
        assert!(KERNEL.get().cnode_slots_at(index).is_none());
        f.assert_reclaimed(5);
        f.retype(5, 16, ObjectType::CapTable, 2);
        assert!(matches!(f.cap(16), Cap::CNode { ptr: new, .. } if new == ptr));
        assert!(f.internal(0, TcbSlot::CSpace).is_null());
        f.finish();
    }

    unsafe fn fault_and_timeout_revoke_withdraws_authority() {
        let f = Fixture::new();
        f.retype(5, 6, ObjectType::Endpoint, 0);
        f.retype(7, 8, ObjectType::Endpoint, 0);
        f.bind(0, TcbSlot::FaultHandler, 6, 0);
        f.bind(0, TcbSlot::Timeout, 6, 0);
        f.bind(1, TcbSlot::FaultHandler, 8, 0);
        bind_invoker_cap(KERNEL.get(), f.targets[0], TcbSlot::CSpace, f.cspace, 0);
        let other = f.internal(1, TcbSlot::FaultHandler);
        f.cnode(InvocationLabel::CNodeRevoke, 5, 0);
        assert!(f.internal(0, TcbSlot::FaultHandler).is_null());
        assert!(f.internal(0, TcbSlot::Timeout).is_null());
        assert_eq!(f.internal(1, TcbSlot::FaultHandler), other);
        f.assert_reclaimed(5);

        // Reusing the original source CPtr cannot restore the revoked internal endpoint.
        f.cnode(InvocationLabel::CNodeMove, 8, 6);
        assert_eq!(crate::cspace::lookup_cap(KERNEL.get(), &f.cspace, 6).unwrap(), other);
        assert!(crate::fault::deliver_fault(f.targets[0],
            crate::fault::FaultMessage::UnknownSyscall { number: 99 }).is_err());
        assert!(!crate::fault::deliver_timeout_fault(f.targets[0]));
        f.finish();
    }

    unsafe fn ipc_frame_revoke_clears_byte_access_before_retype() {
        let f = Fixture::new();
        f.retype(5, 6, ObjectType::Arch(crate::object_type::X86_4K), 0);
        f.bind(0, TcbSlot::IpcBuffer, 6, 0x2400);
        let thread = KERNEL.get().scheduler.slab.get(f.targets[0]);
        assert_eq!(thread.ipc_buffer_send_paddr(), f.first + 1024);
        assert_eq!(thread.ipc_buffer_receive_paddr(), f.first + 1024);
        assert!(matches!(thread.ipc_buffer_cap(), Cap::Frame {
            mapped: None, asid: 0, map_type: crate::cap::FrameMapType::None, ..
        }));
        f.cnode(InvocationLabel::CNodeRevoke, 5, 0);
        let thread = KERNEL.get().scheduler.slab.get(f.targets[0]);
        assert_eq!(thread.ipc_buffer, 0);
        assert_eq!(thread.ipc_buffer_send_paddr(), 0);
        assert_eq!(thread.ipc_buffer_receive_paddr(), 0);
        assert!(thread.ipc_buffer_cap().is_null());
        f.assert_reclaimed(5);
        f.retype(5, 16, ObjectType::Arch(crate::object_type::X86_4K), 0);
        assert!(matches!(f.cap(16), Cap::Frame { ptr, .. } if ptr.addr() == f.first));
        assert_eq!(KERNEL.get().scheduler.slab.get(f.targets[0]).ipc_buffer_receive_paddr(), 0);
        f.finish();
    }

    unsafe fn mapped_fixture() -> (Fixture, *mut u64, *mut u64) {
        let f = Fixture::new();
        f.make_pool();
        f.retype(5, 6, ObjectType::Arch(crate::object_type::X86_PML4), 0);
        f.retype(7, 8, ObjectType::Arch(crate::object_type::X86_PML4), 0);
        f.assign(6);
        f.assign(8);
        f.bind(0, TcbSlot::VSpace, 6, 0);
        f.bind(1, TcbSlot::VSpace, 8, 0);
        let pages = core::ptr::addr_of_mut!(MAPPING_PAGES) as *mut Page;
        for (index, kind) in [crate::object_type::X86_PDPT, crate::object_type::X86_PAGE_DIRECTORY,
            crate::object_type::X86_PAGE_TABLE, crate::object_type::X86_4K].into_iter().enumerate()
        {
            let source = 10 + index * 2;
            f.put(source, Fixture::untyped(arch::virt_to_phys(pages.add(index) as u64)));
            f.retype(source, source + 1, ObjectType::Arch(kind), 0);
        }
        for (slot, label) in [(11, InvocationLabel::X86PDPTMap),
            (13, InvocationLabel::X86PageDirectoryMap), (15, InvocationLabel::X86PageTableMap)]
        {
            decode_invocation(f.cap(slot), &SyscallArgs {
                a0: slot as u64, a1: (label as u64) << 12,
                a2: MAPPED_ADDRESS, a3: 6, ..Default::default()
            }, f.invoker).unwrap();
        }
        decode_invocation(f.cap(17), &SyscallArgs {
            a0: 17, a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: MAPPED_ADDRESS, a3: 3, a4: 6, ..Default::default()
        }, f.invoker).unwrap();
        let parent = (pages.add(1) as *mut u64).add(5);
        let leaf = (pages.add(2) as *mut u64).add(7);
        assert_eq!(parent.read_volatile() & 0x000f_ffff_ffff_f000,
            arch::virt_to_phys(pages.add(2) as u64));
        assert_eq!(leaf.read_volatile() & 0x000f_ffff_ffff_f000,
            arch::virt_to_phys(pages.add(3) as u64));
        assert_eq!(parent.read_volatile() & 7, 7);
        assert_eq!(leaf.read_volatile() & 7, 7);
        (f, parent, leaf)
    }

    unsafe fn assert_other_root_unchanged(f: &Fixture, expected: Cap) {
        assert_eq!(f.internal(1, TcbSlot::VSpace), expected);
        assert!(crate::asid::root_is_current(&expected));
        assert!(KERNEL.get().scheduler.slab.get(f.targets[1]).has_current_vspace());
        let second = core::ptr::addr_of!(SECOND) as *const u64;
        for index in 0..256 { assert_eq!(second.add(index).read_volatile(), 0); }
    }

    unsafe fn mapped_frame_revoke_flushes_before_backing_reuse() {
        let (f, parent, leaf) = mapped_fixture();
        let other = f.internal(1, TcbSlot::VSpace);
        let parent_entry = parent.read_volatile();
        let Cap::Frame { ptr: backing, .. } = f.cap(17) else { panic!("mapped frame"); };
        observe_release_of(16);
        f.cnode(InvocationLabel::CNodeRevoke, 16, 0);
        assert_release_observed();
        assert_eq!(leaf.read_volatile(), 0);
        assert_eq!(parent.read_volatile(), parent_entry);
        f.assert_reclaimed(16);
        f.retype(16, 18, ObjectType::Arch(crate::object_type::X86_4K), 0);
        assert!(matches!(f.cap(18), Cap::Frame { ptr, mapped: None, .. } if ptr == backing));
        assert_eq!(leaf.read_volatile(), 0, "retype does not recreate a retired mapping");
        assert_other_root_unchanged(&f, other);
        f.finish();
    }

    unsafe fn mapped_table_revoke_flushes_before_backing_reuse() {
        let (f, parent, _) = mapped_fixture();
        let other = f.internal(1, TcbSlot::VSpace);
        let Cap::PageTable { ptr: backing, .. } = f.cap(15) else { panic!("mapped table"); };
        observe_release_of(14);
        f.cnode(InvocationLabel::CNodeRevoke, 14, 0);
        assert_release_observed();
        assert_eq!(parent.read_volatile(), 0);
        f.assert_reclaimed(14);
        f.retype(14, 18, ObjectType::Arch(crate::object_type::X86_PAGE_TABLE), 0);
        assert!(matches!(f.cap(18), Cap::PageTable { ptr, mapped: None, .. } if ptr == backing));
        assert_eq!(parent.read_volatile(), 0, "table backing reuse cannot reconnect its subtree");
        assert_other_root_unchanged(&f, other);
        f.finish();
    }

    unsafe fn move_into_derived_cnode(f: &Fixture, source: usize, destination: usize) {
        let invoker = KERNEL.get().scheduler.slab.get_mut(f.invoker);
        invoker.pending_extra_caps_count = 1;
        invoker.pending_extra_caps[0] = f.cspace;
        decode_invocation(f.cap(6), &SyscallArgs {
            a0: 6, a1: ((InvocationLabel::CNodeMove as u64) << 12) | (1 << 7) | 4,
            a2: destination as u64, a3: 2, a4: source as u64, a5: 64,
        }, f.invoker).unwrap();
    }

    unsafe fn revoke_source_inside_derived_cnode(thread_cycle: bool) {
        let f = Fixture::new();
        f.retype(5, 6, ObjectType::CapTable, 2);
        let Cap::CNode { ptr, .. } = f.cap(6) else { panic!("derived CNode"); };
        let cnode_index = KernelState::cnode_index(ptr);
        let target = if thread_cycle {
            f.retype(7, 8, ObjectType::Tcb, 0);
            let Cap::Thread { tcb } = f.cap(8) else { panic!("derived Thread"); };
            let target = TcbId(tcb.addr() as u16);
            move_into_derived_cnode(&f, 8, 1);
            target
        } else {
            f.targets[0]
        };
        derive_tcb_cap(KERNEL.get(), target, TcbSlot::CSpace, Some(MdbId::pack(0, 6)), 0)
            .unwrap();
        move_into_derived_cnode(&f, 5, 0);
        let source = MdbId::pack(cnode_index as u32, 0);
        assert!(f.cap(5).is_null());
        assert_eq!(KERNEL.get().cte(MdbId::pack(0, 6)).unwrap().parent(), Some(source));
        assert!(matches!(KERNEL.get().cte(source).unwrap().cap(), Cap::Untyped { .. }));
        decode_invocation(f.cap(6), &SyscallArgs {
            a0: 6, a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: 0, ..Default::default()
        }, f.invoker).unwrap();
        assert!(f.cap(6).is_null());
        assert!(KERNEL.get().cte(source).is_none(), "revoke may destroy its own source CNode");
        assert!(KERNEL.get().cnode_slots_at(cnode_index).is_none());
        if thread_cycle {
            assert!(KERNEL.get().scheduler.slab.try_get(target).is_none(),
                "the queued Thread finalizer must drain the closed CNode/TCB cycle");
            f.assert_reclaimed(7);
        } else {
            assert!(KERNEL.get().scheduler.slab.get(target).cspace_root().is_null());
        }
        assert_eq!(KERNEL.get().scheduler.slab.get(f.invoker).cspace_root(), f.cspace);
        f.finish();
    }
}
