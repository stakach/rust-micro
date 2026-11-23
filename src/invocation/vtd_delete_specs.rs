/// Refusing DMA retirement must leave the invoking capability reachable and owned.

mod vtd_delete_specs {
    use super::*;
    use crate::cap::{
        FrameMapType, FrameRights, FrameSize, FrameStorage, IoPageTableStorage, UntypedStorage,
    };

    const FIXTURE_REQUESTER: u16 = u16::MAX;
    const TABLE_PHYS: u64 = 0x0080_0000;
    const FRAME_PHYS: u64 = TABLE_PHYS + 0x1000;
    const IO_ADDRESS: u64 = 0x4000;
    const SOURCE: MdbId = MdbId::pack(0, 1);
    const RETIRING: MdbId = MdbId::pack(0, 2);
    const DERIVED: MdbId = MdbId::pack(0, 3);
    const LEAF: MdbId = MdbId::pack(0, 4);

    #[inline(never)]
    fn revoke_refuses_unowned_dma_before_releasing_ownership(nested: bool) {
        let invoker = setup_invoker(0);
        let source_cap = Cap::Untyped {
            ptr: PAddr::<UntypedStorage>::new(TABLE_PHYS),
            block_bits: 14,
            free_index: 0x2000,
            is_device: false,
        };
        let mapped = fixture_frame();
        let root = unsafe {
            let s = KERNEL.get();
            s.cte_mut(SOURCE).unwrap().set_cap(&source_cap);
            s.cte_mut(SOURCE).unwrap().set_child_count(1);
            if nested {
                let vi = s.alloc_small_cnode().expect("nested CNode");
                s.cnode_slot_mut(vi, 0).unwrap().set_cap(&mapped);
                s.cte_mut(RETIRING).unwrap().set_cap(&Cap::CNode {
                    ptr: KernelState::cnode_ptr(vi), radix: 1, guard_size: 63, guard: 0,
                });
            } else {
                s.cte_mut(RETIRING).unwrap().set_cap(&mapped);
            }
            s.cte_mut(RETIRING).unwrap().set_parent(Some(SOURCE));
            s.scheduler.slab.get(invoker).cspace_root()
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: u64::from(SOURCE.slot()),
            ..Default::default()
        };
        assert_eq!(
            decode_invocation(root, &args, invoker),
            Err(KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))),
        );
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.cte(SOURCE).unwrap().cap(), source_cap);
            assert_eq!(s.cte(SOURCE).unwrap().child_count(), 1);
            let retiring = s.cte(RETIRING).unwrap();
            assert_eq!(retiring.parent(), Some(SOURCE), "revoke did not splice the MDB");
            if nested {
                let Cap::CNode { ptr, .. } = retiring.cap() else { panic!("nested CNode survives") };
                let vi = KernelState::cnode_index(ptr);
                assert_eq!(s.cnode_slot(vi, 0).unwrap().cap(), mapped,
                    "CNode still owns the mapped frame");
                s.cnode_slot_mut(vi, 0).unwrap().set_cap(&without_mapping(mapped));
            } else {
                assert_eq!(retiring.cap(), mapped, "mapped frame survives");
                s.cte_mut(RETIRING).unwrap().set_cap(&without_mapping(mapped));
            }
            delete_cap_slot(s, RETIRING).expect("release fixture child");
            delete_cap_slot(s, SOURCE).expect("release fixture source");
        }
        teardown_invoker(invoker);
    }

    #[inline(never)]
    fn revoke_refuses_unowned_tcb_dma_before_releasing_ownership() {
        let invoker = setup_invoker(0);
        let source_cap = Cap::Untyped {
            ptr: PAddr::<UntypedStorage>::new(TABLE_PHYS),
            block_bits: 14,
            free_index: 0x2000,
            is_device: false,
        };
        let mapped = fixture_frame();
        let (root, target) = unsafe {
            let s = KERNEL.get();
            let target = s.scheduler.admit(crate::tcb::Tcb::default());
            let thread_cap = Cap::Thread {
                tcb: PPtr::<crate::cap::Tcb>::new(target.0 as u64).unwrap(),
            };
            s.cte_mut(SOURCE).unwrap().set_cap(&source_cap);
            s.cte_mut(SOURCE).unwrap().set_child_count(1);
            s.cte_mut(RETIRING).unwrap().set_cap(&thread_cap);
            s.cte_mut(RETIRING).unwrap().set_parent(Some(SOURCE));
            assert!(s.write_cte_cap(MdbId::tcb(target, crate::cte::TcbSlot::IpcBuffer), &mapped));
            (s.scheduler.slab.get(invoker).cspace_root(), target)
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: u64::from(SOURCE.slot()),
            ..Default::default()
        };
        assert_eq!(
            decode_invocation(root, &args, invoker),
            Err(KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))),
        );
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.cte(SOURCE).unwrap().cap(), source_cap);
            assert_eq!(s.cte(SOURCE).unwrap().child_count(), 1);
            assert!(matches!(s.cte(RETIRING).unwrap().cap(), Cap::Thread { .. }));
            assert_eq!(s.cte(RETIRING).unwrap().parent(), Some(SOURCE));
            let internal = MdbId::tcb(target, crate::cte::TcbSlot::IpcBuffer);
            assert_eq!(s.cte(internal).unwrap().cap(), mapped,
                "the live TCB still owns its mapped frame");
            assert!(s.write_cte_cap(internal, &without_mapping(mapped)));
            delete_cap_slot(s, RETIRING).expect("release fixture Thread");
            assert!(s.scheduler.slab.try_get(target).is_none());
            delete_cap_slot(s, SOURCE).expect("release fixture source");
        }
        teardown_invoker(invoker);
    }

    #[inline(never)]
    fn delete_refuses_unowned_finalizer_dma(cnode: bool) {
        let invoker = setup_invoker(0);
        let mapped = fixture_frame();
        let (root, inner) = unsafe {
            let s = KERNEL.get();
            let (cap, inner) = if cnode {
                let vi = s.alloc_small_cnode().expect("owned CNode");
                s.cnode_slot_mut(vi, 0).unwrap().set_cap(&mapped);
                (Cap::CNode { ptr: KernelState::cnode_ptr(vi),
                    radix: 1, guard_size: 63, guard: 0 }, MdbId::pack(vi as u32, 0))
            } else {
                let target = s.scheduler.admit(crate::tcb::Tcb::default());
                let inner = MdbId::tcb(target, crate::cte::TcbSlot::IpcBuffer);
                assert!(s.write_cte_cap(inner, &mapped));
                (Cap::Thread { tcb: PPtr::<crate::cap::Tcb>::new(target.0 as u64).unwrap() }, inner)
            };
            s.cte_mut(RETIRING).unwrap().set_cap(&cap);
            (s.scheduler.slab.get(invoker).cspace_root(), inner)
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeDelete as u64) << 12,
            a2: u64::from(RETIRING.slot()),
            ..Default::default()
        };
        assert_eq!(decode_invocation(root, &args, invoker),
            Err(KException::SyscallError(SyscallError::new(seL4_Error::seL4_InvalidCapability))));
        assert!(!unsafe { revoke_retirement_active() },
            "a refused direct finalizer must release its retirement guard");
        unsafe {
            let s = KERNEL.get();
            assert!(!s.cte(RETIRING).unwrap().cap().is_null(), "outer owner survives refusal");
            assert_eq!(s.cte(inner).unwrap().cap(), mapped, "inner mapped cap survives refusal");
            assert!(s.write_cte_cap(inner, &without_mapping(mapped)));
            delete_cap_slot(s, RETIRING).expect("release outer fixture");
        }
        teardown_invoker(invoker);
    }

    fn fixture_frame() -> Cap {
        Cap::Frame {
            ptr: PAddr::<FrameStorage>::new(FRAME_PHYS),
            size: FrameSize::Small,
            rights: FrameRights::ReadWrite,
            mapped: Some(IO_ADDRESS),
            asid: FIXTURE_REQUESTER,
            map_type: FrameMapType::IoSpace,
            is_device: false,
        }
    }

    fn without_mapping(mut cap: Cap) -> Cap {
        match &mut cap {
            Cap::Frame {
                mapped,
                asid,
                map_type,
                ..
            } => {
                *mapped = None;
                *asid = 0;
                *map_type = FrameMapType::None;
            }
            Cap::IoPageTable {
                is_mapped,
                level,
                mapped_address,
                ioasid,
                ..
            } => {
                *is_mapped = false;
                *level = 0;
                *mapped_address = 0;
                *ioasid = 0;
            }
            _ => unreachable!(),
        }
        cap
    }

    #[inline(never)]
    fn refuse_without_releasing_ownership(mapped: Cap, dependent: Option<Cap>, error: seL4_Error) {
        let invoker = setup_invoker(0);
        let source_cap = Cap::Untyped {
            ptr: PAddr::<UntypedStorage>::new(TABLE_PHYS),
            block_bits: 14,
            free_index: 0x2000,
            is_device: false,
        };
        let source_children = 1 + u32::from(dependent.is_some());
        let unmapped = without_mapping(mapped);
        let root = unsafe {
            let s = KERNEL.get();
            let source = s.cte_mut(SOURCE).unwrap();
            source.set_cap(&source_cap);
            source.set_child_count(source_children);
            let retiring = s.cte_mut(RETIRING).unwrap();
            retiring.set_cap(&mapped);
            retiring.set_parent(Some(SOURCE));
            retiring.set_child_count(1);
            // A copy made before the map is not a second live mapping of the table.
            let derived = s.cte_mut(DERIVED).unwrap();
            derived.set_cap(&unmapped);
            derived.set_parent(Some(RETIRING));
            if let Some(leaf_cap) = dependent {
                let leaf = s.cte_mut(LEAF).unwrap();
                leaf.set_cap(&leaf_cap);
                leaf.set_parent(Some(SOURCE));
            }
            s.scheduler.slab.get(invoker).cspace_root()
        };
        let args = SyscallArgs {
            a1: (InvocationLabel::CNodeDelete as u64) << 12,
            a2: u64::from(RETIRING.slot()),
            ..Default::default()
        };
        assert_eq!(
            decode_invocation(root, &args, invoker),
            Err(KException::SyscallError(SyscallError::new(error))),
        );
        unsafe {
            let s = KERNEL.get();
            let source = s.cte(SOURCE).unwrap();
            assert_eq!(source.cap(), source_cap, "Untyped watermark remains held");
            assert_eq!(source.child_count(), source_children);
            let retiring = s.cte(RETIRING).unwrap();
            assert_eq!(
                retiring.cap(),
                mapped,
                "mapped capability remains reachable"
            );
            assert_eq!(retiring.parent(), Some(SOURCE));
            assert_eq!(retiring.child_count(), 1);
            let derived = s.cte(DERIVED).unwrap();
            assert_eq!(derived.cap(), unmapped);
            assert_eq!(
                derived.parent(),
                Some(RETIRING),
                "refusal does not splice the MDB"
            );
            if let Some(leaf) = dependent {
                assert_eq!(s.cte(LEAF).unwrap().cap(), leaf);
                assert_eq!(s.cte(LEAF).unwrap().parent(), Some(SOURCE));
                // The synthetic fixture has no hardware mappings or MMIO to tear down.
                s.cte_mut(LEAF).unwrap().set_cap(&without_mapping(leaf));
                delete_cap_slot(s, LEAF).unwrap();
            }
            s.cte_mut(RETIRING).unwrap().set_cap(&unmapped);
            for id in [DERIVED, RETIRING, SOURCE] {
                delete_cap_slot(s, id).unwrap();
            }
        }
        teardown_invoker(invoker);
    }

    pub(super) fn run() {
        unsafe {
            assert!(
                crate::arch::x86_64::iommu::lookup_vtd_context_slot(FIXTURE_REQUESTER, false)
                    .is_none(),
                "the fixture must not use an installed requester",
            );
        }
        let table = Cap::IoPageTable {
            ptr: PPtr::<IoPageTableStorage>::new(TABLE_PHYS).unwrap(),
            is_mapped: true,
            level: 0,
            mapped_address: 0,
            ioasid: FIXTURE_REQUESTER,
        };
        refuse_without_releasing_ownership(
            table,
            Some(fixture_frame()),
            seL4_Error::seL4_DeleteFirst,
        );
        refuse_without_releasing_ownership(
            fixture_frame(),
            None,
            seL4_Error::seL4_InvalidCapability,
        );
        revoke_refuses_unowned_dma_before_releasing_ownership(false);
        revoke_refuses_unowned_dma_before_releasing_ownership(true);
        revoke_refuses_unowned_tcb_dma_before_releasing_ownership();
        delete_refuses_unowned_finalizer_dma(true);
        delete_refuses_unowned_finalizer_dma(false);
        arch::log("  refused VT-d capability deletion preserves the mapped cap and MDB\n");
    }
}
