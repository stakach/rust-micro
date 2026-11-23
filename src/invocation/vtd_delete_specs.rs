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
        arch::log("  refused VT-d capability deletion preserves the mapped cap and MDB\n");
    }
}
