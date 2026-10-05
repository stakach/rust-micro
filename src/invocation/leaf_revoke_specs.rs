mod leaf_revoke_specs {
    use super::*;
    use crate::cap::{FrameMapType, FrameRights, FrameSize, FrameStorage, PAddr, UntypedStorage};

    fn scans() -> usize {
        crate::kernel::CTE_CURSOR_NEXT_CALLS.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn revoke(root: Cap, invoker: TcbId, slot: u64) -> KResult<()> {
        decode_invocation(root, &SyscallArgs {
            a1: (InvocationLabel::CNodeRevoke as u64) << 12,
            a2: slot,
            ..Default::default()
        }, invoker)
    }

    fn root(invoker: TcbId) -> Cap {
        unsafe { KERNEL.get().scheduler.slab.get(invoker).cspace_root() }
    }

    fn frame() -> Cap {
        Cap::Frame {
            ptr: PAddr::<FrameStorage>::new(0x4000_0000),
            size: FrameSize::Small,
            rights: FrameRights::ReadWrite,
            mapped: Some(0x8000_0000),
            asid: 7,
            is_device: true,
            map_type: FrameMapType::VSpace,
        }
    }

    #[inline(never)]
    fn leaf_frame_preserves_source_without_registry_scan() {
        let invoker = setup_invoker(0);
        let source = frame();
        let parent = MdbId::pack(0, 1);
        unsafe {
            let s = KERNEL.get();
            s.cnodes[0].0[1].set_cap(&Cap::Untyped {
                ptr: PAddr::<UntypedStorage>::new(0x4000_0000),
                block_bits: 12, free_index: 256, is_device: true,
            });
            s.cnodes[0].0[2].set_cap(&source);
            s.cnodes[0].0[2].set_parent(Some(parent));
            child_count_inc(parent, 1);
        }
        let before = scans();
        revoke(root(invoker), invoker, 2).expect("leaf frame revoke");
        assert_eq!(scans(), before, "leaf revoke must not walk any global CTE registry");
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.cnodes[0].0[2].cap(), source);
            assert_eq!(s.cnodes[0].0[2].parent(), Some(parent));
            assert_eq!(s.cnodes[0].0[2].child_count(), 0);
            assert_eq!(s.cnodes[0].0[1].child_count(), 1);
            assert_eq!(s.cnodes[0].0[2].revoke_epoch(), 0);
            assert!(matches!(s.cnodes[0].0[1].cap(), Cap::Untyped { free_index: 256, .. }));
        }
        teardown_invoker(invoker);
        arch::log("  leaf Frame revoke preserves source mapping and derivation without scans\n");
    }

    #[inline(never)]
    fn empty_source_is_scan_free_noop() {
        let invoker = setup_invoker(0);
        let before = scans();
        revoke(root(invoker), invoker, 2).expect("empty revoke");
        assert_eq!(scans(), before, "empty revoke must not walk the CTE registry");
        unsafe {
            let slot = &KERNEL.get().cnodes[0].0[2];
            assert!(slot.cap().is_null());
            assert_eq!(slot.parent(), None);
            assert_eq!(slot.child_count(), 0);
            assert_eq!(slot.revoke_epoch(), 0);
        }
        teardown_invoker(invoker);
    }

    #[inline(never)]
    fn empty_untyped_resets_watermark_before_real_retype() {
        let invoker = setup_invoker(0);
        let source = Cap::Untyped {
            ptr: PAddr::<UntypedStorage>::new(spec_ram_paddr(0x00D0_0000)),
            block_bits: 14, free_index: 1024, is_device: false,
        };
        unsafe { KERNEL.get().cnodes[0].0[1].set_cap(&source); }
        let before = scans();
        revoke(root(invoker), invoker, 1).expect("empty Untyped revoke");
        assert_eq!(scans(), before, "empty Untyped revoke must not scan");
        let reset = unsafe { KERNEL.get().cnodes[0].0[1].cap() };
        assert!(matches!(reset, Cap::Untyped { free_index: 0, block_bits: 14, is_device: false, .. }));
        if let (Cap::Untyped { ptr: original, .. }, Cap::Untyped { ptr: actual, .. }) = (source, reset) {
            assert_eq!(actual, original);
        } else { panic!("Untyped identity must survive revoke"); }
        decode_invocation(reset, &SyscallArgs {
            a0: 1,
            a1: (InvocationLabel::UntypedRetype as u64) << 12,
            a2: ObjectType::Endpoint.to_word(), a3: 1, a4: 4,
            ..Default::default()
        }, invoker).expect("genuine Retype after watermark reset");
        unsafe {
            let s = KERNEL.get();
            assert!(matches!(s.cnodes[0].0[4].cap(), Cap::Endpoint { .. }));
            assert_eq!(s.cnodes[0].0[4].parent(), Some(MdbId::pack(0, 1)));
            assert_eq!(s.cnodes[0].0[1].child_count(), 1);
            delete_cap_slot(s, MdbId::pack(0, 4)).expect("release retyped endpoint");
        }
        teardown_invoker(invoker);
    }

    #[inline(never)]
    fn invalid_source_rejected_before_leaf_admission() {
        let invoker = setup_invoker(0);
        let before = scans();
        assert!(matches!(revoke(root(invoker), invoker, MdbId::SLOT_MASK + 1),
            Err(KException::SyscallError(SyscallError { code: seL4_Error::seL4_RangeError }))));
        assert_eq!(scans(), before);
        teardown_invoker(invoker);
    }

    #[inline(never)]
    fn tcb_internal_child_requires_real_revoke_walk() {
        let invoker = setup_invoker(0);
        let target = unsafe {
            let s = KERNEL.get();
            let mut source = frame();
            if let Cap::Frame { mapped, asid, .. } = &mut source {
                *mapped = None;
                *asid = 0;
            }
            // IPC buffers cannot derive from device frames.
            if let Cap::Frame { is_device, .. } = &mut source { *is_device = false; }
            s.cnodes[0].0[1].set_cap(&source);
            let target = s.scheduler.admit(crate::tcb::Tcb::default());
            derive_tcb_cap(s, target, crate::cte::TcbSlot::IpcBuffer,
                Some(MdbId::pack(0, 1)), 0x1000).expect("derive exact TCB IPC cap");
            assert_eq!(s.cnodes[0].0[1].child_count(), 1);
            target
        };
        let before = scans();
        revoke(root(invoker), invoker, 1).expect("revoke TCB internal child");
        assert!(scans() > before, "nonleaf must retain the descendant traversal");
        unsafe {
            let s = KERNEL.get();
            assert!(s.cte(MdbId::tcb(target, crate::cte::TcbSlot::IpcBuffer)).unwrap().cap().is_null());
            assert_eq!(s.cnodes[0].0[1].child_count(), 0);
            assert!(matches!(s.cnodes[0].0[1].cap(), Cap::Frame { .. }));
            teardown_thread_in(s, target);
        }
        teardown_invoker(invoker);
    }

    pub(super) fn run() {
        leaf_frame_preserves_source_without_registry_scan();
        empty_source_is_scan_free_noop();
        empty_untyped_resets_watermark_before_real_retype();
        invalid_source_rejected_before_leaf_admission();
        tcb_internal_child_requires_real_revoke_walk();
    }
}
