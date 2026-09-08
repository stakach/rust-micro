mod cnode_frame_specs {
    use super::*;
    use crate::cap::{FrameMapType, FrameRights, FrameSize, FrameStorage, PAddr};

    fn frame(rights: FrameRights, size: FrameSize) -> Cap {
        Cap::Frame {
            ptr: PAddr::<FrameStorage>::new(0x4000_0000),
            size,
            rights,
            mapped: Some(0x8000_0000),
            asid: 7,
            is_device: true,
            map_type: FrameMapType::VSpace,
        }
    }

    fn args(mint: bool, length: u64) -> SyscallArgs {
        SyscallArgs {
            a1: ((if mint { InvocationLabel::CNodeMint } else { InvocationLabel::CNodeCopy })
                as u64) << 12 | (1 << 7) | length,
            a2: 2,
            a3: crate::cspace::WORD_BITS as u64,
            a4: 1,
            a5: crate::cspace::WORD_BITS as u64,
            ..Default::default()
        }
    }

    fn stage(invoker: TcbId, root: Cap, rights: u64) {
        unsafe {
            let tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
            tcb.pending_extra_caps_count = 1;
            tcb.pending_extra_caps[0] = root;
            tcb.msg_regs[4] = rights;
            tcb.msg_regs[5] = 0x1234;
        }
    }

    #[inline(never)]
    fn attenuation() {
        for mint in [false, true] {
            for size in [FrameSize::Small, FrameSize::Large, FrameSize::Huge] {
                for source_rights in [FrameRights::KernelOnly, FrameRights::ReadOnly,
                    FrameRights::ReadWrite] {
                    for mask in 0..8u64 {
                        let invoker = setup_invoker(0);
                        let source = frame(source_rights, size);
                        let root = unsafe {
                            let s = KERNEL.get();
                            s.cnodes[0].0[1].set_cap(&source);
                            s.scheduler.slab.get(invoker).cspace_root
                        };
                        stage(invoker, root, mask);
                        decode_invocation(root, &args(mint, if mint { 6 } else { 5 }), invoker)
                            .expect("frame derivation succeeds");
                        let expected_rights = if mask & 2 == 0 {
                            FrameRights::KernelOnly
                        } else {
                            match source_rights {
                                FrameRights::ReadWrite if mask & 1 == 0 => FrameRights::ReadOnly,
                                rights => rights,
                            }
                        };
                        unsafe {
                            let s = KERNEL.get();
                            assert_eq!(s.cnodes[0].0[1].cap(), source);
                            assert_eq!(s.cnodes[0].0[1].child_count(), 1);
                            assert_eq!(s.cnodes[0].0[2].cap(), Cap::Frame {
                                ptr: PAddr::<FrameStorage>::new(0x4000_0000),
                                size,
                                rights: expected_rights,
                                mapped: None,
                                asid: 0,
                                is_device: true,
                                map_type: FrameMapType::None,
                            });
                            assert_eq!(s.cnodes[0].0[2].parent(),
                                Some(crate::cte::MdbId::pack(0, 1)));
                        }
                        teardown_invoker(invoker);
                    }
                }
            }
        }
    }

    #[inline(never)]
    fn malformed_requests_preserve_slots() {
        for mint in [false, true] {
            let required = if mint { 6 } else { 5 };
            for length in 0..required {
                let invoker = setup_invoker(0);
                let source = frame(FrameRights::ReadWrite, FrameSize::Small);
                let root = unsafe {
                    let s = KERNEL.get();
                    s.cnodes[0].0[1].set_cap(&source);
                    s.scheduler.slab.get(invoker).cspace_root
                };
                stage(invoker, root, 3);
                assert_eq!(decode_invocation(root, &args(mint, length), invoker),
                    Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_TruncatedMessage))));
                assert_untouched(invoker, source);
                teardown_invoker(invoker);
            }
            for supplied in [false, true] {
                let invoker = setup_invoker(0);
                let source = frame(FrameRights::ReadWrite, FrameSize::Small);
                let root = unsafe {
                    let s = KERNEL.get();
                    s.cnodes[0].0[1].set_cap(&source);
                    s.scheduler.slab.get(invoker).cspace_root
                };
                stage(invoker, Cap::Null, 3);
                if !supplied {
                    unsafe { KERNEL.get().scheduler.slab.get_mut(invoker)
                        .pending_extra_caps_count = 0; }
                }
                let result = decode_invocation(root, &args(mint, required), invoker);
                assert!(result.is_err(), "missing root cannot use invoker CSpace");
                if !supplied {
                    assert_eq!(result, Err(KException::SyscallError(SyscallError::new(
                        seL4_Error::seL4_TruncatedMessage))));
                }
                assert_untouched(invoker, source);
                teardown_invoker(invoker);
            }
        }
    }

    fn assert_untouched(invoker: TcbId, source: Cap) {
        unsafe {
            let s = KERNEL.get();
            assert_eq!(s.cnodes[0].0[1].cap(), source);
            assert_eq!(s.cnodes[0].0[1].child_count(), 0);
            assert_eq!(s.cnodes[0].0[1].parent(), None);
            assert_eq!(s.cnodes[0].0[2].cap(), Cap::Null);
            assert_eq!(s.cnodes[0].0[2].parent(), None);
            assert_eq!(s.scheduler.slab.get(invoker).pending_extra_caps_count, 0);
        }
    }

    #[inline(never)]
    fn legacy_preserves_source_authority() {
        for mint in [false, true] {
            let invoker = setup_invoker(0);
            let source = frame(FrameRights::ReadOnly, FrameSize::Small);
            let root = unsafe {
                let s = KERNEL.get();
                s.cnodes[0].0[1].set_cap(&source);
                s.scheduler.slab.get(invoker).cspace_root
            };
            let request = SyscallArgs {
                a1: ((if mint { InvocationLabel::CNodeMint } else {
                    InvocationLabel::CNodeCopy }) as u64) << 12,
                a2: 2,
                a3: 1,
                a4: 0x1234,
                ..Default::default()
            };
            decode_invocation(root, &request, invoker).expect("legacy frame derivation");
            unsafe {
                let s = KERNEL.get();
                assert_eq!(s.cnodes[0].0[1].cap(), source);
                assert!(matches!(s.cnodes[0].0[2].cap(), Cap::Frame {
                    rights: FrameRights::ReadOnly, mapped: None, asid: 0,
                    map_type: FrameMapType::None, ..
                }));
            }
            teardown_invoker(invoker);
        }
    }

    #[inline(never)]
    fn derived_caps_cannot_regain_authority() {
        for mint in [false, true] {
            let invoker = setup_invoker(0);
            let source = frame(FrameRights::ReadWrite, FrameSize::Small);
            let root = unsafe {
                let s = KERNEL.get();
                s.cnodes[0].0[1].set_cap(&source);
                s.scheduler.slab.get(invoker).cspace_root
            };
            stage(invoker, root, 2);
            decode_invocation(root, &args(mint, if mint { 6 } else { 5 }), invoker)
                .expect("first derivation attenuates to read-only");
            let first = unsafe { KERNEL.get().cnodes[0].0[2].cap() };
            stage(invoker, root, 3);
            let request = SyscallArgs {
                a2: 3,
                a4: 2,
                ..args(mint, if mint { 6 } else { 5 })
            };
            decode_invocation(root, &request, invoker)
                .expect("second derivation stays source-bounded");
            unsafe {
                let s = KERNEL.get();
                assert_eq!(s.cnodes[0].0[1].cap(), source);
                assert_eq!(s.cnodes[0].0[2].cap(), first);
                assert_eq!(s.cnodes[0].0[3].cap(), first);
                assert!(matches!(first, Cap::Frame { rights: FrameRights::ReadOnly, .. }));
                assert_eq!(s.cnodes[0].0[3].parent(),
                    Some(crate::cte::MdbId::pack(0, 2)));
                assert_eq!(s.cnodes[0].0[2].child_count(), 1);
            }
            teardown_invoker(invoker);
        }
    }

    #[inline(never)]
    fn occupied_destination_is_unchanged() {
        for mint in [false, true] {
            let invoker = setup_invoker(0);
            let source = frame(FrameRights::ReadWrite, FrameSize::Small);
            let destination = frame(FrameRights::ReadOnly, FrameSize::Large);
            let root = unsafe {
                let s = KERNEL.get();
                s.cnodes[0].0[1].set_cap(&source);
                s.cnodes[0].0[2].set_cap(&destination);
                s.scheduler.slab.get(invoker).cspace_root
            };
            stage(invoker, root, 0);
            assert_eq!(decode_invocation(root, &args(mint, if mint { 6 } else { 5 }), invoker),
                Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_DeleteFirst))));
            unsafe {
                let s = KERNEL.get();
                assert_eq!(s.cnodes[0].0[1].cap(), source);
                assert_eq!(s.cnodes[0].0[1].child_count(), 0);
                assert_eq!(s.cnodes[0].0[2].cap(), destination);
                assert_eq!(s.cnodes[0].0[2].parent(), None);
                assert_eq!(s.cnodes[0].0[2].child_count(), 0);
            }
            teardown_invoker(invoker);
        }
    }

    pub(super) fn run() {
        attenuation();
        malformed_requests_preserve_slots();
        legacy_preserves_source_authority();
        derived_caps_cannot_regain_authority();
        occupied_destination_is_unchanged();
        arch::log("  CNode frame derivation attenuates authority and rejects malformed requests\n");
    }
}
