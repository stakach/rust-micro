mod vspace_binding_specs {
    use super::*;

    #[repr(C, align(4096))]
    struct Page([u8; 4096]);
    static CHILD: Page = Page([0; 4096]);
    static PROVIDER: Page = Page([0; 4096]);

    fn request(child: u64, provider: u64) -> SyscallArgs {
        SyscallArgs {
            a1: ((InvocationLabel::TCBQueryVSpaceBinding as u64) << 12) | 2,
            a2: child,
            a3: provider,
            ..Default::default()
        }
    }

    unsafe fn query(invoker: TcbId, target: TcbId, child: u64, provider: u64) -> u64 {
        let cap = Cap::Thread {
            tcb: PPtr::new(target.0 as u64).unwrap(),
        };
        decode_invocation(cap, &request(child, provider), invoker).unwrap();
        let response = KERNEL.get().scheduler.slab.get(invoker);
        assert_eq!((response.ipc_label, response.ipc_length), (0, 1));
        response.msg_regs[0]
    }

    pub(super) fn run() {
        unsafe {
            let invoker = setup_invoker(0);
            let mut owners = crate::asid::spec::RootOwners::new();
            let child = owners.root(crate::arch::virt_to_phys(&CHILD as *const _ as u64));
            let provider = owners.root(crate::arch::virt_to_phys(&PROVIDER as *const _ as u64));
            let target = KERNEL.get().scheduler.admit(crate::tcb::Tcb::default());
            let source = owners.root_source(crate::arch::virt_to_phys(&CHILD as *const _ as u64));
            derive_tcb_cap(KERNEL.get(), target, TcbSlot::VSpace, Some(source), 0).unwrap();
            KERNEL.get().cnodes[0].0[2].set_cap(&child);
            KERNEL.get().cnodes[0].0[3].set_cap(&provider);
            KERNEL.get().cnodes[0].0[4].set_cap(&child);
            let target_before = KERNEL.get().scheduler.slab.get(target).vspace_root();
            let hold_before = KERNEL.get().scheduler.slab.get(target).execution_hold;
            let Cap::PML4 {
                asid: child_asid, ..
            } = child
            else {
                unreachable!()
            };
            let Cap::PML4 {
                asid: provider_asid,
                ..
            } = provider
            else {
                unreachable!()
            };
            let refs = (
                crate::asid::pml4_refcount(child_asid),
                crate::asid::pml4_refcount(provider_asid),
            );
            assert_eq!(query(invoker, target, 2, 3), 1);
            // Unequal CPtrs for copies of one physical root are not separate VSpaces.
            assert_eq!(query(invoker, target, 2, 4), 0);
            assert_eq!(query(invoker, target, 3, 2), 0);
            for invalid in [0, 31] {
                let cap = Cap::Thread {
                    tcb: PPtr::new(target.0 as u64).unwrap(),
                };
                assert!(decode_invocation(cap, &request(invalid, 3), invoker).is_err());
                assert!(decode_invocation(cap, &request(2, invalid), invoker).is_err());
            }
            let Cap::PML4 { ptr, .. } = child else {
                unreachable!()
            };
            KERNEL.get().cnodes[0].0[5].set_cap(&Cap::PML4 {
                ptr,
                mapped: false,
                asid: 0,
            });
            assert_eq!(query(invoker, target, 5, 3), 0);
            assert_eq!(query(invoker, target, 2, 5), 0);
            KERNEL.get().cnodes[0].0[6].set_cap(&Cap::Thread {
                tcb: PPtr::new(target.0 as u64).unwrap(),
            });
            let cap = Cap::Thread {
                tcb: PPtr::new(target.0 as u64).unwrap(),
            };
            assert!(decode_invocation(cap, &request(6, 3), invoker).is_err());
            assert!(decode_invocation(cap, &request(2, 6), invoker).is_err());
            KERNEL.get().cnodes[0].0[7].set_cap(&Cap::PML4 {
                ptr,
                mapped: true,
                asid: provider_asid,
            });
            assert_eq!(query(invoker, target, 7, 3), 0);
            for info in [
                request(2, 3).a1 - 1,
                request(2, 3).a1 + 1,
                request(2, 3).a1 | (1 << 7),
                request(2, 3).a1 | (1 << 9),
            ] {
                let mut malformed = request(2, 3);
                malformed.a1 = info;
                assert!(decode_invocation(cap, &malformed, invoker).is_err());
            }
            assert_eq!(
                KERNEL.get().scheduler.slab.get(target).vspace_root(),
                target_before
            );
            assert_eq!(
                KERNEL.get().scheduler.slab.get(target).execution_hold,
                hold_before
            );
            assert_eq!(
                (
                    crate::asid::pml4_refcount(child_asid),
                    crate::asid::pml4_refcount(provider_asid)
                ),
                refs
            );
            let other = owners.root_source(crate::arch::virt_to_phys(&PROVIDER as *const _ as u64));
            derive_tcb_cap(KERNEL.get(), target, TcbSlot::VSpace, Some(other), 0).unwrap();
            assert_eq!(query(invoker, target, 2, 3), 0);
            derive_tcb_cap(KERNEL.get(), target, TcbSlot::VSpace, None, 0).unwrap();
            assert_eq!(query(invoker, target, 2, 3), 0);
            // Drop the fixture's raw Thread reference before explicitly retiring its TCB below.
            KERNEL.get().cnodes[0].0[6].set_cap(&Cap::Null);
            for slot in [2, 3, 4, 5, 7] {
                delete_cap_slot(KERNEL.get(), MdbId::pack(0, slot)).unwrap();
            }
            teardown_thread_in(KERNEL.get(), target);
            teardown_thread_in(KERNEL.get(), invoker);
            drop(owners);
            arch::log("  TCB VSpace query validates current physical roots without effects\n");
        }
    }
}
