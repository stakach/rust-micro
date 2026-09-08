#[cfg(target_arch = "x86_64")]
mod paging_mapping_specs {
    use super::*;
    use crate::arch::x86_64::paging::kernel_virt_to_phys;
    use crate::cap::{PageDirectoryStorage, PageTableStorage, PdptStorage};

    #[repr(C, align(4096))]
    struct Table([u64; 512]);
    static mut TABLES: [Table; 4] = [const { Table([0; 512]) }; 4];
    const ASID: u16 = 4093;
    const ADDRESS: u64 = (129u64 << 39) + (3u64 << 30) + (5u64 << 21);

    unsafe fn fixture(level: u32) -> (TcbId, Cap, Cap, *mut u64) {
        let invoker = setup_invoker(0);
        let tables = core::ptr::addr_of_mut!(TABLES) as *mut Table;
        core::ptr::write_bytes(tables, 0, 4);
        let root = tables as *mut u64;
        let pdpt = tables.add(1) as *mut u64;
        let pd = tables.add(2) as *mut u64;
        let pt = tables.add(3) as *mut u64;
        let root_pa = kernel_virt_to_phys(root as u64);
        let pdpt_pa = kernel_virt_to_phys(pdpt as u64);
        let pd_pa = kernel_virt_to_phys(pd as u64);
        let pt_pa = kernel_virt_to_phys(pt as u64);
        if level < 3 {
            root.add(129).write_volatile(pdpt_pa | 7);
        }
        if level < 2 {
            pdpt.add(3).write_volatile(pd_pa | 7);
        }
        let (target, entry) = match level {
            3 => (
                Cap::Pdpt {
                    ptr: PPtr::<PdptStorage>::new(pdpt_pa).unwrap(),
                    mapped: None,
                    asid: 0,
                },
                root.add(129),
            ),
            2 => (
                Cap::PageDirectory {
                    ptr: PPtr::<PageDirectoryStorage>::new(pd_pa).unwrap(),
                    mapped: None,
                    asid: 0,
                },
                pdpt.add(3),
            ),
            _ => (
                Cap::PageTable {
                    ptr: PPtr::<PageTableStorage>::new(pt_pa).unwrap(),
                    mapped: None,
                    asid: 0,
                },
                pd.add(5),
            ),
        };
        let vspace = mapping_catalog_specs::root(ASID, root_pa, 3);
        KERNEL.get().cnodes[0].0[2].set_cap(&target);
        KERNEL.get().cnodes[0].0[28].set_cap(&target);
        (invoker, target, vspace, entry)
    }

    fn args(level: u32, upstream: bool, attributes: u64) -> SyscallArgs {
        let label = match level {
            3 => InvocationLabel::X86PDPTMap,
            2 => InvocationLabel::X86PageDirectoryMap,
            _ => InvocationLabel::X86PageTableMap,
        };
        SyscallArgs {
            a0: 28,
            a1: (label as u64) << 12 | if upstream { (1 << 7) | 2 } else { 0 },
            a2: ADDRESS + if upstream { 123 } else { 0x1000 },
            a3: if upstream { attributes } else { 3 },
            ..Default::default()
        }
    }

    fn stage(invoker: TcbId, vspace: Cap) {
        unsafe {
            let tcb = KERNEL.get().scheduler.slab.get_mut(invoker);
            tcb.pending_extra_caps_count = 1;
            tcb.pending_extra_caps[0] = vspace;
        }
    }

    #[inline(never)]
    pub(super) fn run() {
        for level in 1..=3 {
            for upstream in [false, true] {
                for attributes in 0..8 {
                    unsafe {
                        let (invoker, target, vspace, entry) = fixture(level);
                        stage(invoker, vspace);
                        let call = args(level, upstream, attributes);
                        decode_invocation(target, &call, invoker).expect("real table installation");
                        let base = call.a2 & !((1u64 << (12 + level * 9)) - 1);
                        assert_eq!(
                            entry.read_volatile(),
                            paging_struct_state(&target).0
                                | 7
                                | if upstream { (attributes & 3) << 3 } else { 0 }
                        );
                        assert_eq!(KERNEL.get().cnodes[0].0[2].cap(), target);
                        assert_eq!(
                            KERNEL.get().cnodes[0].0[28].cap(),
                            paging_cap_with_mapping(
                                target,
                                paging_struct_state(&target).0,
                                Some(base),
                                ASID
                            )
                            .unwrap()
                        );
                        let mapped = KERNEL.get().cnodes[0].0[28].cap();
                        let before = entry.read_volatile();
                        stage(invoker, vspace);
                        assert_eq!(
                            decode_invocation(mapped, &call, invoker),
                            Err(KException::SyscallError(SyscallError::new(
                                seL4_Error::seL4_InvalidCapability
                            )))
                        );
                        assert_eq!(entry.read_volatile(), before);
                        assert_eq!(KERNEL.get().cnodes[0].0[28].cap(), mapped);
                        teardown_invoker(invoker);
                    }
                }
                for failure in 0..9 {
                    if (failure == 7 && level == 3) || (failure == 8 && !upstream) {
                        continue;
                    }
                    unsafe {
                        let (invoker, target, mut vspace, entry) = fixture(level);
                        let mut call = args(level, upstream, 0);
                        let expected = match failure {
                            0 => {
                                // Source CTE must match the exact invoked cap before any write.
                                KERNEL.get().cnodes[0].0[28].set_cap(&Cap::Null);
                                seL4_Error::seL4_InvalidCapability
                            }
                            1 => {
                                if let Cap::PML4 { ref mut mapped, .. } = vspace {
                                    *mapped = false;
                                }
                                seL4_Error::seL4_InvalidCapability
                            }
                            2 => {
                                if let Cap::PML4 { ref mut asid, .. } = vspace {
                                    *asid = 0;
                                }
                                seL4_Error::seL4_InvalidCapability
                            }
                            3 => {
                                entry.write_volatile(0x4000_0087);
                                seL4_Error::seL4_DeleteFirst
                            }
                            4 => {
                                call.a0 = 29;
                                seL4_Error::seL4_InvalidCapability
                            }
                            5 => seL4_Error::seL4_InvalidCapability,
                            8 => seL4_Error::seL4_TruncatedMessage,
                            _ => seL4_Error::seL4_FailedLookup,
                        };
                        KERNEL.get().cnodes[0].0[3].set_cap(&vspace);
                        stage(invoker, vspace);
                        if failure == 5 {
                            mapping_catalog_specs::withdraw_pool();
                            let replacement = kernel_virt_to_phys(
                                (core::ptr::addr_of!(TABLES) as *const Table).add(3) as u64,
                            );
                            mapping_catalog_specs::root(ASID, replacement, 6);
                        }
                        if failure == 6 {
                            mapping_catalog_specs::withdraw_pool();
                        }
                        if failure == 7 {
                            let tables = core::ptr::addr_of_mut!(TABLES) as *mut Table;
                            if level == 2 {
                                (tables as *mut u64).add(129).write_volatile(0);
                            } else {
                                (tables.add(1) as *mut u64).add(3).write_volatile(0);
                            }
                        }
                        if failure == 8 {
                            KERNEL
                                .get()
                                .scheduler
                                .slab
                                .get_mut(invoker)
                                .pending_extra_caps_count = 0;
                        }
                        let before = entry.read_volatile();
                        let source = KERNEL.get().cnodes[0].0[28].cap();
                        assert_eq!(
                            decode_invocation(target, &call, invoker),
                            Err(KException::SyscallError(SyscallError::new(expected)))
                        );
                        assert_eq!(entry.read_volatile(), before);
                        assert_eq!(KERNEL.get().cnodes[0].0[28].cap(), source);
                        assert_eq!(KERNEL.get().cnodes[0].0[2].cap(), target);
                        teardown_invoker(invoker);
                    }
                }
            }
            for length in 0..2 {
                unsafe {
                    let (invoker, target, vspace, entry) = fixture(level);
                    stage(invoker, vspace);
                    let mut call = args(level, true, 0);
                    call.a1 = call.a1 & !0x7f | length;
                    assert_eq!(
                        decode_invocation(target, &call, invoker),
                        Err(KException::SyscallError(SyscallError::new(
                            seL4_Error::seL4_TruncatedMessage
                        )))
                    );
                    assert_eq!(entry.read_volatile(), 0);
                    assert_eq!(KERNEL.get().cnodes[0].0[28].cap(), target);
                    teardown_invoker(invoker);
                }
            }
        }
        arch::log(
            "  paging maps authenticate exact caps/ASIDs and install real table attributes\n",
        );
    }
}
