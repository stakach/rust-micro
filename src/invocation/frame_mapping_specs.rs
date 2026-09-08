#[cfg(target_arch = "x86_64")]
mod frame_mapping_specs {
    use super::*;
    use crate::arch::x86_64::paging::kernel_virt_to_phys;
    use crate::cap::{FrameMapType, FrameRights, FrameSize, FrameStorage, Pml4Storage};

    const ASID: u16 = 4088;
    const OTHER_ASID: u16 = 4089;
    const VA: u64 = 129u64 << 39;
    const PA: u64 = 0x4000_0000;

    #[repr(C, align(4096))]
    struct Table([u64; 512]);
    static mut ROOT: Table = Table([0; 512]);
    static mut OTHER_ROOT: Table = Table([0; 512]);
    static mut PDPT: Table = Table([0; 512]);
    static mut PD: Table = Table([0; 512]);
    static mut PT: Table = Table([0; 512]);

    struct Fixture {
        invoker: TcbId,
        root: Cap,
        other_root: Cap,
        leaf: *mut u64,
        address: u64,
        size: FrameSize,
    }

    impl Fixture {
        unsafe fn new(size: FrameSize, address: u64) -> Self {
            let invoker = setup_invoker(0);
            let root = core::ptr::addr_of_mut!(ROOT) as *mut u64;
            let other_root = core::ptr::addr_of_mut!(OTHER_ROOT) as *mut u64;
            let pdpt = core::ptr::addr_of_mut!(PDPT) as *mut u64;
            let pd = core::ptr::addr_of_mut!(PD) as *mut u64;
            let pt = core::ptr::addr_of_mut!(PT) as *mut u64;
            for table in [root, other_root, pdpt, pd, pt] {
                core::ptr::write_bytes(table, 0, 512);
            }
            let root_pa = kernel_virt_to_phys(root as u64);
            let other_pa = kernel_virt_to_phys(other_root as u64);
            let idx = crate::arch::x86_64::vspace::decompose_vaddr(address);
            root.add(idx.pml4 as usize)
                .write(kernel_virt_to_phys(pdpt as u64) | 7);
            let leaf = match size {
                FrameSize::Huge => pdpt.add(idx.pdpt as usize),
                FrameSize::Large => {
                    pdpt.add(idx.pdpt as usize)
                        .write(kernel_virt_to_phys(pd as u64) | 7);
                    pd.add(idx.pd as usize)
                }
                FrameSize::Small => {
                    pdpt.add(idx.pdpt as usize)
                        .write(kernel_virt_to_phys(pd as u64) | 7);
                    pd.add(idx.pd as usize)
                        .write(kernel_virt_to_phys(pt as u64) | 7);
                    pt.add(idx.pt as usize)
                }
            };
            let root_cap = Cap::PML4 {
                ptr: PPtr::<Pml4Storage>::new(root_pa).unwrap(),
                mapped: true,
                asid: ASID,
            };
            let other_cap = Cap::PML4 {
                ptr: PPtr::<Pml4Storage>::new(other_pa).unwrap(),
                mapped: true,
                asid: OTHER_ASID,
            };
            crate::asid::register_boot_mapping(ASID, root_pa);
            crate::asid::register_boot_mapping(OTHER_ASID, other_pa);
            // These CTEs consume the explicit fixture registrations without adding references.
            KERNEL.get().cnodes[0].0[3] = Cte::with_cap(&root_cap);
            KERNEL.get().cnodes[0].0[4] = Cte::with_cap(&other_cap);
            let result = Self {
                invoker,
                root: root_cap,
                other_root: other_cap,
                leaf,
                address,
                size,
            };
            result.set_frame(1, result.fresh_frame(FrameRights::ReadWrite, PA));
            result
        }

        fn fresh_frame(&self, rights: FrameRights, paddr: u64) -> Cap {
            Cap::Frame {
                ptr: PAddr::<FrameStorage>::new(paddr),
                size: self.size,
                rights,
                mapped: None,
                asid: 0,
                is_device: false,
                map_type: FrameMapType::None,
            }
        }

        unsafe fn set_frame(&self, slot: usize, cap: Cap) {
            KERNEL.get().cnodes[0].0[slot].set_cap(&cap);
        }

        unsafe fn frame(&self, slot: usize) -> Cap {
            KERNEL.get().cnodes[0].0[slot].cap()
        }

        unsafe fn upstream(
            &self,
            slot: usize,
            rights: u64,
            attrs: u64,
            root: Cap,
            address: u64,
        ) -> KResult<()> {
            let tcb = KERNEL.get().scheduler.slab.get_mut(self.invoker);
            tcb.pending_extra_caps_count = 1;
            tcb.pending_extra_caps[0] = root;
            let args = SyscallArgs {
                a0: slot as u64,
                a1: ((InvocationLabel::X86PageMap as u64) << 12) | (1 << 7) | 3,
                a2: address,
                a3: rights,
                a4: attrs,
                ..Default::default()
            };
            decode_invocation(self.frame(slot), &args, self.invoker)
        }

        unsafe fn finish(self) {
            KERNEL.get().cnodes[0].0[3].set_cap(&Cap::Null);
            KERNEL.get().cnodes[0].0[4].set_cap(&Cap::Null);
            assert_eq!(crate::asid::pml4_paddr(ASID), 0);
            assert_eq!(crate::asid::pml4_paddr(OTHER_ASID), 0);
            teardown_invoker(self.invoker);
        }
    }

    pub(super) fn run() {
        unsafe {
            permissions_and_replacement();
            unmap_preserves_pat_leaf_semantics();
            zero_address_retains_mapping();
            rejected_authority_preserves_leaf();
            subtree_and_missing_parent_rejections();
        }
        arch::log("  frame map/remap applies real permissions with exact authority\n");
    }

    unsafe fn permissions_and_replacement() {
        for size in [FrameSize::Small, FrameSize::Large, FrameSize::Huge] {
            let f = Fixture::new(size, VA);
            f.upstream(1, 3 | 4, 7, f.root, VA).unwrap();
            let entry = f.leaf.read();
            assert_eq!(entry & 0x1f, 0x1f);
            assert_eq!(entry >> 63, 0, "upstream Grant is not ExecuteNever");
            let pat = match size {
                FrameSize::Small => 1 << 7,
                FrameSize::Large => 1 << 12,
                FrameSize::Huge => 0,
            };
            assert_eq!(entry & pat, pat);
            if size == FrameSize::Huge {
                assert_eq!(entry & (1 << 12), 0);
            }
            let mapped = f.frame(1);
            f.upstream(1, 2, 0, f.root, VA).unwrap();
            assert_eq!(f.leaf.read() & 7, 5);
            assert_eq!(
                f.frame(1),
                mapped,
                "mapping rights must not attenuate cap authority"
            );
            f.upstream(1, 3, 0, f.root, VA).unwrap();
            assert_eq!(f.leaf.read() & 7, 7);
            f.upstream(1, 1, 0, f.root, VA).unwrap();
            assert_eq!(f.leaf.read() & 7, 3, "write-only becomes kernel-only");
            let compressed = SyscallArgs {
                a0: 1,
                a1: (InvocationLabel::X86PageMap as u64) << 12,
                a2: VA,
                a3: 7,
                a4: 3,
                ..Default::default()
            };
            decode_invocation(f.frame(1), &compressed, f.invoker).unwrap();
            assert_eq!(f.leaf.read() >> 63, 1);
            f.upstream(1, 7, 0, f.root, VA).unwrap();
            assert_eq!(f.leaf.read() >> 63, 0);

            // Another mapping may replace the leaf; the old mapped cap may replace it again.
            f.set_frame(2, f.fresh_frame(FrameRights::ReadOnly, PA * 2));
            f.upstream(2, 3, 0, f.root, VA).unwrap();
            assert_eq!(f.leaf.read() & 0x000f_ffff_ffff_f000, PA * 2);
            assert_eq!(f.leaf.read() & 7, 5);
            assert!(matches!(
                f.frame(2),
                Cap::Frame {
                    rights: FrameRights::ReadOnly,
                    ..
                }
            ));
            f.upstream(1, 3, 0, f.root, VA).unwrap();
            assert_eq!(f.leaf.read() & 0x000f_ffff_ffff_f000, PA);
            f.finish();
        }
    }

    unsafe fn unmap_preserves_pat_leaf_semantics() {
        let f = Fixture::new(FrameSize::Small, VA);
        f.upstream(1, 3, 4, f.root, VA).unwrap();
        assert_ne!(f.leaf.read() & (1 << 7), 0);
        let args = SyscallArgs {
            a0: 1,
            a1: (InvocationLabel::X86PageUnmap as u64) << 12,
            ..Default::default()
        };
        decode_invocation(f.frame(1), &args, f.invoker).unwrap();
        assert_eq!(f.leaf.read(), 0);
        assert!(matches!(
            f.frame(1),
            Cap::Frame {
                mapped: None,
                asid: 0,
                map_type: FrameMapType::None,
                ..
            }
        ));
        f.finish();
    }

    unsafe fn zero_address_retains_mapping() {
        let f = Fixture::new(FrameSize::Small, 0);
        f.upstream(1, 3, 0, f.root, 0).unwrap();
        assert!(matches!(
            f.frame(1),
            Cap::Frame {
                mapped: Some(0),
                asid: ASID,
                ..
            }
        ));
        f.upstream(1, 2, 0, f.root, 0).unwrap();
        assert_eq!(f.leaf.read() & 7, 5);
        let args = SyscallArgs {
            a0: 1,
            a1: (InvocationLabel::X86PageUnmap as u64) << 12,
            ..Default::default()
        };
        decode_invocation(f.frame(1), &args, f.invoker).unwrap();
        assert_eq!(f.leaf.read(), 0);
        assert!(matches!(
            f.frame(1),
            Cap::Frame {
                mapped: None,
                asid: 0,
                ..
            }
        ));
        f.finish();
    }

    unsafe fn rejected_authority_preserves_leaf() {
        let f = Fixture::new(FrameSize::Small, VA);
        f.upstream(1, 3, 0, f.root, VA).unwrap();
        let original = f.frame(1);
        let leaf = f.leaf.read();
        let root_ptr = match f.root {
            Cap::PML4 { ptr, .. } => ptr,
            _ => unreachable!(),
        };
        let other_ptr = match f.other_root {
            Cap::PML4 { ptr, .. } => ptr,
            _ => unreachable!(),
        };
        for (root, expected) in [
            (
                Cap::PML4 {
                    ptr: root_ptr,
                    mapped: false,
                    asid: ASID,
                },
                seL4_Error::seL4_InvalidCapability,
            ),
            (
                Cap::PML4 {
                    ptr: root_ptr,
                    mapped: true,
                    asid: 0,
                },
                seL4_Error::seL4_InvalidCapability,
            ),
            (
                Cap::PML4 {
                    ptr: root_ptr,
                    mapped: true,
                    asid: 4087,
                },
                seL4_Error::seL4_FailedLookup,
            ),
            (
                Cap::PML4 {
                    ptr: other_ptr,
                    mapped: true,
                    asid: ASID,
                },
                seL4_Error::seL4_InvalidCapability,
            ),
            (f.other_root, seL4_Error::seL4_InvalidCapability),
        ] {
            assert_eq!(
                f.upstream(1, 2, 0, root, VA),
                Err(KException::SyscallError(SyscallError::new(expected)))
            );
            assert_eq!(f.frame(1), original);
            assert_eq!(f.leaf.read(), leaf);
        }
        assert_eq!(
            f.upstream(1, 3, 0, f.root, VA + 0x1000),
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidArgument
            )))
        );
        assert_eq!(f.leaf.read(), leaf);
        let wrong_type = match original {
            Cap::Frame {
                ptr,
                size,
                rights,
                mapped,
                asid,
                is_device,
                ..
            } => Cap::Frame {
                ptr,
                size,
                rights,
                mapped,
                asid,
                is_device,
                map_type: FrameMapType::IoSpace,
            },
            _ => unreachable!(),
        };
        f.set_frame(1, wrong_type);
        assert_eq!(
            f.upstream(1, 3, 0, f.root, VA),
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_IllegalOperation
            )))
        );
        assert_eq!(f.leaf.read(), leaf);
        f.set_frame(1, original);

        // Passing a stale source description with the same physical frame must not rewrite a PTE.
        let stale = match original {
            Cap::Frame {
                ptr,
                size,
                mapped,
                asid,
                is_device,
                map_type,
                ..
            } => Cap::Frame {
                ptr,
                size,
                rights: FrameRights::ReadOnly,
                mapped,
                asid,
                is_device,
                map_type,
            },
            _ => unreachable!(),
        };
        let args = SyscallArgs {
            a0: 1,
            a1: (InvocationLabel::X86PageMap as u64) << 12,
            a2: VA,
            a3: 2,
            a4: 3,
            ..Default::default()
        };
        assert_eq!(
            decode_invocation(stale, &args, f.invoker),
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_InvalidCapability
            )))
        );
        assert_eq!(f.frame(1), original);
        assert_eq!(f.leaf.read(), leaf);
        f.finish();
    }

    unsafe fn subtree_and_missing_parent_rejections() {
        for size in [FrameSize::Large, FrameSize::Huge] {
            let f = Fixture::new(size, VA);
            let subtree = kernel_virt_to_phys(core::ptr::addr_of!(PT) as u64) | 7;
            f.leaf.write(subtree);
            let original = f.frame(1);
            assert_eq!(
                f.upstream(1, 3, 0, f.root, VA),
                Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_DeleteFirst
                )))
            );
            assert_eq!(f.frame(1), original);
            assert_eq!(f.leaf.read(), subtree);
            f.finish();
        }
        let f = Fixture::new(FrameSize::Small, VA);
        let original = f.frame(1);
        let root = core::ptr::addr_of_mut!(ROOT) as *mut u64;
        let idx = crate::arch::x86_64::vspace::decompose_vaddr(VA);
        root.add(idx.pml4 as usize).write(0);
        assert_eq!(
            f.upstream(1, 3, 0, f.root, VA),
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup
            )))
        );
        assert_eq!(KERNEL.get().scheduler.slab.get(f.invoker).msg_regs[2], 39);
        assert_eq!(f.frame(1), original);
        assert_eq!(f.leaf.read(), 0);
        f.finish();
    }
}
