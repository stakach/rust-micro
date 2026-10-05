mod table_clear_retirement_specs {
    use super::*;
    use crate::cap::{PageDirectoryStorage, PageTableStorage};

    static mut ALIAS_PDPT: Table = Table([0; 512]);
    static mut ALIAS_PD: Table = Table([0; 512]);

    unsafe fn invoke(slot: usize, label: InvocationLabel, invoker: TcbId) {
        let cap = KERNEL.get().cnodes[0].0[slot].cap();
        let args = SyscallArgs {
            a0: slot as u64,
            a1: (label as u64) << 12,
            ..Default::default()
        };
        decode_invocation(cap, &args, invoker).unwrap();
    }

    unsafe fn map_table(f: &Fixture, slot: usize, root: Cap) {
        let tcb = KERNEL.get().scheduler.slab.get_mut(f.invoker);
        tcb.pending_extra_caps_count = 1;
        tcb.pending_extra_caps[0] = root;
        let args = SyscallArgs {
            a0: slot as u64,
            a1: ((InvocationLabel::X86PageTableMap as u64) << 12) | (1 << 7) | 2,
            a2: VA,
            a3: 0,
            ..Default::default()
        };
        decode_invocation(f.frame(slot), &args, f.invoker).unwrap();
    }

    pub(super) fn run() {
        unsafe { final_table_clear_after_recorded_parent_withdrawal_retires_all_cpus(); }
        arch::log("  physical table clearing retires translations despite missing recorded parent\n");
    }

    unsafe fn final_table_clear_after_recorded_parent_withdrawal_retires_all_cpus() {
        let f = Fixture::new(FrameSize::Small, VA);
        let idx = crate::arch::x86_64::vspace::decompose_vaddr(VA);
        let other_root = core::ptr::addr_of_mut!(OTHER_ROOT) as *mut u64;
        let other_pdpt = core::ptr::addr_of_mut!(ALIAS_PDPT) as *mut u64;
        let other_pd = core::ptr::addr_of_mut!(ALIAS_PD) as *mut u64;
        let pd = core::ptr::addr_of_mut!(PD) as *mut u64;
        let pt = core::ptr::addr_of_mut!(PT) as *mut u64;
        core::ptr::write_bytes(other_pdpt, 0, 512);
        core::ptr::write_bytes(other_pd, 0, 512);
        other_root.add(idx.pml4 as usize)
            .write_volatile(kernel_virt_to_phys(other_pdpt as u64) | 7);
        other_pdpt.add(idx.pdpt as usize)
            .write_volatile(kernel_virt_to_phys(other_pd as u64) | 7);
        pd.add(idx.pd as usize).write_volatile(0);

        // Issue 286 currently permits IPC to copy an unmapped paging cap. Model that actual
        // post-transfer state, not a legitimate seL4 derivation or a fix for IPC provenance.
        let table = Cap::PageTable {
            ptr: PPtr::<PageTableStorage>::new(kernel_virt_to_phys(pt as u64)).unwrap(),
            mapped: None,
            asid: 0,
        };
        f.set_frame(5, table);
        f.set_frame(6, table);
        f.set_frame(7, Cap::PageDirectory {
            ptr: PPtr::<PageDirectoryStorage>::new(kernel_virt_to_phys(other_pd as u64)).unwrap(),
            mapped: Some(VA),
            asid: OTHER_ASID,
        });
        map_table(&f, 5, f.root);
        map_table(&f, 6, f.other_root);
        f.upstream(1, 3, 0, f.root, VA).unwrap();
        let original_leaf = f.leaf.read_volatile();
        assert_ne!(original_leaf & 1, 0);

        // Nonfinal deletion leaves the first hardware edge intact. Withdraw the second root's
        // parent through its actual invocation, then exercise the final PT cap's missing path.
        delete_cap_slot(KERNEL.get(), MdbId::pack(0, 5)).unwrap();
        assert!(f.frame(5).is_null());
        assert_eq!(pd.add(idx.pd as usize).read_volatile() & !0xfff,
            kernel_virt_to_phys(pt as u64));
        invoke(7, InvocationLabel::X86PageDirectoryUnmap, f.invoker);
        assert_eq!(other_pdpt.add(idx.pdpt as usize).read_volatile(), 0);
        assert_eq!(f.leaf.read_volatile(), original_leaf);
        assert!(!crate::arch::x86_64::usermode::user_table_matches_in_paddr(
            kernel_virt_to_phys(other_root as u64), 1, VA,
            kernel_virt_to_phys(pt as u64)));

        let before = crate::smp::retirement_spec_snapshot();
        invoke(6, InvocationLabel::X86PageTableUnmap, f.invoker);
        let after = crate::smp::retirement_spec_snapshot();
        assert_eq!(f.leaf.read_volatile(), 0, "the physical PT was actually cleared");
        assert_ne!(before.0, 0);
        assert_eq!(before.0, after.0);
        assert!(!before.2 && !after.2, "all retirement ACKs must precede return");
        for cpu in 0..after.1.len() {
            let expected = u32::from(before.0 & (1 << cpu) != 0);
            assert_eq!(after.1[cpu].wrapping_sub(before.1[cpu]), expected,
                "final physical table clear must retire cached translations on CPU {}", cpu);
        }
        assert!(matches!(f.frame(6), Cap::PageTable { mapped: None, asid: 0, .. }));
        f.set_frame(6, Cap::Null);
        f.set_frame(7, Cap::Null);
        f.finish();
    }
}
