mod retirement_specs {
    use super::*;
    use crate::smp::retirement_spec_snapshot;

    fn assert_retirements<const N: usize>(
        before: (u32, [u32; N], bool),
        after: (u32, [u32; N], bool),
        count: u32,
    ) {
        assert_ne!(before.0, 0, "the fixture must exercise an online CPU");
        assert_eq!(after.0, before.0, "online participants must remain stable");
        assert!(!before.2, "no previous retirement may remain outstanding");
        assert!(!after.2, "invocation return must follow all retirement ACKs");
        for cpu in 0..N {
            let expected = if before.0 & (1 << cpu) != 0 {
                count
            } else {
                0
            };
            assert_eq!(
                after.1[cpu].wrapping_sub(before.1[cpu]),
                expected,
                "unexpected translation retirement count on CPU {}",
                cpu
            );
        }
    }

    pub(super) fn run() {
        unsafe {
            fresh_insertions_do_not_retire();
            present_replacements_and_rights_changes_retire();
            failed_maps_preserve_mapping_and_retirement_state();
            unmap_ack_precedes_absent_slot_reuse();
        }
        arch::log("  frame map retirement distinguishes absent insertion from replacement\n");
    }

    unsafe fn fresh_insertions_do_not_retire() {
        for size in [FrameSize::Small, FrameSize::Large, FrameSize::Huge] {
            let f = Fixture::new(size, VA);
            assert_eq!(f.leaf.read(), 0);
            let before = retirement_spec_snapshot();
            f.upstream(1, 3, 0, f.root, VA).unwrap();
            assert_retirements(before, retirement_spec_snapshot(), 0);
            assert_eq!(f.leaf.read() & 7, 7);
            assert_eq!(f.leaf.read() & 0x000f_ffff_ffff_f000, PA);
            assert!(matches!(
                f.frame(1),
                Cap::Frame {
                    mapped: Some(VA),
                    asid: ASID,
                    map_type: FrameMapType::VSpace,
                    ..
                }
            ));
            f.finish();
        }
    }

    unsafe fn present_replacements_and_rights_changes_retire() {
        for size in [FrameSize::Small, FrameSize::Large, FrameSize::Huge] {
            let f = Fixture::new(size, VA);
            f.upstream(1, 3, 0, f.root, VA).unwrap();
            let mapped_cap = f.frame(1);
            for (rights, expected_bits) in [(2, 5), (3, 7)] {
                let before = retirement_spec_snapshot();
                f.upstream(1, rights, 0, f.root, VA).unwrap();
                assert_retirements(before, retirement_spec_snapshot(), 1);
                assert_eq!(f.leaf.read() & 7, expected_bits);
                assert_eq!(f.frame(1), mapped_cap);
            }
            f.set_frame(2, f.fresh_frame(FrameRights::ReadOnly, PA * 2));
            let before = retirement_spec_snapshot();
            f.upstream(2, 3, 0, f.root, VA).unwrap();
            assert_retirements(before, retirement_spec_snapshot(), 1);
            assert_eq!(f.leaf.read() & 0x000f_ffff_ffff_f000, PA * 2);
            assert_eq!(f.leaf.read() & 7, 5);
            f.finish();
        }
    }

    unsafe fn failed_maps_preserve_mapping_and_retirement_state() {
        for size in [FrameSize::Small, FrameSize::Large, FrameSize::Huge] {
            let f = Fixture::new(size, VA);
            f.upstream(1, 3, 0, f.root, VA).unwrap();
            let original_cap = f.frame(1);
            let original_leaf = f.leaf.read();
            let before = retirement_spec_snapshot();
            assert_eq!(
                f.upstream(1, 2, 0, f.other_root, VA),
                Err(KException::SyscallError(SyscallError::new(
                    seL4_Error::seL4_InvalidCapability
                )))
            );
            assert_retirements(before, retirement_spec_snapshot(), 0);
            assert_eq!(f.frame(1), original_cap);
            assert_eq!(f.leaf.read(), original_leaf);
            f.finish();
        }
        let f = Fixture::new(FrameSize::Small, VA);
        let original_cap = f.frame(1);
        let root = core::ptr::addr_of_mut!(ROOT) as *mut u64;
        let idx = crate::arch::x86_64::vspace::decompose_vaddr(VA);
        root.add(idx.pml4 as usize).write(0);
        let before = retirement_spec_snapshot();
        assert_eq!(
            f.upstream(1, 3, 0, f.root, VA),
            Err(KException::SyscallError(SyscallError::new(
                seL4_Error::seL4_FailedLookup
            )))
        );
        assert_retirements(before, retirement_spec_snapshot(), 0);
        assert_eq!(f.frame(1), original_cap);
        assert_eq!(f.leaf.read(), 0);
        f.finish();
    }

    unsafe fn unmap_ack_precedes_absent_slot_reuse() {
        for size in [FrameSize::Small, FrameSize::Large, FrameSize::Huge] {
            let f = Fixture::new(size, VA);
            f.upstream(1, 3, 0, f.root, VA).unwrap();
            let before = retirement_spec_snapshot();
            let args = SyscallArgs {
                a0: 1,
                a1: (InvocationLabel::X86PageUnmap as u64) << 12,
                ..Default::default()
            };
            decode_invocation(f.frame(1), &args, f.invoker).unwrap();
            assert_retirements(before, retirement_spec_snapshot(), 1);
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
            // The successful unmap has retired the previous present translation.
            f.set_frame(2, f.fresh_frame(FrameRights::ReadOnly, PA * 2));
            let before = retirement_spec_snapshot();
            f.upstream(2, 3, 0, f.root, VA).unwrap();
            assert_retirements(before, retirement_spec_snapshot(), 0);
            assert_eq!(f.leaf.read() & 0x000f_ffff_ffff_f000, PA * 2);
            assert_eq!(f.leaf.read() & 7, 5);
            f.finish();
        }
    }
}
