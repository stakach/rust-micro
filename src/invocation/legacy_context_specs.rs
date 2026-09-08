mod legacy_context_specs {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    use crate::cap::{FrameMapType, FrameRights, FrameSize};

    #[cfg(target_arch = "x86_64")]
    #[repr(C, align(4096))]
    struct Page([u64; 512]);
    #[cfg(target_arch = "x86_64")]
    static mut IPC: Page = Page([0; 512]);

    fn read_request() -> SyscallArgs {
        SyscallArgs {
            a1: crate::types::seL4_MessageInfo_t::new(
                InvocationLabel::TCBReadLegacyContext as u64,
                0,
                0,
                0,
            )
            .words[0],
            ..Default::default()
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn bind_ipc(invoker: TcbId, rights: FrameRights) {
        let physical = arch::virt_to_phys(core::ptr::addr_of!(IPC) as u64);
        bind_invoker_cap(
            KERNEL.get(),
            invoker,
            TcbSlot::IpcBuffer,
            Cap::Frame {
                ptr: PAddr::new(physical),
                size: FrameSize::Small,
                rights,
                mapped: None,
                asid: 0,
                is_device: false,
                map_type: FrameMapType::None,
            },
            0x1000,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn write_request(words: &[u64; legacy_context_protocol::WRITE_WORDS]) -> SyscallArgs {
        let buffer = core::ptr::addr_of_mut!(IPC.0).cast::<u64>();
        for (index, word) in words.iter().enumerate().skip(4) {
            core::ptr::write_volatile(buffer.add(1 + index), *word);
        }
        SyscallArgs {
            a1: crate::types::seL4_MessageInfo_t::new(
                InvocationLabel::TCBWriteLegacyContext as u64,
                0,
                0,
                legacy_context_protocol::WRITE_WORDS as u64,
            )
            .words[0],
            a2: words[0],
            a3: words[1],
            a4: words[2],
            a5: words[3],
            ..Default::default()
        }
    }

    pub(super) fn run() {
        unsafe {
            let invoker = setup_invoker(0);
            let target = KERNEL.get().scheduler.admit(crate::tcb::Tcb::default());
            let cap = Cap::Thread {
                tcb: PPtr::new(target.0 as u64).unwrap(),
            };
            #[cfg(target_arch = "aarch64")]
            {
                for label in [
                    InvocationLabel::TCBReadLegacyContext,
                    InvocationLabel::TCBWriteLegacyContext,
                ] {
                    let request = SyscallArgs {
                        a1: (label as u64) << 12,
                        ..Default::default()
                    };
                    assert!(matches!(decode_invocation(cap, &request, invoker),
                        Err(KException::SyscallError(error)) if error.code == seL4_Error::seL4_IllegalOperation));
                }
            }
            #[cfg(target_arch = "x86_64")]
            {
                use crate::arch::x86_64::fpu_ctx;
                use legacy_context_protocol::*;
                let mut words = [0u64; WRITE_WORDS];
                words[0] = REGISTER_MASK | FX_MASK;
                words[1] = 0x400000;
                words[2] = 0x800000;
                words[3] = 0x246;
                words[4] = 0xdeadbeef;
                let mut fx = crate::tcb::FxArea::FINIT;
                validate_fx_state(&mut fx.0, fpu_ctx::mxcsr_mask()).unwrap();
                for (word, bytes) in words[1 + REGISTER_WORDS..]
                    .iter_mut()
                    .zip(fx.0.chunks_exact(8))
                {
                    *word = u64::from_le_bytes(bytes.try_into().unwrap());
                }
                let before_fx = KERNEL.get().scheduler.slab.get(target).fpu_state.0;
                assert!(decode_invocation(cap, &read_request(), invoker).is_err());
                for rights in [FrameRights::KernelOnly, FrameRights::ReadOnly] {
                    bind_ipc(invoker, rights);
                    assert!(decode_invocation(cap, &read_request(), invoker).is_err());
                    if rights == FrameRights::KernelOnly {
                        let request = write_request(&words);
                        assert!(decode_invocation(cap, &request, invoker).is_err());
                    }
                }
                assert_eq!(
                    KERNEL.get().scheduler.slab.get(target).fpu_state.0,
                    before_fx
                );
                bind_ipc(invoker, FrameRights::ReadWrite);
                for length in [0, 1, 84, 86, 120] {
                    let mut request = write_request(&words);
                    request.a1 = crate::types::seL4_MessageInfo_t::new(
                        InvocationLabel::TCBWriteLegacyContext as u64,
                        0,
                        0,
                        length,
                    )
                    .words[0];
                    assert!(decode_invocation(cap, &request, invoker).is_err());
                }
                for (extra, unwrapped) in [(1, 0), (0, 1)] {
                    let mut request = write_request(&words);
                    request.a1 = crate::types::seL4_MessageInfo_t::new(
                        InvocationLabel::TCBWriteLegacyContext as u64,
                        unwrapped,
                        extra,
                        WRITE_WORDS as u64,
                    )
                    .words[0];
                    assert!(decode_invocation(cap, &request, invoker).is_err());
                }
                let own_cap = Cap::Thread {
                    tcb: PPtr::new(invoker.0 as u64).unwrap(),
                };
                assert!(decode_invocation(own_cap, &read_request(), invoker).is_err());
                let request = write_request(&words);
                assert!(decode_invocation(own_cap, &request, invoker).is_err());
                for mask in [1 << 18, 1 << 19, 1 << 63] {
                    let mut invalid = words;
                    invalid[0] = mask;
                    assert!(decode_invocation(cap, &write_request(&invalid), invoker).is_err());
                }
                // An invalid selected FX group must not install otherwise valid GPRs.
                let mut invalid = words;
                invalid[1 + REGISTER_WORDS + 3] |= 1u64 << 31;
                assert!(decode_invocation(cap, &write_request(&invalid), invoker).is_err());
                assert_ne!(
                    crate::fault::reported_ip(KERNEL.get().scheduler.slab.get(target)),
                    words[1]
                );
                assert_eq!(
                    KERNEL.get().scheduler.slab.get(target).fpu_state.0,
                    before_fx
                );
                let state = KERNEL.get().scheduler.slab.get(target).state;
                KERNEL
                    .get()
                    .scheduler
                    .slab
                    .get_mut(target)
                    .cpu_context
                    .gs_base = 0x12345000;
                bind_ipc(invoker, FrameRights::ReadOnly);
                decode_invocation(cap, &write_request(&words), invoker).unwrap();
                let t = KERNEL.get().scheduler.slab.get(target);
                assert_eq!(t.state, state);
                assert_eq!(t.cpu_context.gs_base, 0x12345000);
                assert_eq!(t.user_context.rax, 0xdeadbeef);
                assert_eq!(t.fpu_state.0, fx.0);
                // Unselected malformed FX and stale GPR payload must not overwrite live groups.
                invalid[0] = 1 << 3;
                invalid[4] = 0x9876;
                decode_invocation(cap, &write_request(&invalid), invoker).unwrap();
                let t = KERNEL.get().scheduler.slab.get(target);
                assert_eq!(crate::fault::reported_ip(t), words[1]);
                assert_eq!(t.user_context.rax, 0x9876);
                assert_eq!(t.fpu_state.0, fx.0);
                bind_ipc(invoker, FrameRights::ReadWrite);
                // Real local hardware residency must be captured for Read, not stale TCB bytes.
                fpu_ctx::fpu_switch_to(&mut KERNEL.get().scheduler.slab, target);
                let marker = 0x1122334455667788u64;
                core::arch::asm!("movq xmm15, {}", in(reg) marker, options(nostack));
                decode_invocation(cap, &read_request(), invoker).unwrap();
                assert!(!fpu_ctx::owner_is(arch::get_cpu_id() as usize, target));
                assert_eq!(
                    KERNEL.get().scheduler.slab.get(invoker).ipc_length,
                    READ_WORDS as u32
                );
                let buffer = core::ptr::addr_of!(IPC.0).cast::<u64>();
                assert_eq!(
                    core::ptr::read_volatile(buffer.add(1 + REGISTER_WORDS + 50)),
                    marker
                );
                assert_eq!(KERNEL.get().scheduler.slab.get(target).state, state);
                // Writing selected FX withdraws hardware ownership, so stale state cannot win.
                fpu_ctx::fpu_switch_to(&mut KERNEL.get().scheduler.slab, target);
                words[0] = FX_MASK;
                decode_invocation(cap, &write_request(&words), invoker).unwrap();
                assert!(!fpu_ctx::owner_is(arch::get_cpu_id() as usize, target));
                assert_eq!(KERNEL.get().scheduler.slab.get(target).fpu_state.0, fx.0);
                assert_eq!(
                    KERNEL.get().scheduler.slab.get(target).user_context.rax,
                    0x9876
                );
                // A blocked SYSRET snapshot reports the faulting instruction to readers, but
                // unselected CONTROL must preserve the actual continuation and representation.
                for mask in [1 << 3, (1 << 3) | (1 << 5)] {
                    {
                        let t = KERNEL.get().scheduler.slab.get_mut(target);
                        t.state = crate::tcb::ThreadStateType::BlockedOnReply;
                        t.use_iretq_resume = false;
                        t.user_context.rcx = 0x600002;
                        t.user_context.r11 = 0x246;
                        t.user_context.rip = 0x1111;
                        t.user_context.rflags = 0x2222;
                    }
                    let mut partial = words;
                    partial[0] = mask;
                    partial[4] = 0x9876;
                    partial[6] = 0xabcdef;
                    decode_invocation(cap, &write_request(&partial), invoker).unwrap();
                    let t = KERNEL.get().scheduler.slab.get(target);
                    assert_eq!(crate::fault::resume_ip(t), 0x600002);
                    assert_eq!(crate::fault::resume_flags(t), 0x246);
                    assert_eq!(t.state, crate::tcb::ThreadStateType::BlockedOnReply);
                    if mask == 1 << 3 {
                        assert!(!t.use_iretq_resume);
                        assert_eq!(t.user_context.rip, 0x1111);
                        assert_eq!(t.user_context.rflags, 0x2222);
                    } else {
                        assert!(t.use_iretq_resume);
                        assert_eq!(t.user_context.rcx, 0xabcdef);
                    }
                }
                // Restart must not cancel the old operation until all selected state validates.
                let reply_index = 11;
                let receiver = KERNEL.get().scheduler.admit(crate::tcb::Tcb::default());
                let donated_sc = KERNEL.get().alloc_sched_context().expect("donated SC");
                {
                    let s = KERNEL.get();
                    // Stale indices and mismatched reciprocal owners cannot withdraw an SC.
                    s.scheduler.slab.get_mut(target).state =
                        crate::tcb::ThreadStateType::BlockedOnReply;
                    s.scheduler.slab.get_mut(target).donated_sc = Some(u16::MAX);
                    cancel_reply_wait_for_caller(s, target);
                    assert_eq!(s.scheduler.slab.get(target).donated_sc, Some(u16::MAX));
                    s.scheduler.slab.get_mut(target).donated_sc = Some(donated_sc as u16);
                    s.sched_contexts[donated_sc].bound_tcb = Some(TcbId(u16::MAX));
                    cancel_reply_wait_for_caller(s, target);
                    assert_eq!(s.scheduler.slab.get(target).donated_sc, Some(donated_sc as u16));
                    assert_eq!(s.sched_contexts[donated_sc].bound_tcb, Some(TcbId(u16::MAX)));
                    s.sched_contexts[donated_sc].bound_tcb = Some(receiver);
                    cancel_reply_wait_for_caller(s, target);
                    assert_eq!(s.scheduler.slab.get(target).donated_sc, Some(donated_sc as u16));
                    assert_eq!(s.sched_contexts[donated_sc].bound_tcb, Some(receiver));
                    assert_eq!(s.scheduler.slab.get(receiver).sc, None);
                    s.sched_contexts[donated_sc].bound_tcb = None;
                    crate::sched_context::sc_donate(s, donated_sc, receiver);
                    s.replies[reply_index] = crate::reply::Reply::new();
                    s.replies[reply_index].bound_tcb = Some(target);
                    s.scheduler.slab.get_mut(receiver).reply_to = Some(target);
                    let t = s.scheduler.slab.get_mut(target);
                    t.state = crate::tcb::ThreadStateType::BlockedOnReply;
                    t.pending_fault = 6;
                }
                invalid = words;
                invalid[0] = REGISTER_MASK | FX_MASK | RESTART_MASK;
                invalid[1 + REGISTER_WORDS + 3] |= 1u64 << 31;
                assert!(decode_invocation(cap, &write_request(&invalid), invoker).is_err());
                {
                    let s = KERNEL.get();
                    let t = s.scheduler.slab.get(target);
                    assert_eq!(t.state, crate::tcb::ThreadStateType::BlockedOnReply);
                    assert_eq!(t.pending_fault, 6);
                    assert_eq!(t.user_context.rax, 0x9876);
                    assert_eq!(s.replies[reply_index].bound_tcb, Some(target));
                    assert_eq!(s.scheduler.slab.get(receiver).reply_to, Some(target));
                    assert_eq!(t.donated_sc, Some(donated_sc as u16));
                    assert_eq!(t.sc, None);
                    assert_eq!(s.sched_contexts[donated_sc].bound_tcb, Some(receiver));
                    assert_eq!(s.scheduler.slab.get(receiver).sc, Some(donated_sc as u16));
                }
                words[0] = REGISTER_MASK | FX_MASK | RESTART_MASK;
                decode_invocation(cap, &write_request(&words), invoker).unwrap();
                {
                    let s = KERNEL.get();
                    let t = s.scheduler.slab.get(target);
                    assert_eq!(t.state, crate::tcb::ThreadStateType::Running);
                    assert_eq!(t.pending_fault, 0);
                    assert_eq!(t.user_context.rax, words[4]);
                    assert_eq!(s.replies[reply_index].bound_tcb, None);
                    assert_eq!(s.scheduler.slab.get(receiver).reply_to, None);
                    assert_eq!(t.donated_sc, None);
                    assert_eq!(t.sc, Some(donated_sc as u16));
                    assert_eq!(s.sched_contexts[donated_sc].bound_tcb, Some(target));
                    assert_eq!(s.scheduler.slab.get(receiver).sc, None);
                    s.scheduler.scrub_tcb(target);
                    s.free_sched_context(donated_sc);
                    teardown_thread_in(s, receiver);
                    s.replies[reply_index] = crate::reply::Reply::new();
                }
            }
            teardown_thread_in(KERNEL.get(), target);
            teardown_invoker(invoker);
        }
        arch::log("  LegacyContext validates complete selected state before atomic installation\n");
    }
}
