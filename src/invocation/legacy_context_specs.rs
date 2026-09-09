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

    #[cfg(target_arch = "x86_64")]
    unsafe fn terminal_fault_reply_preserves_context_edit() {
        use crate::endpoint::{IpcOutcome, RecvOptions};
        use crate::tcb::ThreadStateType;
        use legacy_context_protocol::*;

        let invoker = setup_invoker(0);
        bind_ipc(invoker, FrameRights::ReadOnly);
        let mut owners = crate::asid::spec::RootOwners::new();
        let (caller, handler, reply_index, sc_index, thread_cap, reply_cap) = {
            let s = KERNEL.get();
            let caller = s.scheduler.admit(crate::tcb::Tcb::default());
            let handler = s.scheduler.admit(crate::tcb::Tcb::default());
            let endpoint_index = s.alloc_endpoint().expect("fault endpoint");
            let reply_index = s.alloc_reply().expect("fault reply");
            let sc_index = s.alloc_sched_context().expect("fault caller SC");
            let fault_source = owners.cap_source_in(s, Cap::Endpoint {
                ptr: KernelState::endpoint_ptr(endpoint_index),
                badge: crate::cap::Badge(0x150),
                rights: crate::cap::EndpointRights {
                    can_send: true, can_receive: true,
                    can_grant: true, can_grant_reply: true,
                },
            });
            derive_tcb_cap(s, caller, TcbSlot::FaultHandler, Some(fault_source), 0).unwrap();
            let reply_cap = Cap::Reply {
                ptr: KernelState::reply_ptr(reply_index), can_grant: true,
            };
            owners.cap_source_in(s, reply_cap);
            owners.cap_source_in(s, Cap::SchedContext {
                ptr: KernelState::sched_context_ptr(sc_index),
                size_bits: crate::object_type::MIN_SCHED_CONTEXT_BITS as u8,
            });
            crate::sched_context::sc_donate(s, sc_index, caller);
            {
                let t = s.scheduler.slab.get_mut(caller);
                t.use_iretq_resume = false;
                t.user_context.rcx = 0x600002;
                t.user_context.r11 = 0x202;
                t.user_context.rsp = 0x800008;
                t.user_context.rax = 0x77;
                t.user_context.rbx = 0x1111;
            }
            crate::reply::offer(s, handler, reply_index as u16);
            assert_eq!(crate::endpoint::receive_ipc(
                &mut s.endpoints[endpoint_index], &mut s.scheduler, handler,
                RecvOptions::blocking(),
            ), IpcOutcome::Blocked);
            crate::fault::deliver_fault_in(s, caller,
                crate::fault::FaultMessage::UnknownSyscall { number: 0x77 }).unwrap();
            assert_eq!(s.scheduler.slab.get(handler).ipc_label, 2);
            assert_eq!(s.scheduler.slab.get(handler).msg_regs[0], 0x77);
            assert_eq!(s.scheduler.slab.get(handler).msg_regs[1], 0x1111);
            s.scheduler.set_current(Some(invoker));
            (caller, handler, reply_index, sc_index, Cap::Thread {
                tcb: PPtr::new(caller.0 as u64).unwrap(),
            }, reply_cap)
        };

        let mut words = [0u64; WRITE_WORDS];
        words[0] = REGISTER_MASK;
        for index in 0..18 {
            words[1 + index] = 0x7100 + index as u64;
        }
        words[1] = 0x700000;
        words[2] = 0x900008;
        words[3] = 0x246;
        let request = write_request(&words);
        decode_invocation(thread_cap, &request, invoker).expect("blocked caller context edit");
        {
            let s = KERNEL.get();
            let t = s.scheduler.slab.get(caller);
            assert_eq!(t.state, ThreadStateType::BlockedOnReply);
            assert_eq!(t.pending_fault, 2);
            assert_eq!(t.user_context.rax, words[4]);
            assert_eq!(t.sc, None);
            assert_eq!(t.donated_sc, Some(sc_index as u16));
            assert_eq!(s.replies[reply_index].bound_tcb, Some(caller));
            assert_eq!(s.scheduler.slab.get(handler).reply_to, Some(caller));
            assert_eq!(s.scheduler.slab.get(handler).sc, Some(sc_index as u16));
            assert_eq!(s.sched_contexts[sc_index].bound_tcb, Some(handler));
            s.scheduler.set_current(Some(handler));
        }

        // The handler retains the old fault snapshot, but terminal delivery owns only RAX.
        let terminal = SyscallArgs {
            a1: crate::types::seL4_MessageInfo_t::new(0, 0, 0, 1).words[0],
            a2: 0xc0000001,
            a3: 0x1111, a4: 0x600000, a5: 0xdead,
            ..Default::default()
        };
        decode_invocation(reply_cap, &terminal, handler).expect("one-word terminal fault reply");
        {
            let s = KERNEL.get();
            let t = s.scheduler.slab.get(caller);
            let actual = [
                crate::fault::resume_ip(t), t.user_context.rsp, crate::fault::resume_flags(t),
                t.user_context.rax, t.user_context.rbx, t.user_context.rcx,
                t.user_context.rdx, t.user_context.rsi, t.user_context.rdi,
                t.user_context.rbp, t.user_context.r8, t.user_context.r9,
                t.user_context.r10, t.user_context.r11, t.user_context.r12,
                t.user_context.r13, t.user_context.r14, t.user_context.r15,
            ];
            words[4] = terminal.a2;
            assert_eq!(actual.as_slice(), &words[1..19]);
            assert!(t.use_iretq_resume);
            assert_eq!(t.pending_fault, 0);
            assert_eq!(t.state, ThreadStateType::Running);
            assert_eq!(t.sc, Some(sc_index as u16));
            assert_eq!(t.donated_sc, None);
            assert_eq!(s.sched_contexts[sc_index].bound_tcb, Some(caller));
            assert_eq!(s.replies[reply_index].bound_tcb, None);
            let h = s.scheduler.slab.get(handler);
            assert_eq!(h.pending_reply, None);
            assert_eq!(h.reply_to, None);
            assert_eq!(h.sc, None);
            assert_eq!(h.active_sc, None);
        }
        assert!(matches!(decode_invocation(reply_cap, &terminal, handler),
            Err(KException::SyscallError(error)) if error.code == seL4_Error::seL4_InvalidCapability));
        {
            let s = KERNEL.get();
            assert_eq!(s.sched_contexts[sc_index].bound_tcb, Some(caller));
            assert_eq!(s.scheduler.slab.get(caller).user_context.rax, terminal.a2);
            teardown_thread_in(s, caller);
            teardown_thread_in(s, handler);
        }
        teardown_invoker(invoker);
        drop(owners);
        arch::log("  LegacyContext edit survives one-word fault reply and exact SC return\n");
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
                words[0] = REGISTER_MASK | FX_MASK | DEBUG_MASK;
                words[1] = 0x400000;
                words[2] = 0x800000;
                words[3] = 0x246;
                words[4] = 0xdeadbeef;
                let raw_debug = [0x400800, 0x400900, 0x123000, 0x456000, 0x4000, 0x409];
                let saved_debug = [0x400800, 0x400900, 0x123000, 0x456000, 0xffff4ff0, 0x409];
                words[1 + DEBUG_OFFSET..].copy_from_slice(&raw_debug);
                {
                    let t = KERNEL.get().scheduler.slab.get_mut(target);
                    t.debug.n_instructions = 9;
                    t.debug.single_step_enabled = true;
                }
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
                for length in [0, 1, 84, 85, 90, 92, 120] {
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
                assert_eq!(t.debug.dr, saved_debug);
                assert_eq!(t.debug.n_instructions, 9);
                assert!(t.debug.single_step_enabled);
                // Unselected malformed FX and stale GPR payload must not overwrite live groups.
                invalid[0] = 1 << 3;
                invalid[4] = 0x9876;
                invalid[1 + DEBUG_OFFSET..].fill(u64::MAX);
                decode_invocation(cap, &write_request(&invalid), invoker).unwrap();
                let t = KERNEL.get().scheduler.slab.get(target);
                assert_eq!(crate::fault::reported_ip(t), words[1]);
                assert_eq!(t.user_context.rax, 0x9876);
                assert_eq!(t.fpu_state.0, fx.0);
                assert_eq!(t.debug.dr, saved_debug);
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
                for (index, word) in saved_debug.iter().enumerate() {
                    assert_eq!(
                        core::ptr::read_volatile(buffer.add(1 + DEBUG_OFFSET + index)),
                        *word
                    );
                }
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
                // DEBUG alone cannot rewrite the stale supplied GPR/FX groups or TLS.
                let mut debug_only = words;
                debug_only[0] = DEBUG_MASK;
                debug_only[1..1 + DEBUG_OFFSET].fill(u64::MAX);
                decode_invocation(cap, &write_request(&debug_only), invoker).unwrap();
                let t = KERNEL.get().scheduler.slab.get(target);
                assert_eq!(t.debug.dr, saved_debug);
                assert_eq!(t.user_context.rax, 0x9876);
                assert_eq!(crate::fault::resume_ip(t), words[1]);
                assert_eq!(t.fpu_state.0, fx.0);
                assert_eq!(t.cpu_context.gs_base, 0x12345000);
                assert_eq!(t.state, state);
                // Only restart of a delivered debug fault acknowledges unselected status.
                for (pending_fault, selected_debug, expected_status) in [
                    (4, false, 0xffff0ff0),
                    (6, false, 0xffff0ff1),
                    (4, true, saved_debug[4]),
                ] {
                    let ack_target = KERNEL.get().scheduler.admit(crate::tcb::Tcb::default());
                    let ack_cap = Cap::Thread {
                        tcb: PPtr::new(ack_target.0 as u64).unwrap(),
                    };
                    {
                        let t = KERNEL.get().scheduler.slab.get_mut(ack_target);
                        t.state = crate::tcb::ThreadStateType::BlockedOnReply;
                        t.pending_fault = pending_fault;
                        t.debug.dr = saved_debug;
                        t.debug.dr[4] = 0xffff0ff1;
                        t.debug.used_breakpoints_bf = 3;
                        t.debug.n_instructions = 9;
                        t.debug.single_step_enabled = true;
                    }
                    let mut restart = words;
                    restart[0] = RESTART_MASK | if selected_debug { DEBUG_MASK } else { 0 };
                    decode_invocation(ack_cap, &write_request(&restart), invoker).unwrap();
                    let t = KERNEL.get().scheduler.slab.get(ack_target);
                    assert_eq!(t.pending_fault, 0);
                    assert_eq!(t.debug.dr[4], expected_status);
                    assert_eq!(&t.debug.dr[..4], &saved_debug[..4]);
                    assert_eq!(t.debug.dr[5], saved_debug[5]);
                    assert_eq!(t.debug.n_instructions, 9);
                    assert!(t.debug.single_step_enabled);
                    if pending_fault == 4 && !selected_debug {
                        let t = KERNEL.get().scheduler.slab.get_mut(ack_target);
                        t.debug.n_instructions = 1;
                        let status = t.debug.dr[4] | (1 << 14);
                        crate::arch::x86_64::exceptions::defer_quiesced_debug(
                            t,
                            crate::smp::UserEntryKind::Debug { status },
                        );
                        assert_eq!(
                            t.debug.n_instructions, 0,
                            "new BS was not mistaken for stale B0"
                        );
                        assert!(t.deferred_debug.take().is_some());
                    }
                    teardown_thread_in(KERNEL.get(), ack_target);
                }
                // The private snapshot returns the canonical SYSRET continuation. Unlike
                // upstream ReadRegisters, its paired write does not add a syscall length.
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
                    decode_invocation(cap, &read_request(), invoker).unwrap();
                    assert_eq!(
                        KERNEL.get().scheduler.slab.get(invoker).msg_regs[0],
                        0x600002
                    );
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
                    assert_eq!(
                        s.scheduler.slab.get(target).donated_sc,
                        Some(donated_sc as u16)
                    );
                    assert_eq!(
                        s.sched_contexts[donated_sc].bound_tcb,
                        Some(TcbId(u16::MAX))
                    );
                    s.sched_contexts[donated_sc].bound_tcb = Some(receiver);
                    cancel_reply_wait_for_caller(s, target);
                    assert_eq!(
                        s.scheduler.slab.get(target).donated_sc,
                        Some(donated_sc as u16)
                    );
                    assert_eq!(s.sched_contexts[donated_sc].bound_tcb, Some(receiver));
                    assert_eq!(s.scheduler.slab.get(receiver).sc, None);
                    s.sched_contexts[donated_sc].bound_tcb = None;
                    crate::sched_context::sc_donate(s, donated_sc, target);
                    s.replies[reply_index] = crate::reply::Reply::new();
                    crate::reply::offer(s, receiver, reply_index as u16);
                    crate::reply::bind_call(s, target, receiver, Some(reply_index as u16));
                    let t = s.scheduler.slab.get_mut(target);
                    t.state = crate::tcb::ThreadStateType::BlockedOnReply;
                    t.pending_fault = 6;
                }
                for invalid_debug in [false, true] {
                    invalid = words;
                    invalid[0] = REGISTER_MASK | FX_MASK | DEBUG_MASK | RESTART_MASK;
                    if invalid_debug {
                        invalid[1 + DEBUG_OFFSET + 5] |= 1 << 13; // GD cannot enter user state.
                    } else {
                        invalid[1 + REGISTER_WORDS + 3] |= 1u64 << 31;
                    }
                    assert!(decode_invocation(cap, &write_request(&invalid), invoker).is_err());
                    let s = KERNEL.get();
                    let t = s.scheduler.slab.get(target);
                    assert_eq!(t.state, crate::tcb::ThreadStateType::BlockedOnReply);
                    assert_eq!(t.pending_fault, 6);
                    assert_eq!(t.user_context.rax, 0x9876);
                    assert_eq!(t.fpu_state.0, fx.0);
                    assert_eq!(t.debug.dr, saved_debug);
                    assert_eq!(t.debug.n_instructions, 9);
                    assert!(t.debug.single_step_enabled);
                    assert_eq!(s.replies[reply_index].bound_tcb, Some(target));
                    assert_eq!(s.scheduler.slab.get(receiver).reply_to, Some(target));
                    assert_eq!(t.donated_sc, Some(donated_sc as u16));
                    assert_eq!(t.sc, None);
                    assert_eq!(s.sched_contexts[donated_sc].bound_tcb, Some(receiver));
                    assert_eq!(s.scheduler.slab.get(receiver).sc, Some(donated_sc as u16));
                }
                words[0] = REGISTER_MASK | FX_MASK | DEBUG_MASK | RESTART_MASK;
                decode_invocation(cap, &SyscallArgs {
                    a1: (InvocationLabel::TCBAcquireExecutionHold as u64) << 12,
                    ..Default::default()
                }, invoker).unwrap();
                let hold = KERNEL.get().scheduler.slab.get(invoker).msg_regs[0];
                decode_invocation(cap, &write_request(&words), invoker).unwrap();
                {
                    let s = KERNEL.get();
                    let t = s.scheduler.slab.get(target);
                    assert_eq!(t.state, crate::tcb::ThreadStateType::Running);
                    assert_eq!(t.execution_hold, hold);
                    assert!(!t.enqueued && !t.is_runnable());
                    assert_eq!(t.pending_fault, 0);
                    assert_eq!(t.user_context.rax, words[4]);
                    assert_eq!(t.fpu_state.0, fx.0);
                    assert_eq!(t.debug.dr, saved_debug);
                    assert_eq!(t.debug.n_instructions, 9);
                    assert!(t.debug.single_step_enabled);
                    assert_eq!(s.replies[reply_index].bound_tcb, None);
                    assert_eq!(s.scheduler.slab.get(receiver).reply_to, None);
                    assert_eq!(t.donated_sc, None);
                    assert_eq!(t.sc, None);
                    assert_eq!(s.sched_contexts[donated_sc].bound_tcb, Some(receiver));
                    assert_eq!(s.scheduler.slab.get(receiver).sc, Some(donated_sc as u16));
                    assert_eq!(s.sched_contexts[donated_sc].reply_head, None);
                    decode_invocation(cap, &SyscallArgs {
                        a1: ((InvocationLabel::TCBReleaseExecutionHold as u64) << 12) | 1,
                        a2: hold, ..Default::default()
                    }, invoker).unwrap();
                    assert_eq!(s.scheduler.slab.get(target).execution_hold, 0);
                    assert!(!s.scheduler.slab.get(target).enqueued);
                    s.scheduler.scrub_tcb(target);
                    s.free_sched_context(donated_sc);
                    teardown_thread_in(s, receiver);
                    s.replies[reply_index] = crate::reply::Reply::new();
                }
            }
            teardown_thread_in(KERNEL.get(), target);
            teardown_invoker(invoker);
        }
        #[cfg(target_arch = "x86_64")]
        unsafe { terminal_fault_reply_preserves_context_edit(); }
        arch::log("  LegacyContext validates complete selected state before atomic installation\n");
    }
}
