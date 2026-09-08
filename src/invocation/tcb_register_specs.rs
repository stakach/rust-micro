#[cfg(target_arch = "x86_64")]
mod tcb_register_specs {
    use super::*;
    use crate::cap::{FrameMapType, FrameRights, FrameSize};

    #[repr(C, align(4096))]
    struct Page([u64; 512]);
    static mut IPC: Page = Page([0; 512]);

    fn request(count: u64, length: u64) -> SyscallArgs {
        SyscallArgs {
            a1: crate::types::seL4_MessageInfo_t::new(
                InvocationLabel::TCBWriteRegisters as u64, 0, 0, length).words[0],
            a3: count, a4: 0x400000, a5: 0x800000,
            ..Default::default()
        }
    }

    pub(super) fn run() {
        unsafe {
            let invoker = setup_invoker(0);
            let state = KERNEL.get();
            let target = state.scheduler.admit(crate::tcb::Tcb::default());
            let cap = Cap::Thread { tcb: PPtr::new(target.0 as u64).unwrap() };
            state.scheduler.slab.get_mut(target).user_context.rip = 0x1234;
            state.scheduler.slab.get_mut(target).user_context.rsp = 0x5678;
            for (count, length, code) in [
                (1, 1, seL4_Error::seL4_TruncatedMessage),
                (u64::MAX, 23, seL4_Error::seL4_TruncatedMessage),
                (21, 23, seL4_Error::seL4_TruncatedMessage),
                (2, 3, seL4_Error::seL4_TruncatedMessage),
                (3, 5, seL4_Error::seL4_TruncatedMessage),
            ] {
                assert!(matches!(decode_invocation(cap, &request(count, length), invoker),
                    Err(KException::SyscallError(error)) if error.code == code));
                let target = KERNEL.get().scheduler.slab.get(target);
                assert_eq!(target.user_context.rip, 0x1234);
                assert_eq!(target.user_context.rsp, 0x5678);
            }
            let physical = arch::virt_to_phys(core::ptr::addr_of!(IPC) as u64);
            for rights in [FrameRights::ReadOnly, FrameRights::KernelOnly] {
                bind_invoker_cap(KERNEL.get(), invoker, crate::cte::TcbSlot::IpcBuffer,
                    Cap::Frame { ptr: PAddr::new(physical), size: FrameSize::Small, rights,
                        mapped: None, asid: 0, is_device: false, map_type: FrameMapType::None }, 0x1000);
                IPC.0[5] = 0x246;
                // A prior request's staged tail must not replace this request's buffer bytes.
                KERNEL.get().scheduler.slab.get_mut(invoker).msg_regs[4] = 0x202;
                let result = decode_invocation(cap, &request(3, 5), invoker);
                if rights == FrameRights::ReadOnly {
                    result.unwrap();
                    let t = KERNEL.get().scheduler.slab.get(target);
                    assert_eq!(t.user_context.rip, 0x400000);
                    assert_eq!(t.user_context.rsp, 0x800000);
                    assert_eq!(t.user_context.rflags, 0x246);
                    decode_invocation(cap, &request(0, 2), invoker).unwrap();
                    let t = KERNEL.get().scheduler.slab.get(target);
                    assert_eq!(t.user_context.rip, 0x400000);
                    assert_eq!(t.user_context.rsp, 0x800000);
                    assert_eq!(t.user_context.rflags, 0x246);
                    let (registers, count) = read_tcb_register_request::<20>(
                        KERNEL.get().scheduler.slab.get(invoker), &request(21, 23)).unwrap();
                    assert_eq!(count, 20);
                    assert_eq!(registers[2], 0x246);
                    let t = KERNEL.get().scheduler.slab.get_mut(target);
                    t.use_iretq_resume = true;
                    t.user_context.rcx = 0xABCD;
                    t.user_context.r11 = 0xBCDE;
                    decode_invocation(cap, &request(1, 3), invoker).unwrap();
                    let t = KERNEL.get().scheduler.slab.get(target);
                    assert_eq!(t.user_context.rsp, 0x800000);
                    assert_eq!(t.user_context.rflags, 0x246);
                    assert_eq!(t.user_context.rcx, 0xABCD);
                    assert_eq!(t.user_context.r11, 0xBCDE);
                    assert!(t.use_iretq_resume);
                    decode_invocation(cap, &request(21, 23), invoker).unwrap();
                    let t = KERNEL.get().scheduler.slab.get(target);
                    assert_eq!(t.user_context.rip, 0x400000);
                    assert_eq!(t.user_context.rflags, 0x246);
                    assert_eq!(t.user_context.rcx, 0);
                    assert_eq!(t.cpu_context.gs_base, 0);
                } else {
                    assert!(matches!(result, Err(KException::SyscallError(error))
                        if error.code == seL4_Error::seL4_TruncatedMessage));
                    assert_eq!(KERNEL.get().scheduler.slab.get(target).user_context.rflags, 0x246);
                }
            }
            KERNEL.get().scheduler.make_runnable(target);
            let before = KERNEL.get().scheduler.slab.get(target).state;
            let mut read = SyscallArgs {
                a1: crate::types::seL4_MessageInfo_t::new(
                    InvocationLabel::TCBReadRegisters as u64, 0, 0, 2).words[0],
                a2: 1, a3: 0, ..Default::default()
            };
            assert!(matches!(decode_invocation(cap, &read, invoker),
                Err(KException::SyscallError(error)) if error.code == seL4_Error::seL4_RangeError));
            assert_eq!(KERNEL.get().scheduler.slab.get(target).state, before);
            read.a3 = 2;
            decode_invocation(cap, &read, invoker).unwrap();
            assert_eq!(KERNEL.get().scheduler.slab.get(target).state,
                crate::tcb::ThreadStateType::Inactive);
            assert_eq!(KERNEL.get().scheduler.slab.get(invoker).ipc_length, 2);
            let invoker_cap = Cap::Thread { tcb: PPtr::new(invoker.0 as u64).unwrap() };
            assert!(matches!(decode_invocation(invoker_cap, &read, invoker),
                Err(KException::SyscallError(error)) if error.code == seL4_Error::seL4_IllegalOperation));
            assert!(matches!(decode_invocation(invoker_cap, &request(0, 2), invoker),
                Err(KException::SyscallError(error)) if error.code == seL4_Error::seL4_IllegalOperation));
            teardown_thread_in(KERNEL.get(), target);
            teardown_invoker(invoker);
        }
        arch::log("  WriteRegisters requires complete readable payload without stale staging\n");
    }
}
