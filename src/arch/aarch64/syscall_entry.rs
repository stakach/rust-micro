//! seL4-compatible AArch64 SVC dispatch.

use crate::arch::UserContext;
use crate::kernel::KERNEL;
use crate::syscall_handler::{handle_syscall, DebugSink, SyscallArgs};
use crate::syscalls::Syscall;
use crate::tcb::{TcbId, ThreadStateType};

struct BklGuard;

impl Drop for BklGuard {
    fn drop(&mut self) {
        crate::smp::bkl_release();
    }
}

struct SerialSink;

impl DebugSink for SerialSink {
    fn put_byte(&mut self, byte: u8) {
        if let Ok(text) = core::str::from_utf8(core::slice::from_ref(&byte)) {
            crate::arch::log(text);
        }
    }
}

fn may_consume_direct_handoff(syscall: Syscall, reply: u64) -> bool {
    matches!(
        syscall,
        Syscall::SysReplyRecv | Syscall::SysNBSendRecv | Syscall::SysNBSendWait
    ) || (matches!(syscall, Syscall::SysCall) && reply == crate::invocation::REPLY_HANDOFF_MAGIC)
}

fn completed_receive(
    syscall: Syscall,
    next: TcbId,
    current: Option<TcbId>,
    invoker: Option<TcbId>,
    succeeded: bool,
) -> bool {
    succeeded
        && matches!(
            syscall,
            Syscall::SysRecv
                | Syscall::SysNBRecv
                | Syscall::SysReplyRecv
                | Syscall::SysNBSendRecv
                | Syscall::SysNBSendWait
                | Syscall::SysWait
                | Syscall::SysNBWait
        )
        && Some(next) == current
        && Some(next) == invoker
}

fn activate_thread_vspace(id: TcbId) {
    let tcb = unsafe { KERNEL.get().scheduler.slab.get(id) };
    if let crate::cap::Cap::PML4 {
        ptr,
        asid,
        mapped: true,
        ..
    } = tcb.vspace_root
    {
        crate::arch::aarch64::vspace::activate_user_vspace(ptr.addr(), asid);
    } else if tcb.cpu_context.cr3 != 0 {
        crate::arch::aarch64::vspace::activate_user_vspace(tcb.cpu_context.cr3, 0);
    }
}

fn choose_next(may_handoff: bool) -> Option<TcbId> {
    unsafe {
        let state = KERNEL.get();
        loop {
            let next = if may_handoff {
                state.scheduler.take_direct_handoff()
            } else {
                state.scheduler.nodes[crate::arch::get_cpu_id() as usize].direct_handoff = None;
                None
            }
            .or_else(|| state.scheduler.current())
            .or_else(|| state.scheduler.choose_thread());
            match next {
                Some(id) if !crate::sched_context::dispatch_budget_check(id) => continue,
                other => return other,
            }
        }
    }
}

fn publish_receive(context: &mut UserContext, tcb: &crate::tcb::Tcb) {
    let info = (tcb.ipc_label << 12)
        | (((tcb.received_extra_caps as u64) & 0x3) << 7)
        | (tcb.ipc_length as u64 & 0x7f);
    crate::arch::set_ipc_return(context, tcb.ipc_badge, info, &tcb.msg_regs[..4]);

    if tcb.ipc_length as usize > 4 && tcb.ipc_buffer_paddr != 0 {
        let buffer = (crate::arch::phys_to_virt(tcb.ipc_buffer_paddr) as *mut u64).wrapping_add(1);
        let count = (tcb.ipc_length as usize).min(tcb.msg_regs.len());
        for index in 4..count {
            unsafe { core::ptr::write_volatile(buffer.add(index), tcb.msg_regs[index]) };
        }
    }
}

fn wait_for_runnable() -> TcbId {
    loop {
        crate::smp::bkl_release();
        unsafe {
            core::arch::asm!(
                "msr daifclr, #2",
                "wfi",
                "msr daifset, #2",
                options(nomem, nostack),
            );
        }
        crate::smp::bkl_acquire();
        if let Some(next) = choose_next(false) {
            return next;
        }
    }
}

/// Handle one lower-EL SVC using seL4's AArch64 register ABI.
pub fn dispatch(frame: *mut UserContext) {
    crate::smp::bkl_acquire();
    let _guard = BklGuard;
    crate::smp::SYSCALL_COUNT_PER_CPU[crate::arch::get_cpu_id() as usize]
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let context = unsafe { &mut *frame };
    let invoker = unsafe {
        let state = KERNEL.get();
        let id = state
            .scheduler
            .active_user()
            .or_else(|| state.scheduler.current());
        if let Some(id) = id {
            state.scheduler.set_current(Some(id));
            let tcb = state.scheduler.slab.get_mut(id);
            tcb.user_context = *context;
            crate::arch::aarch64::context::save_exception_fpu(frame, &mut tcb.aarch64_fpu_state);
            if !tcb.state.is_runnable() {
                tcb.state = ThreadStateType::Running;
            }
        }
        id
    };

    let args = SyscallArgs {
        a0: context.x[0],
        a1: context.x[1],
        a2: context.x[2],
        a3: context.x[3],
        a4: context.x[4],
        a5: context.x[5],
    };
    let number = context.x[7];
    let Some(syscall) = Syscall::from_i32(number as i32) else {
        unsafe {
            let state = KERNEL.get();
            if let Some(id) = invoker {
                if crate::fault::deliver_fault(
                    id,
                    crate::fault::FaultMessage::UnknownSyscall { number },
                )
                .is_err()
                {
                    state.scheduler.block(id, ThreadStateType::Inactive);
                }
            }
        }
        dispatch_selected(context, invoker, Syscall::SysYield, false, false);
        return;
    };

    let mut sink = SerialSink;
    let result = handle_syscall(syscall, &args, &mut sink);

    if matches!(syscall, Syscall::SysDebugPutChar) {
        if let Some(success) = crate::rootserver::sel4test_check_byte(args.a0 as u8) {
            crate::arch::qemu_exit(if success { 0 } else { 255 });
        }
    }

    dispatch_selected(
        context,
        invoker,
        syscall,
        result.is_ok(),
        may_consume_direct_handoff(syscall, context.x[6]),
    );
}

pub(super) fn dispatch_selected(
    context: &mut UserContext,
    invoker: Option<TcbId>,
    syscall: Syscall,
    succeeded: bool,
    may_handoff: bool,
) {
    let next = choose_next(may_handoff).unwrap_or_else(wait_for_runnable);
    unsafe {
        let state = KERNEL.get();
        state.scheduler.set_current(Some(next));
        state.scheduler.set_active_user(Some(next));
        crate::sched_context::complete_yield_if_pending(next);

        let current = state.scheduler.current();
        let tcb = state.scheduler.slab.get(next);
        let mut next_context = tcb.user_context;
        if completed_receive(syscall, next, current, invoker, succeeded) {
            publish_receive(&mut next_context, tcb);
        }
        crate::arch::aarch64::debug::restore_user_debug_context(&tcb.debug, &mut next_context);
        crate::arch::aarch64::context::restore_exception_fpu(context, &tcb.aarch64_fpu_state);
        crate::arch::aarch64::context::set_user_fpu_access(tcb.flags & 1 != 0);
        state.scheduler.slab.get_mut(next).user_context = next_context;
        *context = next_context;
    }
    activate_thread_vspace(next);
}
