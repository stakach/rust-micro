use super::*;

#[cfg(target_arch = "x86_64")]
use super::legacy_context_protocol::{
    DEBUG_MASK, DEBUG_OFFSET, FX_MASK, READ_WORDS, REGISTER_WORDS, WRITE_WORDS,
};

/// Shared upstream register installer. The compact legacy three-register ABI is separate.
/// Preserve unsupplied registers and the independently configured TLS bases.
#[cfg(target_arch = "x86_64")]
pub(super) fn install_registers(t: &mut crate::tcb::Tcb, regs: &[u64]) {
    let mask = (1u64 << regs.len().min(18)) - 1;
    install_selected_registers(t, regs, mask);
}

#[cfg(target_arch = "x86_64")]
fn install_selected_registers(t: &mut crate::tcb::Tcb, regs: &[u64], mask: u64) {
    let selected = |index: usize| mask & (1u64 << index) != 0;
    let old_iretq = t.use_iretq_resume;
    let rip = if selected(0) {
        regs[0]
    } else {
        crate::fault::resume_ip(t)
    };
    // Upstream user-legal flags, with bit1 and IF forced. Unselected flags remain exact.
    let flags = if selected(2) {
        (regs[2] & 0xdd5) | 0x202
    } else {
        crate::fault::resume_flags(t)
    };
    let rcx = if selected(5) {
        regs[5]
    } else if old_iretq {
        t.user_context.rcx
    } else {
        0
    };
    let r11 = if selected(13) {
        regs[13]
    } else if old_iretq {
        t.user_context.r11
    } else {
        0
    };
    macro_rules! set {
        ($index:expr, $field:ident) => {
            if selected($index) {
                t.user_context.$field = regs[$index];
            }
        };
    }
    set!(1, rsp);
    set!(3, rax);
    set!(4, rbx);
    set!(6, rdx);
    set!(7, rsi);
    set!(8, rdi);
    set!(9, rbp);
    set!(10, r8);
    set!(11, r9);
    set!(12, r10);
    set!(14, r12);
    set!(15, r13);
    set!(16, r14);
    set!(17, r15);
    if selected(0) || selected(2) || selected(5) || selected(13) {
        // SYSRET uses RCX/R11 as IP/flags; independently selected RCX/R11 require IRET.
        let iretq = old_iretq || selected(5) || selected(13);
        t.user_context.rip = rip;
        t.user_context.rflags = flags;
        t.user_context.rcx = if iretq { rcx } else { rip };
        t.user_context.r11 = if iretq { r11 } else { flags };
        t.use_iretq_resume = iretq;
    }
}

#[cfg(target_arch = "x86_64")]
fn registers(t: &crate::tcb::Tcb) -> [u64; REGISTER_WORDS] {
    [
        crate::fault::resume_ip(t),
        t.user_context.rsp,
        crate::fault::resume_flags(t),
        t.user_context.rax,
        t.user_context.rbx,
        if t.use_iretq_resume {
            t.user_context.rcx
        } else {
            0
        },
        t.user_context.rdx,
        t.user_context.rsi,
        t.user_context.rdi,
        t.user_context.rbp,
        t.user_context.r8,
        t.user_context.r9,
        t.user_context.r10,
        if t.use_iretq_resume {
            t.user_context.r11
        } else {
            0
        },
        t.user_context.r12,
        t.user_context.r13,
        t.user_context.r14,
        t.user_context.r15,
        0,
        0,
    ]
}

pub(super) fn invoke(
    s: &mut KernelState,
    target: u64,
    label: InvocationLabel,
    args: &SyscallArgs,
    invoker: TcbId,
) -> KResult<()> {
    #[cfg(target_arch = "aarch64")]
    {
        let _ = (s, target, label, args, invoker);
        Err(tcb_cap_error(seL4_Error::seL4_IllegalOperation))
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use crate::arch::x86_64::debug;
        use crate::arch::x86_64::fpu_ctx;
        const _: () = assert!(WRITE_WORDS <= crate::types::seL4_MsgMaxLength);
        const _: () = assert!(InvocationLabel::TCBReadLegacyContext as u64 == 69);
        const _: () = assert!(InvocationLabel::TCBWriteLegacyContext as u64 == 70);
        let id = TcbId(
            u16::try_from(target).map_err(|_| tcb_cap_error(seL4_Error::seL4_InvalidCapability))?,
        );
        if id == invoker || s.scheduler.slab.try_get(id).is_none() {
            return Err(tcb_cap_error(seL4_Error::seL4_IllegalOperation));
        }
        let write = label == InvocationLabel::TCBWriteLegacyContext;
        let info = crate::types::seL4_MessageInfo_t { words: [args.a1] };
        if info.length() != if write { WRITE_WORDS as u64 } else { 0 }
            || info.extra_caps() != 0
            || info.caps_unwrapped() != 0
        {
            return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
        }
        let inv = s.scheduler.slab.get(invoker);
        let ipc = if write {
            inv.ipc_buffer_send_paddr()
        } else {
            inv.ipc_buffer_receive_paddr()
        };
        if ipc == 0 {
            return Err(tcb_cap_error(seL4_Error::seL4_TruncatedMessage));
        }
        let mut words = [0u64; WRITE_WORDS];
        let mut fx = crate::tcb::FxArea::FINIT;
        let mut selection = 0;
        let mut debug_context = None;
        if write {
            words[..4].copy_from_slice(&[args.a2, args.a3, args.a4, args.a5]);
            let buffer = (crate::arch::phys_to_virt(ipc) as *const u64).add(1);
            for (index, word) in words.iter_mut().enumerate().skip(4) {
                *word = core::ptr::read_volatile(buffer.add(index));
            }
            selection = words[0];
            if !super::legacy_context_protocol::valid_selection(selection) {
                return Err(tcb_cap_error(seL4_Error::seL4_InvalidArgument));
            }
            if selection & FX_MASK != 0 {
                for (bytes, word) in
                    fx.0.chunks_exact_mut(8)
                        .zip(&words[1 + REGISTER_WORDS..1 + DEBUG_OFFSET])
                {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
                super::legacy_context_protocol::validate_fx_state(&mut fx.0, fpu_ctx::mxcsr_mask())
                    .map_err(|_| tcb_cap_error(seL4_Error::seL4_InvalidArgument))?;
            }
            if selection & DEBUG_MASK != 0 {
                debug_context = Some(
                    debug::validate_raw_context(
                        words[1 + DEBUG_OFFSET..WRITE_WORDS].try_into().unwrap(),
                    )
                    .map_err(|_| tcb_cap_error(seL4_Error::seL4_InvalidArgument))?,
                );
            }
        }
        // These operations retain BKL. The remote mailbox never borrows KernelState; once all
        // hardware owners are flushed no CPU can run the target between selected state groups.
        crate::smp::remote_tcb_stall(s, id);
        if fpu_ctx::owner_is(crate::arch::get_cpu_id() as usize, id) {
            fpu_ctx::flush_local_fpu(&mut s.scheduler.slab);
        }
        if write {
            if selection & FX_MASK != 0 {
                fpu_ctx::fpu_release(id);
            }
            let t = s.scheduler.slab.get_mut(id);
            if selection & super::legacy_context_protocol::RESTART_MASK != 0
                && selection & DEBUG_MASK == 0
                && u64::from(t.pending_fault)
                    == (crate::fault::FaultMessage::DebugException {
                        fault_ip: 0,
                        reason: 0,
                        trigger_addr: 0,
                        bp_num: 0,
                    })
                    .type_word()
            {
                // Restart consumes the delivered debug fault just like its normal reply.
                // Explicitly selected debug state wins over this acknowledgement effect.
                debug::acknowledge_fault(&mut t.debug);
            }
            install_selected_registers(
                t,
                &words[1..1 + REGISTER_WORDS],
                selection & super::legacy_context_protocol::REGISTER_MASK,
            );
            if selection & FX_MASK != 0 {
                t.fpu_state = fx;
            }
            if let Some(context) = &debug_context {
                debug::install_raw_context(&mut t.debug, context);
            }
            if selection & super::legacy_context_protocol::RESTART_MASK != 0 {
                crate::endpoint::cancel_ipc_anywhere(&mut s.scheduler, id);
                cancel_reply_wait_for_caller(s, id);
                s.scheduler.slab.get_mut(id).pending_fault = 0;
                s.scheduler.make_runnable(id);
            }
            write_invocation_words(s.scheduler.slab.get_mut(invoker), ipc, &[]);
        } else {
            let t = s.scheduler.slab.get(id);
            words[..REGISTER_WORDS].copy_from_slice(&registers(t));
            fx.0.copy_from_slice(&t.fpu_state.0);
            fx.0[28..32].copy_from_slice(&fpu_ctx::mxcsr_mask().to_le_bytes());
            for (word, bytes) in words[REGISTER_WORDS..DEBUG_OFFSET]
                .iter_mut()
                .zip(fx.0.chunks_exact(8))
            {
                *word = u64::from_le_bytes(bytes.try_into().unwrap());
            }
            words[DEBUG_OFFSET..READ_WORDS].copy_from_slice(&t.debug.dr);
            write_invocation_words(s.scheduler.slab.get_mut(invoker), ipc, &words[..READ_WORDS]);
        }
        Ok(())
    }
}
