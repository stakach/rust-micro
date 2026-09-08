#[derive(Copy, Clone)]
pub(crate) enum UserEntryKind {
    Interrupt,
    Syscall,
    Fault,
    Debug { status: u64 },
    Breakpoint,
    #[cfg(target_arch = "aarch64")]
    ArmDebug { esr: u64, far: u64 },
}

#[derive(Copy, Clone)]
pub(crate) struct UserEntrySnapshot {
    pub context: crate::arch::UserContext,
    pub kind: UserEntryKind,
    #[cfg(target_arch = "aarch64")]
    pub fpu: crate::tcb::Aarch64FpuState,
}

#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn arm_user_entry(
    frame: *const crate::arch::UserContext,
    kind: UserEntryKind,
) -> Option<UserEntrySnapshot> {
    let context = *frame;
    if context.spsr_el1 & 0xf != 0 { return None; }
    let mut fpu = crate::tcb::Aarch64FpuState::ZERO;
    crate::arch::aarch64::context::save_exception_fpu(frame, &mut fpu);
    Some(UserEntrySnapshot { context, kind, fpu })
}

struct QuiescenceSnapshot {
    entry: Option<UserEntrySnapshot>,
    #[cfg(target_arch = "x86_64")]
    fpu: Option<(TcbId, crate::tcb::FxArea)>,
}

struct QuiescenceMailbox {
    // 0 idle, 1 requested, 2 captured, 3 released. The final remote store to zero
    // prevents a subsequent controller request from overwriting an unseen release.
    phase: core::sync::atomic::AtomicU8,
    snapshot: core::cell::UnsafeCell<Option<QuiescenceSnapshot>>,
}

unsafe impl Sync for QuiescenceMailbox {}

impl QuiescenceMailbox {
    const fn new() -> Self {
        Self {
            phase: core::sync::atomic::AtomicU8::new(0),
            snapshot: core::cell::UnsafeCell::new(None),
        }
    }
}

static QUIESCENCE: [QuiescenceMailbox; MAX_CPUS] =
    [const { QuiescenceMailbox::new() }; MAX_CPUS];

#[cfg(all(target_arch = "x86_64", feature = "spec"))]
static WAITING_ENTRY_KIND: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

#[cfg(all(target_arch = "x86_64", feature = "spec"))]
fn observe_waiting_entry(entry: &Option<UserEntrySnapshot>) {
    let kind = match entry.as_ref().map(|entry| entry.kind) {
        None => 0,
        Some(UserEntryKind::Syscall) => 1,
        Some(_) => 2,
    };
    WAITING_ENTRY_KIND[crate::arch::get_cpu_id() as usize].store(kind, Ordering::Release);
}

// Runs before acquiring BKL, including IF-clear lock contention. It accesses only
// this CPU's architectural state and mailbox, never KERNEL or a TCB reference.
fn service_quiescence(entry: &mut Option<UserEntrySnapshot>) -> bool {
    let mailbox = &QUIESCENCE[crate::arch::get_cpu_id() as usize];
    if mailbox.phase.load(Ordering::Acquire) != 1 {
        return false;
    }
    let captured = entry.take();
    #[cfg(all(target_arch = "x86_64", feature = "spec"))]
    observe_waiting_entry(entry);
    let adopted = captured.is_some();
    let snapshot = QuiescenceSnapshot {
        entry: captured,
        #[cfg(target_arch = "x86_64")]
        fpu: crate::arch::x86_64::fpu_ctx::capture_local_for_quiescence(),
    };
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let root = crate::arch::x86_64::paging::kernel_root_cr3();
        assert_ne!(root, 0);
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::vspace::park_on_kernel_root();
    unsafe { *mailbox.snapshot.get() = Some(snapshot); }
    mailbox.phase.store(2, Ordering::Release);
    while mailbox.phase.load(Ordering::Acquire) != 3 {
        #[cfg(target_arch = "x86_64")]
        service_retirement_shootdown();
        core::hint::spin_loop();
    }
    mailbox.phase.store(0, Ordering::Release);
    adopted
}

/// Synchronously withdraw remote execution without releasing BKL. The caller's
/// exclusive KernelState borrow, source CTEs and finalization transaction remain
/// valid throughout. Repeated calls after withdrawal do not overwrite saved state.
pub fn remote_tcb_stall(s: &mut crate::kernel::KernelState, target: TcbId) -> bool {
    assert_eq!(bkl_holder(), crate::arch::get_cpu_id() + 1);
    let Some(tcb) = s.scheduler.slab.try_get(target) else { return false; };
    let cpu = tcb.affinity as usize;
    if cpu == crate::arch::get_cpu_id() as usize || cpu >= MAX_CPUS {
        return false;
    }
    let running = s.scheduler.active_user_for_cpu(cpu as u32)
        .or_else(|| s.scheduler.current_for_cpu(cpu as u32));
    let mut needed = running == Some(target);
    #[cfg(target_arch = "x86_64")]
    { needed |= crate::arch::x86_64::fpu_ctx::owner_is(cpu, target); }
    if !needed { return false; }
    assert_ne!(ONLINE_CPUS.load(Ordering::Acquire) & (1 << cpu), 0);
    let mailbox = &QUIESCENCE[cpu];
    assert_eq!(mailbox.phase.load(Ordering::Acquire), 0);
    mailbox.phase.store(1, Ordering::Release);
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::lapic::send_ipi(cpu as u8, IPI_VECTOR);
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::gic::send_sgi(cpu as u32, crate::arch::aarch64::interrupts::IPI_IRQ);
    while mailbox.phase.load(Ordering::Acquire) != 2 { core::hint::spin_loop(); }
    let snapshot = unsafe { (*mailbox.snapshot.get()).take().expect("captured remote state") };
    if let Some(mut entry) = snapshot.entry {
        let id = running.expect("remote user entry must have a retained execution owner");
        if matches!(entry.kind, UserEntryKind::Syscall) {
            // No syscall code has run before BKL admission. Re-execute the actual
            // entry instruction once after migration instead of losing its call.
            #[cfg(target_arch = "x86_64")]
            {
                entry.context.rip = entry.context.rcx.checked_sub(2).expect("SYSCALL return PC");
                entry.context.rflags = entry.context.r11;
            }
            #[cfg(target_arch = "aarch64")]
            { entry.context.elr_el1 = entry.context.elr_el1.checked_sub(4).expect("SVC return PC"); }
        }
        let tcb = s.scheduler.slab.get_mut(id);
        tcb.user_context = entry.context;
        #[cfg(target_arch = "x86_64")]
        {
            tcb.use_iretq_resume = true;
            crate::arch::x86_64::exceptions::defer_quiesced_debug(tcb, entry.kind);
        }
        #[cfg(target_arch = "aarch64")]
        {
            tcb.aarch64_fpu_state = entry.fpu;
            crate::arch::aarch64::exceptions::defer_quiesced_debug(tcb, entry.kind);
        }
    }
    #[cfg(target_arch = "x86_64")]
    if let Some((owner, state)) = snapshot.fpu {
        s.scheduler.slab.get_mut(owner).fpu_state = state;
    }
    s.scheduler.nodes[cpu].current = None;
    s.scheduler.nodes[cpu].active_user = None;
    s.scheduler.nodes[cpu].direct_handoff = None;
    mailbox.phase.store(3, Ordering::Release);
    while mailbox.phase.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
    true
}
