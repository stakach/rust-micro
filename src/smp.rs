//! Phase 10b / 28 — multi-CPU support.
//!
//! Mirrors seL4's `NODE_STATE` / `ksSMP[]` machinery and the IPI
//! plumbing in `src/smp/ipi.c`. The actual APIC programming +
//! cross-CPU IPI vector lives in arch/x86_64; this module owns the
//! pure data-structure side plus the BSP/AP barrier counters.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::tcb::TcbId;

// ---------------------------------------------------------------------------
// AP bring-up barrier (Phase 28a).
//
// BOOTBOOT lands every CPU at `_start` in long mode. The BSP path
// runs full kernel init; AP paths perform per-CPU init then bump
// `APS_ALIVE`. The BSP busy-waits for the count to match the
// reported `numcores - 1` before running the spec runner / demo,
// so per-CPU MSRs and TSS are fully programmed when threads start
// migrating.
// ---------------------------------------------------------------------------

/// Set by the BSP once shared global structures (GDT contents,
/// IDT contents) are fully populated. APs spin on this before
/// loading the GDT/IDT so they don't lgdt-into-zeros and triple-fault.
pub static BSP_READY: AtomicBool = AtomicBool::new(false);

/// Mark all shared init done. BSP calls this after its own
/// init_gdt / init_interrupts / init_exceptions complete.
pub fn signal_bsp_ready() {
    BSP_READY.store(true, Ordering::Release);
}

/// Spin until BSP has populated the shared GDT and IDT.
pub fn wait_for_bsp_ready() {
    while !BSP_READY.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
}

/// Number of APs that have completed `ap_init` and are now idle in
/// HLT. Bumped once per AP; the BSP reads it as the barrier
/// condition.
pub static APS_ALIVE: AtomicU32 = AtomicU32::new(0);

/// Mark the calling CPU as alive — bumps `APS_ALIVE`. Called by
/// each AP after it finishes per-CPU init.
pub fn mark_ap_alive() {
    APS_ALIVE.fetch_add(1, Ordering::SeqCst);
}

/// Spin until at least `n_aps` APs have called `mark_ap_alive`.
/// Called by the BSP after its own init completes.
pub fn wait_for_aps(n_aps: u32) {
    while APS_ALIVE.load(Ordering::SeqCst) < n_aps {
        core::hint::spin_loop();
    }
}

/// Read-only accessor for specs.
pub fn aps_alive() -> u32 {
    APS_ALIVE.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Big Kernel Lock (Phase 28b).
//
// The kernel runs with IF=0 (SYSCALL FMASK clears IF; IRQ entry has
// IF=0; exception entries cleared via the gate type), so within a
// single CPU it cannot re-enter itself. Across CPUs, however, two
// kernel paths could land in `KERNEL.get()` simultaneously — every
// kernel mutation (scheduler queues, cap pools, TCB user_context
// writes) is protected by this single lock.
//
// Granularity: one lock for the whole kernel. Real seL4 uses
// per-subsystem locking; we'll get there in a later phase. For now,
// correctness > scaling.
//
// `BKL` holds 0 when free, or `cpu_id + 1` of the holding CPU. The
// "+1 to encode unlocked" trick lets us release with a plain
// store-zero and detect "this CPU already holds the BKL" panics
// in debug builds.
// ---------------------------------------------------------------------------

pub static BKL: AtomicU32 = AtomicU32::new(0);

/// Acquire the BKL. Spins until granted. Caller must be in kernel
/// mode with IF=0 (so the same CPU can't re-enter via interrupt).
pub fn bkl_acquire() {
    let me = crate::arch::get_cpu_id() + 1;
    loop {
        match BKL.compare_exchange_weak(
            0,
            me,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(_) => {
                while BKL.load(Ordering::Relaxed) != 0 {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

/// Release the BKL. Must be called by the same CPU that acquired it
/// — we don't enforce that today (asserting the holder would cost
/// an extra atomic load), but the kernel's structure guarantees it
/// since IF=0 prevents foreign release.
pub fn bkl_release() {
    BKL.store(0, Ordering::Release);
}

/// Read-only accessor for specs. Returns 0 if free, otherwise
/// `cpu_id + 1` of the holder.
pub fn bkl_holder() -> u32 {
    BKL.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Per-CPU NodeState storage (Phase 28d).
//
// `signal_ipi` / `handle_ipis` (above) operate on `&mut PerCpu<NodeState>`.
// We need a single instance the kernel can borrow under BKL. Wrapped in
// `UnsafeCell` like `KERNEL` because Rust's borrow rules don't model
// "BKL-serialized exclusive access" — the BKL takes the role of `&mut`.
// ---------------------------------------------------------------------------

/// A `PerCpu<NodeState>` where every entry is initialised to
/// `NodeState::default()`. Read/written under BKL.
struct IpiNodes(core::cell::UnsafeCell<PerCpu<NodeState>>);

/// SAFETY: BKL serializes all access — the `UnsafeCell` rule of "no
/// other reference exists when you have `&mut`" is enforced by the
/// kernel structure (every entry into `nodes_mut()` happens with BKL
/// held).
unsafe impl Sync for IpiNodes {}

const NODE_INIT: NodeState = NodeState {
    current: None,
    idle: None,
    pending_ipis: 0,
    ipi_cause: [None; MAX_CPUS],
};

static IPI_NODES: IpiNodes =
    IpiNodes(core::cell::UnsafeCell::new(PerCpu { entries: [NODE_INIT; MAX_CPUS] }));

/// Borrow the per-CPU node array mutably. Caller must hold the BKL.
pub fn nodes_mut() -> &'static mut PerCpu<NodeState> {
    unsafe { &mut *IPI_NODES.0.get() }
}

/// Read-only accessor used by atomic counters (e.g. spec polls).
pub fn node(cpu: u32) -> &'static NodeState {
    unsafe { &(*IPI_NODES.0.get()).entries[cpu as usize] }
}

// ---------------------------------------------------------------------------
// Send + observe an IPI by CPU id.
//
// `send_ipi(target_cpu, kind)`:
//   1. registers the cause in `IPI_NODES[target_cpu]` under the
//      caller's CPU bit,
//   2. writes the LAPIC ICR to fan vector `IPI_VECTOR` to the target.
// ---------------------------------------------------------------------------

/// IDT vector reserved for cross-CPU reschedule + IPI dispatch.
/// Must not collide with PIC vectors (0x20..0x2F), LAPIC timer
/// (0xEF), or spurious (0xFF).
pub const IPI_VECTOR: u8 = 0x40;

/// Send an IPI from the current CPU to `target_cpu`. Caller must
/// hold the BKL — we mutate the target's NodeState under the
/// assumption that no other CPU's send/handle is racing.
#[cfg(target_arch = "x86_64")]
pub fn send_ipi(target_cpu: u32, kind: IpiKind) {
    let from = crate::arch::get_cpu_id();
    if from == target_cpu {
        return; // self-IPI is a no-op (matches signal_ipi semantics).
    }
    signal_ipi(nodes_mut(), from, target_cpu, kind);
    // Hardware delivery: assume APIC ID == cpu_id. (See main.rs
    // `ap_main` for the same simplification.) Phase 28+ may need a
    // MADT-driven cpu_id → apic_id table.
    crate::arch::x86_64::lapic::send_ipi(target_cpu as u8, IPI_VECTOR);
}

/// Counter bumped by the IPI ISR for spec observability. Each ISR
/// invocation increments by 1 so the BSP can spin on this from
/// outside the BKL to confirm the AP processed the IPI.
pub static IPI_HANDLED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Maximum CPUs we'll ever run on. Picked small so the per-CPU
/// arrays fit on the stack inside specs and on the BSS in the
/// production kernel without alloc().
pub const MAX_CPUS: usize = 4;

/// Per-CPU container. `T` is the per-CPU state type; `N` defaults to
/// `MAX_CPUS`. Indexed by 0-based CPU number.
#[derive(Copy, Clone, Debug)]
pub struct PerCpu<T, const N: usize = MAX_CPUS> {
    pub entries: [T; N],
}

impl<T: Copy + Default, const N: usize> Default for PerCpu<T, N> {
    fn default() -> Self {
        Self { entries: [T::default(); N] }
    }
}

impl<T, const N: usize> PerCpu<T, N> {
    pub const fn new(initial: [T; N]) -> Self { Self { entries: initial } }

    pub fn get(&self, cpu: u32) -> Option<&T> {
        self.entries.get(cpu as usize)
    }
    pub fn get_mut(&mut self, cpu: u32) -> Option<&mut T> {
        self.entries.get_mut(cpu as usize)
    }
}

// ---------------------------------------------------------------------------
// Per-CPU node state. Mirrors seL4's `nodeState` struct (the parts
// we already represent — current thread, idle thread, ready queues).
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default)]
pub struct NodeState {
    /// The TCB currently running on this CPU.
    pub current: Option<TcbId>,
    /// The idle TCB (set once at boot).
    pub idle: Option<TcbId>,
    /// Pending IPI work — bitmap of CPUs that signalled us. Cleared
    /// on IPI handling.
    pub pending_ipis: u32,
    /// Per-CPU IPI cause table. Set by the remote CPU before
    /// signalling and cleared by us when handling.
    pub ipi_cause: [Option<IpiKind>; MAX_CPUS],
}

/// IPI variants. Mirrors seL4's `IpiRemoteCall_*` enum.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum IpiKind {
    /// Reschedule the target CPU (it should re-run choose_thread).
    Reschedule,
    /// Invalidate a TLB entry. The vaddr fits in a u64 — simplification
    /// for the spec; production carries an asid+range pair.
    InvalidateTlb { vaddr: u64 },
    /// Stop the target CPU (used during shutdown).
    Stop,
}

// ---------------------------------------------------------------------------
// IPI dispatch.
// ---------------------------------------------------------------------------

/// Mark that `from_cpu` wants `to_cpu` to handle `kind`. The actual
/// hardware send (writing the LAPIC ICR register) is the arch
/// driver's job; this routine handles the in-kernel bookkeeping.
pub fn signal_ipi(
    nodes: &mut PerCpu<NodeState>,
    from_cpu: u32,
    to_cpu: u32,
    kind: IpiKind,
) {
    if from_cpu == to_cpu {
        // self-IPI is meaningless; let the caller catch this.
        return;
    }
    if let Some(target) = nodes.get_mut(to_cpu) {
        target.pending_ipis |= 1u32 << from_cpu;
        target.ipi_cause[from_cpu as usize] = Some(kind);
    }
}

/// Drain pending IPIs on `cpu` and apply them via `apply`. Returns
/// the number of IPIs dispatched.
pub fn handle_ipis<F: FnMut(u32, IpiKind)>(
    nodes: &mut PerCpu<NodeState>,
    cpu: u32,
    mut apply: F,
) -> u32 {
    let node = match nodes.get_mut(cpu) {
        Some(n) => n,
        None => return 0,
    };
    let pending = node.pending_ipis;
    node.pending_ipis = 0;
    let mut count = 0;
    for from in 0..MAX_CPUS as u32 {
        if (pending & (1u32 << from)) == 0 {
            continue;
        }
        if let Some(kind) = node.ipi_cause[from as usize].take() {
            apply(from, kind);
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_smp() {
        arch::log("Running SMP tests...\n");
        per_cpu_indexes_correctly();
        signal_then_handle_round_trip();
        multiple_signals_coalesce_into_pending_mask();
        self_ipi_is_a_no_op();
        all_aps_came_up();
        bkl_acquire_release_round_trip();
        cross_cpu_ipi_delivers_and_runs_isr();
        arch::log("SMP tests completed\n");
    }

    /// Phase 28d — fire an IPI from BSP (running this spec) to AP1
    /// and confirm AP1's ISR ran. AP1 is parked in `hlt`; the IPI
    /// wakes it, the ISR drains pending IPIs and bumps
    /// `IPI_HANDLED_COUNT`, then `iretq` back to `hlt`. We poll
    /// the counter from BSP outside the BKL.
    #[inline(never)]
    fn cross_cpu_ipi_delivers_and_runs_isr() {
        // Skip if running with -smp 1.
        if crate::bootboot::get_num_cores() < 2 {
            arch::log("  ✓ IPI test skipped (single-CPU launch)\n");
            return;
        }

        let before = IPI_HANDLED_COUNT.load(Ordering::SeqCst);

        // Send Reschedule IPI to CPU 1 under BKL.
        bkl_acquire();
        send_ipi(1, IpiKind::Reschedule);
        bkl_release();

        // Wait for AP1's ISR to bump the counter. Tight bound;
        // typical QEMU IPI latency is < 100k spin iterations.
        let mut spins = 0u64;
        loop {
            if IPI_HANDLED_COUNT.load(Ordering::SeqCst) > before {
                break;
            }
            spins += 1;
            if spins > 100_000_000 {
                panic!("IPI_HANDLED_COUNT never advanced — AP1 ISR didn't run");
            }
            core::hint::spin_loop();
        }

        // After the ISR drains, AP1's pending bitmap is empty and
        // its cause slot for BSP (CPU 0) is cleared.
        let n = node(1);
        assert_eq!(n.pending_ipis & 1, 0,
            "AP1's pending bit for BSP should be cleared");
        assert!(n.ipi_cause[0].is_none(),
            "AP1's cause slot for BSP should be cleared");
        arch::log("  ✓ BSP→AP1 Reschedule IPI delivered + handled\n");
    }

    /// Phase 28b — BKL primitive.
    /// Acquire then release leaves the lock free; a second acquire
    /// after release succeeds. (We don't try to test contention
    /// from the spec runner since it runs single-threaded; that
    /// surfaces in 28d when APs make actual kernel calls.)
    #[inline(never)]
    fn bkl_acquire_release_round_trip() {
        // BKL must be free at the start of each spec — earlier
        // tests ran in a single-CPU context that didn't leak it.
        assert_eq!(bkl_holder(), 0, "BKL should be free at spec start");

        bkl_acquire();
        let me = crate::arch::get_cpu_id() + 1;
        assert_eq!(bkl_holder(), me, "BKL should record this CPU's id+1");
        bkl_release();
        assert_eq!(bkl_holder(), 0, "BKL should be free after release");

        // A second cycle proves release actually frees the lock
        // (not just that we crashed and restarted).
        bkl_acquire();
        bkl_release();
        assert_eq!(bkl_holder(), 0);
        arch::log("  ✓ BKL acquire/release round-trip\n");
    }

    /// Phase 28a — by the time the spec runner executes, the BSP has
    /// already barriered on `wait_for_aps`, so `APS_ALIVE` must equal
    /// `numcores - 1`. Confirms each AP completed its per-CPU init
    /// path and is parked in HLT.
    #[inline(never)]
    fn all_aps_came_up() {
        let total = crate::bootboot::get_num_cores() as u32;
        let expected_aps = total.saturating_sub(1);
        assert_eq!(aps_alive(), expected_aps,
            "APS_ALIVE should equal numcores-1 once BSP is past barrier");
        arch::log("  ✓ all APs reached the barrier\n");
    }

    #[inline(never)]
    fn per_cpu_indexes_correctly() {
        let mut nodes: PerCpu<NodeState> = PerCpu::default();
        nodes.get_mut(2).unwrap().current = Some(TcbId(7));
        assert_eq!(nodes.get(2).unwrap().current, Some(TcbId(7)));
        assert_eq!(nodes.get(0).unwrap().current, None);
        // Out-of-range CPU returns None.
        assert!(nodes.get(99).is_none());
        arch::log("  ✓ PerCpu indexes by CPU id\n");
    }

    #[inline(never)]
    fn signal_then_handle_round_trip() {
        let mut nodes: PerCpu<NodeState> = PerCpu::default();
        signal_ipi(&mut nodes, 0, 1, IpiKind::Reschedule);
        // CPU 1 sees a pending bit for CPU 0 and the cause set.
        let n = nodes.get(1).unwrap();
        assert_eq!(n.pending_ipis, 1u32 << 0);
        assert_eq!(n.ipi_cause[0], Some(IpiKind::Reschedule));

        // Drain on CPU 1.
        let mut seen: Option<(u32, IpiKind)> = None;
        let dispatched = handle_ipis(&mut nodes, 1, |from, kind| {
            seen = Some((from, kind));
        });
        assert_eq!(dispatched, 1);
        assert_eq!(seen, Some((0, IpiKind::Reschedule)));
        // After draining, the queue is clear.
        assert_eq!(nodes.get(1).unwrap().pending_ipis, 0);
        assert!(nodes.get(1).unwrap().ipi_cause[0].is_none());
        arch::log("  ✓ signal_ipi → handle_ipis round-trip\n");
    }

    #[inline(never)]
    fn multiple_signals_coalesce_into_pending_mask() {
        let mut nodes: PerCpu<NodeState> = PerCpu::default();
        signal_ipi(&mut nodes, 0, 3, IpiKind::Reschedule);
        signal_ipi(&mut nodes, 1, 3, IpiKind::InvalidateTlb { vaddr: 0x1000 });
        signal_ipi(&mut nodes, 2, 3, IpiKind::Stop);

        let n = nodes.get(3).unwrap();
        // Three sources set bits 0, 1, 2.
        assert_eq!(n.pending_ipis, 0b0111);

        let mut count = 0;
        handle_ipis(&mut nodes, 3, |_from, _kind| { count += 1; });
        assert_eq!(count, 3);
        arch::log("  ✓ pending mask coalesces multiple senders\n");
    }

    #[inline(never)]
    fn self_ipi_is_a_no_op() {
        let mut nodes: PerCpu<NodeState> = PerCpu::default();
        signal_ipi(&mut nodes, 1, 1, IpiKind::Reschedule);
        assert_eq!(nodes.get(1).unwrap().pending_ipis, 0);
        arch::log("  ✓ self-IPI ignored\n");
    }
}
