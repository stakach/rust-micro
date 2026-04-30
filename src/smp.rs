//! Phase 10b — multi-CPU support.
//!
//! Mirrors seL4's `NODE_STATE` / `ksSMP[]` machinery and the IPI
//! plumbing in `src/smp/ipi.c`. The actual APIC programming +
//! cross-CPU IPI vector lives in arch/x86_64; this module owns the
//! pure data-structure side, which is testable on the BSP today.
//!
//! Gated behind the `smp` cargo feature.

#![cfg(feature = "smp")]

use crate::tcb::TcbId;

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
        arch::log("SMP tests completed\n");
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
