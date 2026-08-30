//! IRQ → Notification dispatch.
//!
//! Mirrors `seL4/src/object/interrupt.c` for the parts that don't
//! touch real interrupt-controller hardware. Each IRQ has one of
//! three states:
//!   - Inactive — no handler, kernel masks it
//!   - Signal — an IRQHandler cap was issued and bound to a
//!     notification; when the IRQ fires, the kernel signals the
//!     notification with a badge of 0
//!   - IpiSignal / Reserved — used for IPIs / kernel-internal IRQs;
//!     we treat as Inactive for now
//!
//! The `IrqState` table is keyed by CPU delivery vector rather than by a controller-local pin.
//! Each issued handler owns an exact hardware source until the last handler capability is deleted.

use crate::notification::{signal, Notification};
use crate::scheduler::Scheduler;

/// Highest IRQ vector number represented by the kernel's IRQ capability table.
pub const MAX_IRQ: usize = 64;
pub const FIRST_IOAPIC_IRQ: u16 = 1;
pub const LAST_IOAPIC_IRQ: u16 = 15;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum IrqState {
    #[default]
    Inactive,
    /// Bound to a notification; when fired, deliver via `signal`.
    Signal,
    /// IPI or a kernel-internal IRQ — stub for now.
    Reserved,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum IrqSource {
    #[default]
    None,
    Generic,
    IoApic {
        controller: u16,
        pin: u16,
    },
}

/// Per-IRQ dispatch entry: state and (when state==Signal) the
/// notification index this IRQ is bound to. We use a slab-style
/// index rather than a pointer so the table is plain BSS.
#[derive(Copy, Clone, Debug, Default)]
pub struct IrqEntry {
    pub state: IrqState,
    /// Notification slab index, or `None` if no binding.
    pub notification: Option<u16>,
    /// Badge from the badged notification cap that was bound to this
    /// IRQ via IRQHandler::SetNotification. Signal() uses this value
    /// instead of 0 so userspace can route the IRQ to the right
    /// timer slot via CTZL(badge) (sel4test convention).
    pub badge: u64,
    /// True while a delivered IRQ has not yet been ack'd. seL4 masks
    /// the line at the controller; we just track the flag.
    pub pending: bool,
    /// Hardware source reserved by IRQControl for this vector. Binding and clearing a notification
    /// never discards route ownership; only deletion of the last handler capability releases it.
    pub source: IrqSource,
}

#[derive(Copy, Clone, Debug)]
pub struct IrqTable {
    pub entries: [IrqEntry; MAX_IRQ],
}

impl Default for IrqTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqTable {
    pub const fn new() -> Self {
        Self {
            entries: [IrqEntry {
                state: IrqState::Inactive,
                notification: None,
                badge: 0,
                pending: false,
                source: IrqSource::None,
            }; MAX_IRQ],
        }
    }
    pub fn get(&self, irq: u16) -> Option<&IrqEntry> {
        self.entries.get(irq as usize)
    }
    pub fn get_mut(&mut self, irq: u16) -> Option<&mut IrqEntry> {
        self.entries.get_mut(irq as usize)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IrqError {
    /// IRQ number out of range.
    Range,
    /// IRQ already has a handler bound.
    AlreadyBound,
    /// IRQ has no handler — can't ack a non-existent binding.
    NotBound,
}

pub fn reserve_source(table: &mut IrqTable, irq: u16, source: IrqSource) -> Result<(), IrqError> {
    can_reserve_source(table, irq, source)?;
    let entry = table
        .get_mut(irq)
        .expect("source reservation validated the IRQ index");
    entry.source = source;
    Ok(())
}

pub fn source(table: &IrqTable, irq: u16) -> Result<IrqSource, IrqError> {
    table
        .get(irq)
        .map(|entry| entry.source)
        .ok_or(IrqError::Range)
}

/// Bind an IRQ to a notification slab index. Mirrors
/// `IRQHandler::SetNotification` in seL4 (we don't implement
/// `IRQControl::Get` because that's about cap construction).
pub fn set_notification(
    table: &mut IrqTable,
    irq: u16,
    notification_index: u16,
    badge: u64,
) -> Result<(), IrqError> {
    let entry = table.get_mut(irq).ok_or(IrqError::Range)?;
    if entry.state != IrqState::Inactive {
        return Err(IrqError::AlreadyBound);
    }
    entry.state = IrqState::Signal;
    entry.notification = Some(notification_index);
    entry.badge = badge;
    Ok(())
}

/// Clear a binding. Mirrors `IRQHandler::Clear`.
pub fn clear_handler(table: &mut IrqTable, irq: u16) -> Result<(), IrqError> {
    let entry = table.get_mut(irq).ok_or(IrqError::Range)?;
    let source = entry.source;
    *entry = IrqEntry::default();
    entry.source = source;
    Ok(())
}

pub fn release_handler(table: &mut IrqTable, irq: u16) -> Result<IrqSource, IrqError> {
    let entry = table.get_mut(irq).ok_or(IrqError::Range)?;
    let source = entry.source;
    *entry = IrqEntry::default();
    Ok(source)
}

pub fn can_reserve_source(table: &IrqTable, irq: u16, source: IrqSource) -> Result<(), IrqError> {
    let entry = table.get(irq).ok_or(IrqError::Range)?;
    if entry.source != IrqSource::None || source == IrqSource::None {
        return Err(IrqError::AlreadyBound);
    }
    if let IrqSource::IoApic { controller, pin } = source {
        let route = IrqSource::IoApic { controller, pin };
        if table.entries.iter().any(|entry| entry.source == route) {
            return Err(IrqError::AlreadyBound);
        }
    }
    Ok(())
}

/// Acknowledge a fired IRQ. Mirrors `IRQHandler::Ack`. Setting
/// `pending = false` mirrors unmasking in the real PIC.
pub fn ack_irq(table: &mut IrqTable, irq: u16) -> Result<(), IrqError> {
    let entry = table.get_mut(irq).ok_or(IrqError::Range)?;
    if entry.state == IrqState::Inactive {
        return Err(IrqError::NotBound);
    }
    entry.pending = false;
    Ok(())
}

/// The kernel's central interrupt entry point (for IRQs the kernel
/// hands to userspace via a notification). Walks the table and, if
/// `irq` has a Signal binding, signals that notification.
///
/// `notifications` is a slab the caller indexes into; this keeps the
/// dispatcher independent of where notifications live in memory.
/// Returns `Some(thread)` if a thread was woken (the scheduler
/// might want to immediately switch to it).
pub fn handle_interrupt(
    table: &mut IrqTable,
    notifications: &mut [Notification],
    sched: &mut Scheduler,
    irq: u16,
) -> Option<crate::tcb::TcbId> {
    let entry = match table.get_mut(irq) {
        Some(e) => e,
        None => return None,
    };
    entry.pending = true;
    match entry.state {
        IrqState::Signal => {
            let idx = entry.notification?;
            let badge = entry.badge;
            let ntfn = notifications.get_mut(idx as usize)?;
            // Use the badge stored at SetNotification time. sel4test
            // mints a badged notification cap (BIT(N)) per timer IRQ
            // and binds it via IRQHandler::SetNotification; on signal
            // it expects to read that badge in rdi so its
            // handle_timer_interrupts() can `CTZL(badge)` to pick
            // the right per-timer callback. Signalling with badge=0
            // would route the wake into the "no-badge" branch and
            // skip the per-timer dispatch entirely.
            signal(ntfn, sched, badge)
        }
        IrqState::Inactive | IrqState::Reserved => None,
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;
    use crate::notification::{wait, Notification, WaitOutcome};
    use crate::tcb::{Tcb, ThreadStateType};

    fn runnable(prio: u8) -> Tcb {
        let mut t = Tcb::default();
        t.priority = prio;
        t.state = ThreadStateType::Running;
        // MCS is_schedulable needs an SC; placeholder index so
        // these specs' threads stay schedulable/enqueued.
        t.sc = Some(0);
        t
    }

    pub fn test_interrupt() {
        arch::log("Running IRQ tests...\n");
        irq_to_notification_round_trip();
        bind_unbind_rebind();
        ack_clears_pending();
        source_ownership_survives_binding_clear();
        out_of_range_irq_rejected();
        arch::log("IRQ tests completed\n");
    }

    #[inline(never)]
    fn irq_to_notification_round_trip() {
        let mut table = IrqTable::new();
        let mut ntfns = [Notification::new(); 2];
        let mut sched = Scheduler::new();
        let t = sched.admit(runnable(50));

        // Bind IRQ 7 to notification 1, then have `t` wait on it.
        set_notification(&mut table, 7, 1, 0).unwrap();
        wait(&mut ntfns[1], &mut sched, t);
        assert_eq!(
            sched.slab.get(t).state,
            ThreadStateType::BlockedOnNotification
        );

        // Fire the IRQ — the dispatcher signals notification 1 and
        // unblocks the waiter.
        let woken = handle_interrupt(&mut table, &mut ntfns, &mut sched, 7);
        assert_eq!(woken, Some(t));
        assert_eq!(sched.slab.get(t).state, ThreadStateType::Running);
        // The IRQ entry is now pending until ack.
        assert!(table.get(7).unwrap().pending);
        arch::log("  ✓ IRQ → notification → waiter wakes up\n");
    }

    #[inline(never)]
    fn bind_unbind_rebind() {
        let mut table = IrqTable::new();
        set_notification(&mut table, 3, 0, 0).unwrap();
        // Double-bind rejected.
        assert_eq!(
            set_notification(&mut table, 3, 1, 0),
            Err(IrqError::AlreadyBound),
        );
        // Clear, then re-bind.
        clear_handler(&mut table, 3).unwrap();
        assert_eq!(table.get(3).unwrap().state, IrqState::Inactive);
        set_notification(&mut table, 3, 1, 0).unwrap();
        assert_eq!(table.get(3).unwrap().notification, Some(1));
        arch::log("  ✓ bind/unbind/rebind transitions\n");
    }

    #[inline(never)]
    fn ack_clears_pending() {
        let mut table = IrqTable::new();
        let mut ntfns = [Notification::new()];
        let mut sched = Scheduler::new();
        set_notification(&mut table, 5, 0, 0).unwrap();
        handle_interrupt(&mut table, &mut ntfns, &mut sched, 5);
        assert!(table.get(5).unwrap().pending);
        ack_irq(&mut table, 5).unwrap();
        assert!(!table.get(5).unwrap().pending);

        // Acking an unbound IRQ is an error.
        assert_eq!(ack_irq(&mut table, 6), Err(IrqError::NotBound));
        arch::log("  ✓ ack clears pending; ack on unbound IRQ rejected\n");
    }

    #[inline(never)]
    fn out_of_range_irq_rejected() {
        let mut table = IrqTable::new();
        assert_eq!(
            set_notification(&mut table, 9999, 0, 0),
            Err(IrqError::Range)
        );
        assert_eq!(clear_handler(&mut table, 9999), Err(IrqError::Range));
        assert_eq!(ack_irq(&mut table, 9999), Err(IrqError::Range));
        arch::log("  ✓ out-of-range IRQ rejected\n");
    }

    #[inline(never)]
    fn source_ownership_survives_binding_clear() {
        let mut table = IrqTable::new();
        let route = IrqSource::IoApic {
            controller: 2,
            pin: 19,
        };
        reserve_source(&mut table, 7, route).unwrap();
        assert_eq!(
            reserve_source(&mut table, 8, route),
            Err(IrqError::AlreadyBound)
        );
        set_notification(&mut table, 7, 1, 0x40).unwrap();
        clear_handler(&mut table, 7).unwrap();
        assert_eq!(source(&table, 7), Ok(route));
        assert_eq!(release_handler(&mut table, 7), Ok(route));
        assert_eq!(source(&table, 7), Ok(IrqSource::None));
        arch::log("  ✓ IRQ source ownership survives Clear until final release\n");
    }
}
