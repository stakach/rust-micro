//! MCS (Mixed-Criticality Systems) scheduling context.
//!
//! Mirrors `seL4/src/object/schedcontext.c` + `seL4/src/kernel/sporadic.c`
//! at the algorithmic level. Real-time scheduling in MCS-mode seL4
//! moves "how much CPU time can this thread consume" out of the TCB
//! and into a separate `SchedContext` object that thread caps can be
//! bound to. The scheduling discipline is *sporadic* — the
//! SchedContext holds a list of `Refill` records `(release_time,
//! amount)` that say "starting at time T, this many ticks of CPU are
//! available". As time advances, refills mature; as the bound thread
//! runs, the head refill is debited.
//!
//! The full MCS scheduler has more moving parts (CBS, head/tail
//! split, slack-time donation). This commit lands the pure
//! algorithmic core (refill bookkeeping, charge/replenish) so it's
//! testable today; the scheduler hookup happens when the spec
//! runner has a cargo-feature switch.
//!
//! Phase 32a — always compiled. MCS is the only scheduler model
//! (`CONFIG_KERNEL_MCS = true` in the codegen, no runtime feature
//! gate). The `mcs` cargo feature is retained as a no-op so
//! existing build invocations don't break.

use crate::tcb::TcbId;
use crate::types::seL4_Word as Word;

/// Time in kernel ticks. seL4 calls this `ticks_t`. We pick u64
/// because the kernel never wants to think about wraparound.
pub type Ticks = u64;

/// Single replenishment record. seL4's `refill_t`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Refill {
    /// Time at which the budget becomes spendable.
    pub release_time: Ticks,
    /// Number of ticks the SchedContext gains at `release_time`.
    pub amount: Ticks,
}

/// Maximum refills per SchedContext. seL4 sizes this from
/// `seL4_MaxExtraRefills(size_bits)`; we pick 8 here so the struct
/// fits comfortably on the stack during specs. Production kernels
/// allocate refills based on the SchedContext's size_bits.
pub const MAX_REFILLS: usize = 8;

#[derive(Copy, Clone, Debug)]
pub struct SchedContext {
    /// Period (T) of the sporadic server.
    pub period: Ticks,
    /// Maximum budget per period (the user-supplied "C" parameter).
    pub budget: Ticks,
    /// Refill ring — head at index `head`, `count` valid entries.
    pub refills: [Refill; MAX_REFILLS],
    pub head: u8,
    pub count: u8,
    /// Bound TCB. `None` while unbound. seL4 stores this as the
    /// `scTcb` cap pointer; we use a TcbId.
    pub bound_tcb: Option<TcbId>,
}

impl Default for SchedContext {
    fn default() -> Self { Self::new(0, 0) }
}

impl SchedContext {
    pub const fn new(period: Ticks, budget: Ticks) -> Self {
        Self {
            period,
            budget,
            refills: [Refill { release_time: 0, amount: 0 }; MAX_REFILLS],
            head: 0,
            count: 0,
            bound_tcb: None,
        }
    }

    pub const fn is_empty(&self) -> bool { self.count == 0 }

    pub fn head_refill(&self) -> Option<Refill> {
        if self.count == 0 { None } else { Some(self.refills[self.head as usize]) }
    }

    /// Remaining ticks of CPU time at the head refill — the value
    /// `refill_budget_check` consults to decide preemption.
    pub fn head_amount(&self) -> Ticks {
        self.head_refill().map(|r| r.amount).unwrap_or(0)
    }

    /// Sum of all refill amounts. Useful for spec sanity checks.
    pub fn total_amount(&self) -> Ticks {
        let mut total = 0;
        let mut i = self.head as usize;
        for _ in 0..self.count {
            total += self.refills[i].amount;
            i = (i + 1) % MAX_REFILLS;
        }
        total
    }

    /// Earliest time at which the head refill becomes spendable.
    pub fn head_ready_time(&self) -> Option<Ticks> {
        self.head_refill().map(|r| r.release_time)
    }

    /// Push a new refill at the tail.
    pub fn push(&mut self, refill: Refill) -> Result<(), RefillError> {
        if self.count as usize == MAX_REFILLS {
            return Err(RefillError::Full);
        }
        let tail = (self.head as usize + self.count as usize) % MAX_REFILLS;
        self.refills[tail] = refill;
        self.count += 1;
        Ok(())
    }

    fn pop_head(&mut self) -> Option<Refill> {
        if self.count == 0 {
            return None;
        }
        let r = self.refills[self.head as usize];
        self.head = ((self.head as usize + 1) % MAX_REFILLS) as u8;
        self.count -= 1;
        Ok::<(), ()>(()).ok();
        Some(r)
    }

    fn modify_head<F: FnOnce(&mut Refill)>(&mut self, f: F) {
        if self.count > 0 {
            f(&mut self.refills[self.head as usize])
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RefillError {
    /// Out of refill slots. seL4 returns `seL4_NotEnoughMemory`.
    Full,
}

/// Charge `delta` ticks against the head refill. Mirrors
/// `refill_charge` in seL4. Returns whether the budget is exhausted
/// (caller should preempt or schedule a wake-up at the next refill).
pub fn refill_charge(sc: &mut SchedContext, delta: Ticks) -> bool {
    if sc.count == 0 {
        return true;
    }
    let head_amount = sc.refills[sc.head as usize].amount;
    if delta >= head_amount {
        // Head exhausted — drop it. Any extra should normally have
        // been split; for the spec-sized MAX_REFILLS we let the
        // caller handle that.
        sc.pop_head();
        true
    } else {
        sc.modify_head(|r| r.amount -= delta);
        false
    }
}

/// Add a fresh refill `period` ticks from now. Mirrors
/// `refill_add_tail` in seL4. Returns RefillError::Full if the ring
/// is full — caller is expected to coalesce older refills.
pub fn refill_replenish(sc: &mut SchedContext, now: Ticks) -> Result<(), RefillError> {
    sc.push(Refill {
        release_time: now + sc.period,
        amount: sc.budget,
    })
}

/// Bring the head refill to "ready" if `now` has passed its release
/// time. Mirrors `refill_ready` in seL4. Returns the slack (the
/// amount by which we missed the release).
pub fn refill_ready(sc: &SchedContext, now: Ticks) -> bool {
    sc.head_ready_time().map(|t| t <= now).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_sched_context() {
        arch::log("Running MCS sched_context tests...\n");
        push_pop_round_trip();
        charge_consumes_head_amount();
        charge_drops_exhausted_head();
        replenish_schedules_for_next_period();
        refill_ready_threshold();
        ring_full_returns_error();
        arch::log("MCS sched_context tests completed\n");
    }

    #[inline(never)]
    fn push_pop_round_trip() {
        let mut sc = SchedContext::new(/* period */ 100, /* budget */ 30);
        sc.push(Refill { release_time: 0, amount: 30 }).unwrap();
        sc.push(Refill { release_time: 100, amount: 30 }).unwrap();
        assert_eq!(sc.count, 2);
        assert_eq!(sc.head_amount(), 30);
        assert_eq!(sc.head_ready_time(), Some(0));
        assert_eq!(sc.total_amount(), 60);
        // Pop drops the head.
        let popped = sc.pop_head().unwrap();
        assert_eq!(popped.release_time, 0);
        assert_eq!(sc.count, 1);
        assert_eq!(sc.head_ready_time(), Some(100));
        arch::log("  ✓ push / pop_head / head_amount agree\n");
    }

    #[inline(never)]
    fn charge_consumes_head_amount() {
        let mut sc = SchedContext::new(100, 30);
        sc.push(Refill { release_time: 0, amount: 30 }).unwrap();
        let exhausted = refill_charge(&mut sc, 10);
        assert!(!exhausted);
        assert_eq!(sc.head_amount(), 20);
        arch::log("  ✓ refill_charge debits the head refill\n");
    }

    #[inline(never)]
    fn charge_drops_exhausted_head() {
        let mut sc = SchedContext::new(100, 30);
        sc.push(Refill { release_time: 0, amount: 30 }).unwrap();
        sc.push(Refill { release_time: 100, amount: 30 }).unwrap();
        let exhausted = refill_charge(&mut sc, 30);
        assert!(exhausted);
        assert_eq!(sc.count, 1);
        // Next head is the second refill.
        assert_eq!(sc.head_ready_time(), Some(100));
        arch::log("  ✓ refill_charge drops the head when budget runs out\n");
    }

    #[inline(never)]
    fn replenish_schedules_for_next_period() {
        let mut sc = SchedContext::new(100, 30);
        // Replenish at t=50 → next refill ready at t=150.
        refill_replenish(&mut sc, 50).unwrap();
        assert_eq!(sc.count, 1);
        let r = sc.head_refill().unwrap();
        assert_eq!(r.release_time, 150);
        assert_eq!(r.amount, 30);
        arch::log("  ✓ refill_replenish schedules budget at now + period\n");
    }

    #[inline(never)]
    fn refill_ready_threshold() {
        let mut sc = SchedContext::new(100, 30);
        sc.push(Refill { release_time: 200, amount: 30 }).unwrap();
        assert!(!refill_ready(&sc, 100));
        assert!(!refill_ready(&sc, 199));
        assert!(refill_ready(&sc, 200));
        assert!(refill_ready(&sc, 300));
        arch::log("  ✓ refill_ready honours release_time\n");
    }

    #[inline(never)]
    fn ring_full_returns_error() {
        let mut sc = SchedContext::new(10, 1);
        for i in 0..MAX_REFILLS {
            sc.push(Refill { release_time: i as Ticks, amount: 1 }).unwrap();
        }
        assert_eq!(
            sc.push(Refill { release_time: 99, amount: 1 }),
            Err(RefillError::Full),
        );
        arch::log("  ✓ ring overflow surfaces as RefillError::Full\n");
    }
}
