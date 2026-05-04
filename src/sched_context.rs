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
// Phase 32e — kernel-side per-tick MCS handler.
//
// Called from the PIT ISR (and from specs that exercise the
// budgeting logic without a live PIT). Charges `delta_ticks` from
// the current thread's bound SchedContext; if the SC's budget is
// exhausted, blocks the thread (state = Inactive) so the
// scheduler picks something else next dispatch. Wake-up on the
// next refill's release_time lands in Phase 32f.
//
// Threads without a bound SC are unaffected — `current.sc` is
// `None` and we early-out.
// ---------------------------------------------------------------------------

pub fn mcs_tick(delta_ticks: Ticks) {
    unsafe {
        let s = crate::kernel::KERNEL.get();
        let now = current_time();

        // Phase 32f — first, wake any TCB whose SC's head refill
        // has matured. The scan is O(MAX_SCHED_CONTEXTS) per
        // tick; we keep the pool small (16 today).
        for sc_idx in 0..s.sched_contexts.len() {
            let sc = &s.sched_contexts[sc_idx];
            let bound = match sc.bound_tcb {
                Some(t) => t,
                None => continue,
            };
            // Only consider TCBs that we previously parked. Use
            // `try_get` — a stale `bound_tcb` (set before TCB
            // destruction by a non-cap-delete code path) would otherwise
            // panic the kernel here on every PIT tick.
            let state = match s.scheduler.slab.try_get(bound) {
                Some(t) => t.state,
                None => {
                    // Repair: clear the stale binding so we don't keep
                    // tripping over it.
                    s.sched_contexts[sc_idx].bound_tcb = None;
                    continue;
                }
            };
            if state != crate::tcb::ThreadStateType::Inactive {
                continue;
            }
            if refill_ready(sc, now) && sc.count > 0 {
                s.scheduler.make_runnable(bound);
            }
        }

        // Then charge the current thread's SC (if any). Phase 33c —
        // prefer `active_sc` (set during a call when the caller
        // donated their SC) so the callee burns the caller's
        // budget, not its own (or none).
        let cur = match s.scheduler.current() {
            Some(c) => c,
            None => return,
        };
        let cur_tcb = s.scheduler.slab.get(cur);
        let sc_idx = match cur_tcb.active_sc.or(cur_tcb.sc) {
            Some(i) => i as usize,
            None => return,
        };
        if sc_idx >= s.sched_contexts.len() {
            return;
        }
        let sc = &mut s.sched_contexts[sc_idx];
        let exhausted = refill_charge(sc, delta_ticks);
        if exhausted {
            // Schedule the next refill one period from now so the
            // thread can resume when it matures.
            let _ = refill_replenish(sc, now);
            s.scheduler.block(cur, crate::tcb::ThreadStateType::Inactive);
        }
    }
}

/// "Now" in the same ticks the SC schedule uses. Driven by the
/// PIT (`pit::TICK_COUNT`) on x86; specs override via
/// `set_test_time` in spec mode.
pub fn current_time() -> Ticks {
    #[cfg(feature = "spec")]
    {
        let t = TEST_TIME.load(core::sync::atomic::Ordering::Relaxed);
        if t != u64::MAX {
            return t;
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        return crate::arch::x86_64::pit::TICK_COUNT
            .load(core::sync::atomic::Ordering::Relaxed) as Ticks;
    }
    #[cfg(not(target_arch = "x86_64"))]
    { 0 }
}

#[cfg(feature = "spec")]
static TEST_TIME: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

/// Spec-only: pin `current_time()` to a known value.
#[cfg(feature = "spec")]
pub fn set_test_time(t: Option<Ticks>) {
    TEST_TIME.store(t.unwrap_or(u64::MAX), core::sync::atomic::Ordering::Relaxed);
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
        mcs_tick_blocks_on_exhaustion();
        mcs_tick_wakes_on_matured_refill();
        sc_donation_across_call_charges_callee_on_caller_sc();
        arch::log("MCS sched_context tests completed\n");
    }

    /// Phase 33c — `seL4_Call` donates the caller's bound SC to
    /// the callee for the duration of the call. While the call is
    /// in flight, `mcs_tick` charges the donated SC (caller's), not
    /// the callee's own. Reply restores the callee's `active_sc`
    /// to None.
    #[inline(never)]
    fn sc_donation_across_call_charges_callee_on_caller_sc() {
        unsafe {
            let s = crate::kernel::KERNEL.get();
            s.scheduler.reset_queues();
            s.scheduler.set_current(None);
            super::set_test_time(Some(0));

            // Caller has a 5-tick budget bound SC.
            let mut caller = crate::tcb::Tcb::default();
            caller.priority = 50;
            caller.state = crate::tcb::ThreadStateType::Running;
            let caller_id = s.scheduler.admit(caller);
            let sc_caller = s.alloc_sched_context().expect("sc pool");
            s.sched_contexts[sc_caller] =
                SchedContext::new(/* period */ 100, /* budget */ 5);
            s.sched_contexts[sc_caller].push(
                Refill { release_time: 0, amount: 5 }).unwrap();
            s.sched_contexts[sc_caller].bound_tcb = Some(caller_id);
            s.scheduler.slab.get_mut(caller_id).sc = Some(sc_caller as u16);

            // Server has no bound SC — without donation, mcs_tick
            // would early-out when the server is `current`.
            let mut server = crate::tcb::Tcb::default();
            server.priority = 50;
            server.state = crate::tcb::ThreadStateType::Running;
            let server_id = s.scheduler.admit(server);

            // Simulate post-Call state: caller blocked on Reply,
            // server is current and running on caller's SC. The
            // production path runs through `endpoint::send_ipc`
            // with `do_call`; here we set the same fields directly
            // so the spec doesn't have to construct an endpoint.
            s.scheduler.block(caller_id,
                crate::tcb::ThreadStateType::BlockedOnReply);
            s.scheduler.slab.get_mut(server_id).reply_to = Some(caller_id);
            s.scheduler.slab.get_mut(server_id).active_sc = Some(sc_caller as u16);
            s.scheduler.set_current(Some(server_id));

            // Tick — the server's `active_sc` (= caller's SC) is
            // charged, even though `server.sc` is None.
            crate::sched_context::mcs_tick(1);
            assert_eq!(s.sched_contexts[sc_caller].refills[0].amount, 4,
                "caller's SC should have been debited via the server");

            // Reply: clear donation. Production path is
            // `handle_reply`; spec mirrors the active_sc clear.
            s.scheduler.slab.get_mut(server_id).active_sc = None;
            s.scheduler.make_runnable(caller_id);

            // After reply, server has no SC of its own and no
            // donation; mcs_tick should early-out without charging.
            s.scheduler.set_current(Some(server_id));
            crate::sched_context::mcs_tick(1);
            assert_eq!(s.sched_contexts[sc_caller].refills[0].amount, 4,
                "caller's SC must NOT be charged once donation is cleared");

            // Cleanup.
            super::set_test_time(None);
            s.scheduler.set_current(None);
            s.scheduler.slab.free(caller_id);
            s.scheduler.slab.free(server_id);
            s.sched_contexts[sc_caller].bound_tcb = None;
            s.scheduler.reset_queues();
        }
        arch::log(
            "  ✓ Call donates caller's SC; mcs_tick charges callee on it; reply releases\n");
    }

    /// Phase 32f — exhausting the budget should both:
    ///   * push a new refill one period in the future, and
    ///   * eventually wake the thread when `current_time()`
    ///     reaches that refill's release_time.
    #[inline(never)]
    fn mcs_tick_wakes_on_matured_refill() {
        unsafe {
            let s = crate::kernel::KERNEL.get();
            s.scheduler.reset_queues();
            s.scheduler.set_current(None);

            // Pin "now" so we don't race the live PIT.
            super::set_test_time(Some(0));

            let mut t = crate::tcb::Tcb::default();
            t.priority = 50;
            t.state = crate::tcb::ThreadStateType::Running;
            let id = s.scheduler.admit(t);

            let sc_idx = s.alloc_sched_context().expect("sc pool");
            s.sched_contexts[sc_idx] = SchedContext::new(/* period */ 10, /* budget */ 1);
            s.sched_contexts[sc_idx].push(Refill { release_time: 0, amount: 1 }).unwrap();
            s.sched_contexts[sc_idx].bound_tcb = Some(id);
            s.scheduler.slab.get_mut(id).sc = Some(sc_idx as u16);

            s.scheduler.set_current(Some(id));

            // Tick → budget exhausts → thread parks. The exhaustion
            // path replenishes a new refill at now+period=10.
            super::mcs_tick(1);
            assert_eq!(s.scheduler.slab.get(id).state,
                crate::tcb::ThreadStateType::Inactive,
                "thread should be parked when SC exhausts");
            // The new refill should sit in the ring with release_time=10.
            assert!(s.sched_contexts[sc_idx].count >= 1,
                "replenish should have queued a fresh refill");
            let head = s.sched_contexts[sc_idx].head as usize;
            assert_eq!(s.sched_contexts[sc_idx].refills[head].release_time, 10);

            // Advance "now" past the refill's release_time. The next
            // mcs_tick should see the matured refill and wake the
            // parked thread.
            super::set_test_time(Some(10));
            // Make sure mcs_tick's "current" path doesn't confuse the
            // wake-up scan: clear current first.
            s.scheduler.set_current(None);
            super::mcs_tick(0);
            assert_eq!(s.scheduler.slab.get(id).state,
                crate::tcb::ThreadStateType::Running,
                "thread should be re-runnable after refill matures");

            // Cleanup.
            super::set_test_time(None);
            s.scheduler.set_current(None);
            s.scheduler.slab.free(id);
            s.sched_contexts[sc_idx].bound_tcb = None;
            s.scheduler.reset_queues();
        }
        arch::log("  ✓ mcs_tick wakes parked thread when next refill matures\n");
    }

    /// Phase 32e — driving `mcs_tick` against a live current TCB
    /// + bound SC. Two ticks against a 2-tick budget should leave
    /// the thread `Inactive` (blocked on its empty SC).
    #[inline(never)]
    fn mcs_tick_blocks_on_exhaustion() {
        unsafe {
            let s = crate::kernel::KERNEL.get();
            // Reset scheduler queues / current so prior specs
            // don't bleed in (lessons.md "scheduler-queue
            // staleness across spec teardowns").
            s.scheduler.reset_queues();
            s.scheduler.set_current(None);

            // Plant a thread + an SC and bind them.
            let mut t = crate::tcb::Tcb::default();
            t.priority = 50;
            t.state = crate::tcb::ThreadStateType::Running;
            let id = s.scheduler.admit(t);
            // Allocate a SC slot, give it a 2-tick budget with one
            // ready refill.
            let sc_idx = s.alloc_sched_context().expect("sc pool");
            s.sched_contexts[sc_idx] = SchedContext::new(/* period */ 100, /* budget */ 2);
            s.sched_contexts[sc_idx].push(Refill { release_time: 0, amount: 2 }).unwrap();
            s.sched_contexts[sc_idx].bound_tcb = Some(id);
            s.scheduler.slab.get_mut(id).sc = Some(sc_idx as u16);

            // Make this thread `current` so `mcs_tick` charges
            // against it.
            s.scheduler.set_current(Some(id));

            // Tick once — budget 2 → 1, still running.
            crate::sched_context::mcs_tick(1);
            assert_eq!(s.scheduler.slab.get(id).state,
                crate::tcb::ThreadStateType::Running);
            assert_eq!(s.sched_contexts[sc_idx].refills[0].amount, 1);

            // Tick again — budget 1 → 0, exhausted, thread parks.
            crate::sched_context::mcs_tick(1);
            assert_eq!(s.scheduler.slab.get(id).state,
                crate::tcb::ThreadStateType::Inactive,
                "thread should be parked when SC exhausts");

            // Cleanup: free the slot so subsequent specs aren't
            // poisoned. The SC pool entry stays consumed (no
            // reclaim yet — see todo's "Pool reclaim" follow-up).
            s.scheduler.set_current(None);
            s.scheduler.slab.free(id);
            s.sched_contexts[sc_idx].bound_tcb = None;
        }
        arch::log("  ✓ mcs_tick blocks the current TCB on SC exhaustion\n");
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
