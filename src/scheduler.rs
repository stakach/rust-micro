//! Priority scheduler.
//!
//! Mirrors `seL4/src/kernel/thread.c` (the parts of `chooseThread` /
//! `scheduleChooseNewThread` that live outside the MCS feature flag).
//! Single domain only, single CPU only — adding domains and SMP are
//! deferred to later phases.
//!
//! Data structures:
//!   - A 256-bit priority bitmap tells us in O(1) which priorities
//!     have any runnable threads enqueued.
//!   - Per-priority queues are intrusive doubly-linked lists, with
//!     the next/prev links living inside `Tcb`. The list is keyed
//!     by `TcbId` (an index into the `TcbSlab`) so we never need
//!     raw pointers — every traversal is plain field access.
//!
//! The scheduler does NOT perform the actual register save/restore
//! today; that's the arch-side context switch that lands with the
//! syscall path in Phase 5. `choose_thread` returns a `TcbId` and
//! the caller is expected to switch to it.

use crate::tcb::{Tcb, TcbId, TcbSlab, ThreadStateType, MAX_PRIORITY, NUM_PRIORITIES};

// ---------------------------------------------------------------------------
// Priority bitmap. 256 priorities packed into four u64s, indexed
// from priority 0 = bit 0 of word 0 up to priority 255 = bit 63 of
// word 3. Highest-set-bit lookup uses `leading_zeros` on the most-
// significant non-zero word.
// ---------------------------------------------------------------------------

const BITMAP_WORDS: usize = NUM_PRIORITIES / 64;

#[derive(Copy, Clone, Debug, Default)]
pub struct PrioBitmap {
    words: [u64; BITMAP_WORDS],
}

impl PrioBitmap {
    pub const fn new() -> Self { Self { words: [0; BITMAP_WORDS] } }
    pub const fn is_empty(&self) -> bool {
        let mut i = 0;
        while i < BITMAP_WORDS {
            if self.words[i] != 0 { return false; }
            i += 1;
        }
        true
    }
    pub fn set(&mut self, prio: u8) {
        let p = prio as usize;
        self.words[p / 64] |= 1u64 << (p % 64);
    }
    pub fn clear(&mut self, prio: u8) {
        let p = prio as usize;
        self.words[p / 64] &= !(1u64 << (p % 64));
    }
    pub fn highest(&self) -> Option<u8> {
        // Walk from the high word down so we find the topmost set bit.
        for i in (0..BITMAP_WORDS).rev() {
            let w = self.words[i];
            if w != 0 {
                // 63 - leading_zeros gives the index of the MSB.
                let bit = 63 - w.leading_zeros() as usize;
                return Some((i * 64 + bit) as u8);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Per-priority queue heads/tails. The actual sched_next / sched_prev
// links live in each `Tcb` so a thread occupies its queue node
// in-place — no separate allocations.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct ReadyQueues {
    bitmap: PrioBitmap,
    heads: [Option<TcbId>; NUM_PRIORITIES],
    tails: [Option<TcbId>; NUM_PRIORITIES],
}

impl Default for ReadyQueues {
    fn default() -> Self { Self::new() }
}

impl ReadyQueues {
    pub const fn new() -> Self {
        Self {
            bitmap: PrioBitmap::new(),
            heads: [None; NUM_PRIORITIES],
            tails: [None; NUM_PRIORITIES],
        }
    }

    /// Append `tcb` to the tail of its priority's queue.
    pub fn enqueue(&mut self, slab: &mut TcbSlab, tcb: TcbId) {
        let prio = slab.get(tcb).priority;
        debug_assert!(prio <= MAX_PRIORITY);
        let p = prio as usize;
        let prev_tail = self.tails[p];
        // Update the new TCB's links.
        {
            let t = slab.get_mut(tcb);
            t.sched_prev = prev_tail;
            t.sched_next = None;
        }
        // Splice into the queue.
        match prev_tail {
            Some(prev) => slab.get_mut(prev).sched_next = Some(tcb),
            None => self.heads[p] = Some(tcb),
        }
        self.tails[p] = Some(tcb);
        self.bitmap.set(prio);
    }

    /// Remove `tcb` from its priority's queue. The thread must
    /// currently be enqueued at that priority — debug_assert fires
    /// otherwise.
    pub fn dequeue(&mut self, slab: &mut TcbSlab, tcb: TcbId) {
        let prio = slab.get(tcb).priority;
        let p = prio as usize;
        let (prev, next) = {
            let t = slab.get(tcb);
            (t.sched_prev, t.sched_next)
        };
        match prev {
            Some(prev) => slab.get_mut(prev).sched_next = next,
            None => self.heads[p] = next,
        }
        match next {
            Some(next) => slab.get_mut(next).sched_prev = prev,
            None => self.tails[p] = prev,
        }
        // Clear the dequeued thread's own links so re-enqueue is
        // safe and visiting old links surfaces obviously.
        let t = slab.get_mut(tcb);
        t.sched_prev = None;
        t.sched_next = None;

        // If that was the last thread at this priority, drop the
        // bitmap bit.
        if self.heads[p].is_none() {
            self.bitmap.clear(prio);
        }
    }

    /// Pop the head of the highest-priority non-empty queue.
    /// Returns `None` if every queue is empty.
    pub fn pop_highest(&mut self, slab: &mut TcbSlab) -> Option<TcbId> {
        let prio = self.bitmap.highest()?;
        let head = self.heads[prio as usize].expect("bitmap claims non-empty");
        self.dequeue(slab, head);
        Some(head)
    }

    /// Peek at the highest-priority queued thread without removing
    /// it. Used by `should_preempt` to decide whether the current
    /// thread can keep running.
    pub fn peek_highest(&self) -> Option<u8> {
        self.bitmap.highest()
    }

    /// Test helper: count how many threads sit in `prio`'s queue.
    /// Linear in queue length — only used by specs.
    #[cfg(feature = "spec")]
    pub fn len_at(&self, slab: &TcbSlab, prio: u8) -> usize {
        let mut n = 0;
        let mut cur = self.heads[prio as usize];
        while let Some(id) = cur {
            n += 1;
            cur = slab.get(id).sched_next;
        }
        n
    }
}

// ---------------------------------------------------------------------------
// Per-CPU scheduling state. Mirrors seL4's `nodeState` per-CPU struct.
// Each CPU owns its own ready queues + current/idle pointers; the slab
// is shared since TCBs aren't pinned to a CPU at allocation time
// (affinity decides which queue they land in via `admit`).
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default)]
pub struct SchedulerNode {
    pub queues: ReadyQueues,
    pub current: Option<TcbId>,
    pub idle: Option<TcbId>,
}

// ---------------------------------------------------------------------------
// Scheduler facade. Bundles the (shared) TCB slab and the per-CPU
// scheduling nodes.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct Scheduler {
    pub slab: TcbSlab,
    pub nodes: [SchedulerNode; crate::smp::MAX_CPUS],
}

impl Default for Scheduler {
    fn default() -> Self { Self::new() }
}

impl Scheduler {
    pub const fn new() -> Self {
        const NODE: SchedulerNode = SchedulerNode {
            queues: ReadyQueues::new(),
            current: None,
            idle: None,
        };
        Self {
            slab: TcbSlab::new(),
            nodes: [NODE; crate::smp::MAX_CPUS],
        }
    }

    // -- per-CPU accessors ---------------------------------------------------

    /// Read this CPU's `current` thread. Convenience for the common
    /// case where callers run on the BKL holder.
    #[inline]
    pub fn current(&self) -> Option<TcbId> {
        self.nodes[crate::arch::get_cpu_id() as usize].current
    }

    /// Set this CPU's `current` thread.
    #[inline]
    pub fn set_current(&mut self, val: Option<TcbId>) {
        self.nodes[crate::arch::get_cpu_id() as usize].current = val;
    }

    /// Read another CPU's `current` thread (used by IPI handlers
    /// once Phase 28d lands).
    #[inline]
    pub fn current_for_cpu(&self, cpu: u32) -> Option<TcbId> {
        self.nodes[cpu as usize].current
    }

    #[inline]
    pub fn set_current_for_cpu(&mut self, cpu: u32, val: Option<TcbId>) {
        self.nodes[cpu as usize].current = val;
    }

    /// Borrow this CPU's ready queues (read-only).
    #[inline]
    pub fn queues(&self) -> &ReadyQueues {
        &self.nodes[crate::arch::get_cpu_id() as usize].queues
    }

    /// Borrow this CPU's ready queues mutably.
    #[inline]
    pub fn queues_mut(&mut self) -> &mut ReadyQueues {
        &mut self.nodes[crate::arch::get_cpu_id() as usize].queues
    }

    /// Reset every CPU's queues — used by spec teardowns to scrub
    /// state between tests since we don't yet have a TCB destructor
    /// that dequeues on free.
    pub fn reset_queues(&mut self) {
        for node in self.nodes.iter_mut() {
            node.queues = ReadyQueues::new();
        }
    }

    /// Read this CPU's idle thread.
    #[inline]
    pub fn idle(&self) -> Option<TcbId> {
        self.nodes[crate::arch::get_cpu_id() as usize].idle
    }

    /// Set this CPU's idle thread.
    #[inline]
    pub fn set_idle(&mut self, val: Option<TcbId>) {
        self.nodes[crate::arch::get_cpu_id() as usize].idle = val;
    }

    // -- thread admission / lifecycle ----------------------------------------

    /// Allocate a TCB and (if it's runnable) enqueue it on its
    /// affinity CPU's queue.
    pub fn admit(&mut self, tcb: Tcb) -> TcbId {
        let runnable = tcb.is_runnable();
        let cpu = tcb.affinity as usize;
        let id = self.slab.alloc(tcb).expect("TcbSlab full");
        if runnable {
            self.nodes[cpu].queues.enqueue(&mut self.slab, id);
        }
        id
    }

    /// Mark a thread as runnable and (re-)add it to its affinity
    /// CPU's queue.
    pub fn make_runnable(&mut self, id: TcbId) {
        let was_runnable = self.slab.get(id).is_runnable();
        let cpu = self.slab.get(id).affinity as usize;
        self.slab.get_mut(id).state = ThreadStateType::Running;
        if !was_runnable {
            self.nodes[cpu].queues.enqueue(&mut self.slab, id);
        }
    }

    /// Block a thread. Removes from its affinity CPU's queue (if
    /// runnable), updates state, and surrenders the CPU if it was
    /// current on any node.
    pub fn block(&mut self, id: TcbId, new_state: ThreadStateType) {
        debug_assert!(!new_state.is_runnable());
        let was_runnable = self.slab.get(id).is_runnable();
        let cpu = self.slab.get(id).affinity as usize;
        if was_runnable {
            self.nodes[cpu].queues.dequeue(&mut self.slab, id);
        }
        self.slab.get_mut(id).state = new_state;
        // If the blocked thread was current on any CPU, clear it
        // there. Today only the affinity CPU could have it as
        // current, but loop over all to be safe against migrations.
        for node in self.nodes.iter_mut() {
            if node.current == Some(id) {
                node.current = None;
            }
        }
    }

    /// Pick the thread that should run next on the calling CPU.
    /// Mirrors seL4's `scheduleChooseNewThread` for the single-domain
    /// non-MCS case but per-CPU.
    pub fn choose_thread(&mut self) -> Option<TcbId> {
        let cpu = crate::arch::get_cpu_id() as usize;
        if let Some(id) = self.nodes[cpu].queues.pop_highest(&mut self.slab) {
            // Re-enqueue at the tail so equal-priority threads
            // round-robin.
            self.nodes[cpu].queues.enqueue(&mut self.slab, id);
            Some(id)
        } else {
            self.nodes[cpu].idle
        }
    }

    /// Decide whether the current thread on this CPU should yield.
    pub fn should_preempt(&self) -> Option<u8> {
        let cpu = crate::arch::get_cpu_id() as usize;
        let node = &self.nodes[cpu];
        match (node.current, node.queues.peek_highest()) {
            (Some(cur), Some(top)) => {
                let cur_prio = self.slab.get(cur).priority;
                if top > cur_prio { Some(top) } else { None }
            }
            (None, Some(top)) => Some(top),
            _ => None,
        }
    }

    /// One scheduler tick on the calling CPU. Decrement the current
    /// thread's timeslice; return `true` if it ran out.
    pub fn tick(&mut self) -> bool {
        let cur = match self.current() {
            Some(c) => c,
            None => return false,
        };
        let t = self.slab.get_mut(cur);
        if t.time_slice == 0 {
            return true;
        }
        t.time_slice -= 1;
        t.time_slice == 0
    }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_scheduler() {
        arch::log("Running scheduler tests...\n");
        bitmap_basics();
        chooses_highest_priority();
        round_robin_within_priority();
        block_then_unblock();
        empty_falls_back_to_idle();
        preempt_only_strictly_higher();
        tick_decrements_timeslice();
        tick_with_no_current_is_noop();
        per_cpu_queues_are_isolated();
        arch::log("Scheduler tests completed\n");
    }

    /// Phase 28c — admitting threads with different `affinity` values
    /// places them on the matching CPU's queue; each CPU's queue is
    /// independent. Verifies the per-CPU `nodes` array isn't a
    /// thinly-disguised single shared queue.
    #[inline(never)]
    fn per_cpu_queues_are_isolated() {
        let mut s = Scheduler::new();
        let mut a = runnable(60);
        a.affinity = 0;
        let mut b = runnable(60);
        b.affinity = 1;
        let mut c = runnable(60);
        c.affinity = 1;
        let _ = s.admit(a);
        let _ = s.admit(b);
        let _ = s.admit(c);
        // CPU 0's queue holds 1 thread at prio 60.
        assert_eq!(s.nodes[0].queues.len_at(&s.slab, 60), 1);
        // CPU 1's queue holds 2 threads at prio 60.
        assert_eq!(s.nodes[1].queues.len_at(&s.slab, 60), 2);
        // Setting current per-CPU is independent.
        s.set_current_for_cpu(0, Some(crate::tcb::TcbId(0)));
        s.set_current_for_cpu(1, Some(crate::tcb::TcbId(1)));
        assert_eq!(s.current_for_cpu(0), Some(crate::tcb::TcbId(0)));
        assert_eq!(s.current_for_cpu(1), Some(crate::tcb::TcbId(1)));
        arch::log("  ✓ per-CPU queues + current are independent\n");
    }

    fn runnable(prio: u8) -> Tcb {
        let mut t = Tcb::default();
        t.priority = prio;
        t.state = ThreadStateType::Running;
        t
    }

    #[inline(never)]
    fn bitmap_basics() {
        let mut bm = PrioBitmap::new();
        assert!(bm.is_empty());
        assert_eq!(bm.highest(), None);
        bm.set(0);
        bm.set(127);
        bm.set(255);
        assert_eq!(bm.highest(), Some(255));
        bm.clear(255);
        assert_eq!(bm.highest(), Some(127));
        bm.clear(127);
        assert_eq!(bm.highest(), Some(0));
        bm.clear(0);
        assert!(bm.is_empty());
        arch::log("  ✓ priority bitmap highest/set/clear\n");
    }

    #[inline(never)]
    fn chooses_highest_priority() {
        let mut s = Scheduler::new();
        let _low = s.admit(runnable(10));
        let high = s.admit(runnable(200));
        let _mid = s.admit(runnable(100));
        let chosen = s.choose_thread().expect("should pick a thread");
        assert_eq!(chosen, high);
        arch::log("  ✓ choose_thread picks the highest-priority runnable\n");
    }

    #[inline(never)]
    fn round_robin_within_priority() {
        // Three threads at the same priority — choose_thread cycles
        // through them in admission order, then back to the first.
        let mut s = Scheduler::new();
        let a = s.admit(runnable(50));
        let b = s.admit(runnable(50));
        let c = s.admit(runnable(50));
        assert_eq!(s.queues().len_at(&s.slab, 50), 3);
        assert_eq!(s.choose_thread(), Some(a));
        assert_eq!(s.choose_thread(), Some(b));
        assert_eq!(s.choose_thread(), Some(c));
        assert_eq!(s.choose_thread(), Some(a));
        arch::log("  ✓ round-robin within a priority class\n");
    }

    #[inline(never)]
    fn block_then_unblock() {
        let mut s = Scheduler::new();
        let a = s.admit(runnable(50));
        let b = s.admit(runnable(50));
        s.set_current(Some(a));

        // Block `a` waiting on a notification.
        s.block(a, ThreadStateType::BlockedOnNotification);
        // Queue at priority 50 now has just `b`.
        assert_eq!(s.queues().len_at(&s.slab, 50), 1);
        assert_eq!(s.current(), None);
        // choose_thread picks `b`.
        assert_eq!(s.choose_thread(), Some(b));

        // Unblock `a` — it goes back into the queue at the tail.
        s.make_runnable(a);
        assert_eq!(s.queues().len_at(&s.slab, 50), 2);
        arch::log("  ✓ block / make_runnable updates queue and current\n");
    }

    #[inline(never)]
    fn empty_falls_back_to_idle() {
        let mut s = Scheduler::new();
        // Idle thread (priority 0, runnable but never enqueued by us).
        let idle_tcb = Tcb {
            state: ThreadStateType::Idle,
            ..Default::default()
        };
        let idle = s.slab.alloc(idle_tcb).unwrap();
        s.set_idle(Some(idle));
        assert_eq!(s.choose_thread(), Some(idle));
        arch::log("  ✓ empty queues fall through to the idle thread\n");
    }

    #[inline(never)]
    fn tick_decrements_timeslice() {
        let mut s = Scheduler::new();
        let mut t = runnable(50);
        t.time_slice = 3;
        let id = s.admit(t);
        s.set_current(Some(id));
        // Three ticks bring it to zero; the third returns true.
        assert_eq!(s.tick(), false);
        assert_eq!(s.slab.get(id).time_slice, 2);
        assert_eq!(s.tick(), false);
        assert_eq!(s.slab.get(id).time_slice, 1);
        assert_eq!(s.tick(), true);
        assert_eq!(s.slab.get(id).time_slice, 0);
        // Subsequent ticks stay true (already exhausted).
        assert_eq!(s.tick(), true);
        arch::log("  ✓ tick decrements timeslice; signals exhaustion\n");
    }

    #[inline(never)]
    fn tick_with_no_current_is_noop() {
        let mut s = Scheduler::new();
        // No `current` set.
        assert_eq!(s.tick(), false);
        arch::log("  ✓ tick with no current is a no-op\n");
    }

    #[inline(never)]
    fn preempt_only_strictly_higher() {
        let mut s = Scheduler::new();
        let a = s.admit(runnable(100));
        let _b = s.admit(runnable(50));
        s.set_current(Some(a));

        // Same-priority sibling does NOT preempt.
        assert_eq!(s.should_preempt(), None);

        // Higher-priority arrival DOES preempt.
        let _hi = s.admit(runnable(200));
        assert_eq!(s.should_preempt(), Some(200));
        arch::log("  ✓ should_preempt fires only on a strictly-higher priority\n");
    }
}
