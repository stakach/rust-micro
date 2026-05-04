//! Phase 14a — static kernel state singleton.
//!
//! Up to here the spec runner has been building `Scheduler` values
//! on the stack per test. To run actual threads we need persistent
//! per-CPU state: the current TCB pointer, the ready queues, and
//! (eventually) the IRQ table + endpoint pool.
//!
//! Concurrency model: uniprocessor, no in-kernel preemption point.
//! Once a CPU enters the kernel via SYSCALL or an exception, it
//! runs to completion (or an explicit yield) before the next entry.
//! That makes a plain `UnsafeCell` behind a `Sync` newtype the
//! correct primitive — no mutexes, no atomics, no allocator. SMP
//! later replaces this with `[KernelState; NUM_CPUS]` keyed by
//! GS_BASE.

use core::cell::UnsafeCell;

use crate::cap::{Cap, CNodeStorage, EndpointObj, NotificationObj, PPtr};
use crate::cspace::CSpace;
use crate::cte::Cte;
use crate::endpoint::Endpoint;
use crate::interrupt::IrqTable;
use crate::notification::Notification;
use crate::scheduler::Scheduler;
use crate::tcb::{Tcb, TcbId, ThreadStateType};

/// Maximum endpoints in the in-kernel pool. Production seL4
/// allocates them via Untyped retype with no fixed cap; the slab
/// is just a convenience until we wire that path.
pub const MAX_ENDPOINTS: usize = 256;

/// Maximum notifications in the in-kernel pool.
pub const MAX_NTFNS: usize = 128;

/// Maximum SchedContexts in the in-kernel pool (Phase 32c).
pub const MAX_SCHED_CONTEXTS: usize = 128;

/// Maximum Reply objects in the in-kernel pool (Phase 34e).
pub const MAX_REPLIES: usize = 128;

/// CTEs per pre-allocated CNode in the in-kernel pool.
///
/// Phase 36e bumped from 5 → 6 (32 → 64 slots) for the canonical
/// initial-cap layout. Phase 42 bumped further to 12 (4096 slots)
/// because sel4test's allocman walks `bi.empty` to allocate
/// hundreds of caps for tests; 64 slots ran out almost immediately.
/// Each Cte is 32 bytes → ~128 KiB per CNode × MAX_CNODES = ~512
/// KiB of static memory, comfortably within the kernel's BSS.
pub const CNODE_RADIX: u8 = 12;
pub const CNODE_SLOTS: usize = 1 << CNODE_RADIX;

/// Maximum pre-allocated CNodes. Bumped 4→8→16→32 across phases so
/// sel4test's per-test process spawns (each retyped Untyped→CNode for
/// its own CSpace) don't exhaust the pool when running multiple tests
/// back-to-back. 32 CNodes × 4096 slots × 32 bytes = 4 MiB of static
/// BSS — link.ld's kernel half has room.
pub const MAX_CNODES: usize = 32;

/// One pre-allocated CNode: 32 slots × 32 bytes = 1 KiB.
#[repr(C, align(32))]
pub struct CNodePage(pub [Cte; CNODE_SLOTS]);

impl Default for CNodePage {
    fn default() -> Self { Self([Cte::null(); CNODE_SLOTS]) }
}

pub struct KernelState {
    pub scheduler: Scheduler,
    /// In-kernel endpoint pool. Entry `i` is reachable through a
    /// `Cap::Endpoint { ptr, .. }` whose `ptr.addr() == i + 1`.
    /// (We use 1-based indexing so PPtr's NonZeroU64 invariant
    /// holds.)
    pub endpoints: [Endpoint; MAX_ENDPOINTS],
    /// Same convention for notifications.
    pub notifications: [Notification; MAX_NTFNS],
    /// Phase 32c — in-kernel SchedContext pool. `Cap::SchedContext`
    /// PPtrs encode `pool_index + 1`, same convention as endpoints.
    pub sched_contexts: [crate::sched_context::SchedContext;
                         MAX_SCHED_CONTEXTS],
    /// Phase 34e — in-kernel Reply object pool. Same +1 PPtr
    /// convention. `Untyped::Retype(Reply)` allocates a slot and
    /// emits a `Cap::Reply { ptr, can_grant: true }` referencing
    /// it.
    pub replies: [crate::reply::Reply; MAX_REPLIES],
    /// Pre-allocated CNode pool. Same 1-based indexing convention
    /// for `Cap::CNode { ptr, .. }`.
    pub cnodes: [CNodePage; MAX_CNODES],
    /// Per-IRQ binding table.
    pub irqs: IrqTable,

    /// Phase 29h — bump-allocator state for the in-kernel
    /// endpoint / notification / cnode pools. `Untyped::Retype` for
    /// these object types takes the next free slot and bumps the
    /// counter; the Untyped's own physical bytes stay reserved but
    /// the actual kernel object lives here. (Real seL4 stores the
    /// object in the Untyped's memory; we keep separate pools for
    /// allocation simplicity.)
    pub next_endpoint: usize,
    pub next_notification: usize,
    pub next_cnode: usize,
    pub next_sched_context: usize,
    pub next_reply: usize,
}

/// Phase 43 — pool-recycling bitmap. Bit set means slot is in use.
/// Separate static so we can mutate without borrowing all of
/// `KernelState`. BKL serialises access.
struct PoolBitmaps {
    pub endpoints: [u64; (MAX_ENDPOINTS + 63) / 64],
    pub notifications: [u64; (MAX_NTFNS + 63) / 64],
    pub cnodes: [u64; (MAX_CNODES + 63) / 64],
    pub replies: [u64; (MAX_REPLIES + 63) / 64],
}

static mut POOL_BITMAPS: PoolBitmaps = PoolBitmaps {
    endpoints: [0; (MAX_ENDPOINTS + 63) / 64],
    notifications: [0; (MAX_NTFNS + 63) / 64],
    cnodes: [0; (MAX_CNODES + 63) / 64],
    replies: [0; (MAX_REPLIES + 63) / 64],
};

impl KernelState {
    pub const fn new() -> Self {
        const EMPTY_EP: Endpoint = Endpoint::new();
        const EMPTY_NT: Notification = Notification::new();
        const EMPTY_CN: CNodePage = CNodePage([Cte::null(); CNODE_SLOTS]);
        const EMPTY_SC: crate::sched_context::SchedContext =
            crate::sched_context::SchedContext::new(0, 0);
        const EMPTY_REPLY: crate::reply::Reply = crate::reply::Reply::new();
        Self {
            scheduler: Scheduler::new(),
            endpoints: [EMPTY_EP; MAX_ENDPOINTS],
            notifications: [EMPTY_NT; MAX_NTFNS],
            cnodes: [EMPTY_CN; MAX_CNODES],
            sched_contexts: [EMPTY_SC; MAX_SCHED_CONTEXTS],
            replies: [EMPTY_REPLY; MAX_REPLIES],
            irqs: IrqTable::new(),
            // Reserve indices < these for kernel-internal use
            // (boot CNode = 0, AY-demo CNodes = 1, 2, rootserver
            // CNode = 3). Bump allocators start past the reserved
            // range.
            next_endpoint: 4,
            next_notification: 0,
            next_cnode: 4,
            next_sched_context: 0,
            next_reply: 0,
        }
    }

    /// Allocate the next free in-kernel endpoint.
    pub fn alloc_endpoint(&mut self) -> Option<usize> {
        if self.next_endpoint < MAX_ENDPOINTS {
            let i = self.next_endpoint;
            self.next_endpoint += 1;
            self.endpoints[i] = Endpoint::new();
            return Some(i);
        }
        // Recycle: an endpoint with no waiters is free for reuse.
        for i in 0..MAX_ENDPOINTS {
            let ep = &self.endpoints[i];
            if ep.head.is_none() && ep.tail.is_none()
                && matches!(ep.state, crate::endpoint::EpState::Idle)
            {
                // Need a sentinel to distinguish "freshly idle" from
                // "in-use but currently idle". We use a side-bitmap.
                if !self.ep_in_use(i) {
                    self.endpoints[i] = Endpoint::new();
                    self.set_ep_in_use(i, true);
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn free_endpoint(&mut self, i: usize) {
        if i < MAX_ENDPOINTS {
            self.endpoints[i] = Endpoint::new();
            self.set_ep_in_use(i, false);
        }
    }

    pub fn alloc_notification(&mut self) -> Option<usize> {
        if self.next_notification < MAX_NTFNS {
            let i = self.next_notification;
            self.next_notification += 1;
            self.notifications[i] = Notification::new();
            self.set_ntfn_in_use(i, true);
            return Some(i);
        }
        for i in 0..MAX_NTFNS {
            if !self.ntfn_in_use(i) {
                self.notifications[i] = Notification::new();
                self.set_ntfn_in_use(i, true);
                return Some(i);
            }
        }
        None
    }

    pub fn free_notification(&mut self, i: usize) {
        if i < MAX_NTFNS {
            self.notifications[i] = Notification::new();
            self.set_ntfn_in_use(i, false);
        }
    }

    pub fn alloc_cnode(&mut self) -> Option<usize> {
        if self.next_cnode < MAX_CNODES {
            let i = self.next_cnode;
            self.next_cnode += 1;
            for slot in self.cnodes[i].0.iter_mut() {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
            }
            self.set_cnode_in_use(i, true);
            return Some(i);
        }
        for i in 0..MAX_CNODES {
            if !self.cnode_in_use(i) {
                for slot in self.cnodes[i].0.iter_mut() {
                    slot.set_cap(&Cap::Null);
                    slot.set_parent(None);
                }
                self.set_cnode_in_use(i, true);
                return Some(i);
            }
        }
        None
    }

    pub fn free_cnode(&mut self, i: usize) {
        if i < MAX_CNODES {
            for slot in self.cnodes[i].0.iter_mut() {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
            }
            self.set_cnode_in_use(i, false);
        }
    }

    /// Claim a CNode index whose contents were populated by code
    /// outside the alloc_cnode path (e.g. the rootserver's CNode at
    /// boot). Without this, the in-use bitmap doesn't see the CNode
    /// as occupied and a subsequent `alloc_cnode` recycles it,
    /// wiping every cap the direct-init code placed there.
    pub fn claim_cnode(&mut self, i: usize) {
        if i < MAX_CNODES {
            self.set_cnode_in_use(i, true);
            if self.next_cnode <= i {
                self.next_cnode = i + 1;
            }
        }
    }

    // Phase 43 — bitmap-based "in-use" tracking for pool recycling.
    fn ep_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.endpoints[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_ep_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.endpoints[i / 64];
            if v { *w |= 1 << (i % 64); } else { *w &= !(1 << (i % 64)); }
        }
    }
    fn ntfn_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.notifications[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_ntfn_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.notifications[i / 64];
            if v { *w |= 1 << (i % 64); } else { *w &= !(1 << (i % 64)); }
        }
    }
    fn cnode_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.cnodes[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_cnode_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.cnodes[i / 64];
            if v { *w |= 1 << (i % 64); } else { *w &= !(1 << (i % 64)); }
        }
    }
    fn reply_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.replies[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_reply_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.replies[i / 64];
            if v { *w |= 1 << (i % 64); } else { *w &= !(1 << (i % 64)); }
        }
    }

    pub fn free_reply(&mut self, i: usize) {
        if i < MAX_REPLIES {
            self.replies[i] = crate::reply::Reply::new();
            self.set_reply_in_use(i, false);
        }
    }

    /// Phase 32c — allocate the next free SchedContext slot.
    /// Phase 43 — scan from `next_sched_context` then fall back to a
    /// linear search for a recycled slot (one with `bound_tcb=None`
    /// AND `count==0`, i.e. never configured or freed). This lets
    /// long sel4test runs reuse slots cleared by `free_sched_context`.
    pub fn alloc_sched_context(&mut self) -> Option<usize> {
        if self.next_sched_context < MAX_SCHED_CONTEXTS {
            let i = self.next_sched_context;
            self.next_sched_context += 1;
            self.sched_contexts[i] = crate::sched_context::SchedContext::new(0, 0);
            return Some(i);
        }
        for i in 0..MAX_SCHED_CONTEXTS {
            if self.sched_contexts[i].bound_tcb.is_none()
                && self.sched_contexts[i].count == 0
            {
                self.sched_contexts[i] = crate::sched_context::SchedContext::new(0, 0);
                return Some(i);
            }
        }
        None
    }

    /// Phase 43 — release a SchedContext slot for reuse.
    pub fn free_sched_context(&mut self, i: usize) {
        if i < MAX_SCHED_CONTEXTS {
            self.sched_contexts[i] = crate::sched_context::SchedContext::new(0, 0);
        }
    }

    /// `PPtr<SchedContextStorage>` for SC pool slot `i` — encodes
    /// `i + 1` into the address so it stays NonZero.
    pub fn sched_context_ptr(
        i: usize,
    ) -> PPtr<crate::cap::SchedContextStorage> {
        PPtr::<crate::cap::SchedContextStorage>::new(i as u64 + 1)
            .expect("non-zero")
    }
    pub fn sched_context_index(
        p: PPtr<crate::cap::SchedContextStorage>,
    ) -> usize {
        (p.addr() - 1) as usize
    }

    /// Phase 34e — allocate the next free Reply slot.
    pub fn alloc_reply(&mut self) -> Option<usize> {
        if self.next_reply < MAX_REPLIES {
            let i = self.next_reply;
            self.next_reply += 1;
            self.replies[i] = crate::reply::Reply::new();
            self.set_reply_in_use(i, true);
            return Some(i);
        }
        for i in 0..MAX_REPLIES {
            if !self.reply_in_use(i) {
                self.replies[i] = crate::reply::Reply::new();
                self.set_reply_in_use(i, true);
                return Some(i);
            }
        }
        None
    }

    pub fn reply_ptr(i: usize) -> PPtr<crate::cap::ReplyStorage> {
        PPtr::<crate::cap::ReplyStorage>::new(i as u64 + 1).expect("non-zero")
    }
    pub fn reply_index(p: PPtr<crate::cap::ReplyStorage>) -> usize {
        (p.addr() - 1) as usize
    }

    /// Build the `PPtr<EndpointObj>` for endpoint slot `i`. The
    /// 1-based indexing keeps the address NonZero so it fits in a
    /// PPtr.
    pub fn endpoint_ptr(i: usize) -> PPtr<EndpointObj> {
        PPtr::<EndpointObj>::new(i as u64 + 1).expect("non-zero")
    }
    pub fn endpoint_index(p: PPtr<EndpointObj>) -> usize {
        (p.addr() - 1) as usize
    }

    pub fn cnode_ptr(i: usize) -> PPtr<CNodeStorage> {
        // CnodeCap encodes the pointer with the low bit shifted off
        // (seL4 assumes ≥2-byte CNode alignment so it can pack extra
        // fields into bit 0). Our slab indexing has to keep every
        // synthesized addr even, otherwise odd-`i` slots round-trip
        // through the cap encoding to a different slab index. Use a
        // 2-byte stride: i=0→addr=2, i=1→addr=4, etc.
        PPtr::<CNodeStorage>::new(((i as u64) + 1) << 1).expect("non-zero")
    }
    pub fn cnode_index(p: PPtr<CNodeStorage>) -> usize {
        ((p.addr() >> 1) - 1) as usize
    }

    pub fn ntfn_ptr(i: usize) -> PPtr<NotificationObj> {
        PPtr::<NotificationObj>::new(i as u64 + 1).expect("non-zero")
    }
    pub fn ntfn_index(p: PPtr<NotificationObj>) -> usize {
        (p.addr() - 1) as usize
    }

    /// Resolve an endpoint cap to the live `Endpoint` object.
    pub fn endpoint_for_cap(&mut self, cap: &Cap) -> Option<(PPtr<EndpointObj>, &mut Endpoint)> {
        match cap {
            Cap::Endpoint { ptr, .. } => {
                let idx = Self::endpoint_index(*ptr);
                self.endpoints.get_mut(idx).map(|e| (*ptr, e))
            }
            _ => None,
        }
    }
}

impl CSpace for KernelState {
    fn cnode_at(&self, ptr: PPtr<CNodeStorage>, count: usize) -> Option<&[Cte]> {
        let idx = Self::cnode_index(ptr);
        let page = self.cnodes.get(idx)?;
        let slots = &page.0;
        // Caller may ask for fewer than CNODE_SLOTS — lookup_cap
        // bounds the slice on `slot_count = 1 << radix`.
        Some(&slots[..count.min(slots.len())])
    }
}

/// `Sync` newtype around an `UnsafeCell<KernelState>` so it can be
/// `static`. The contract: only the kernel itself (not user mode,
/// not interrupt context) holds a reference, and the kernel never
/// recurses into itself, so there is exactly one `&mut` in flight
/// at any time.
pub struct KernelStateCell(UnsafeCell<KernelState>);

unsafe impl Sync for KernelStateCell {}

impl KernelStateCell {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(KernelState::new()))
    }

    /// SAFETY: caller is the kernel running in CPL=0 with
    /// interrupts already disabled (or, in UP, simply at any point
    /// where no other kernel-entry context is live). Each call must
    /// drop its `&mut` before another kernel entry runs.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get(&self) -> &mut KernelState {
        &mut *self.0.get()
    }
}

#[no_mangle]
pub static KERNEL: KernelStateCell = KernelStateCell::new();

// ---------------------------------------------------------------------------
// Bootstrap: register the running kernel context as TCB 0.
// ---------------------------------------------------------------------------

/// The bootstrap thread — the one running the boot path. It's
/// already in `Running` state by virtue of being the CPU's current
/// context; we just need to install a TCB representing it so the
/// scheduler has somewhere to save its register state when we
/// context-switch out for the first time.
pub fn bootstrap_boot_thread() -> TcbId {
    unsafe {
        let s = KERNEL.get();
        let mut t = Tcb::default();
        t.priority = 254; // top priority — kernel boot
        t.state = ThreadStateType::Running;
        let id = s.scheduler.admit(t);
        s.scheduler.set_current(Some(id));
        id
    }
}

/// Get the currently-running thread, or `None` if the bootstrap
/// hasn't run yet. Useful for syscall handlers that need to know
/// *which* TCB to consult for the CSpace lookup.
pub fn current_thread() -> Option<TcbId> {
    unsafe { KERNEL.get().scheduler.current() }
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_kernel_state() {
        arch::log("Running KernelState tests...\n");
        bootstrap_registers_boot_thread();
        scheduler_state_persists_across_calls();
        claim_cnode_pins_directly_initialised_slot();
        arch::log("KernelState tests completed\n");
    }

    /// Phase 43 — `claim_cnode` must mark a directly-initialised CNode
    /// as in-use AND advance `next_cnode` so a subsequent
    /// `alloc_cnode` cannot recycle that slot. Regression test for
    /// the bug that caused DOMAINS0001's vka to retype against a
    /// silently-wiped Untyped: rootserver init populated cn3
    /// directly, didn't claim it, then alloc_cnode looking for a free
    /// slot found cn3 and zeroed every cap.
    #[inline(never)]
    fn claim_cnode_pins_directly_initialised_slot() {
        unsafe {
            let s = KERNEL.get();
            // Take a snapshot — specs above us may have already
            // touched the bitmap. We claim slot 7 and verify only the
            // claim affects it.
            let target = 7usize;
            assert!(target < MAX_CNODES);
            let was_in_use = s.cnode_in_use(target);
            let was_next = s.next_cnode;
            s.claim_cnode(target);
            assert!(s.cnode_in_use(target),
                "claim_cnode should mark slot in-use");
            assert!(s.next_cnode > target,
                "next_cnode should advance past a claimed slot");
            // alloc_cnode must NOT now hand back our claimed slot.
            let alloced = s.alloc_cnode().expect("alloc_cnode");
            assert!(alloced != target,
                "alloc_cnode handed back our claimed slot {} (got {})",
                target, alloced);
            // Cleanup: free both back so other specs see the original
            // bookkeeping.
            s.free_cnode(alloced);
            if !was_in_use { s.free_cnode(target); }
            s.next_cnode = was_next;
            arch::log(
                "  \u{2713} claim_cnode pins a directly-initialised CNode\n");
        }
    }

    #[inline(never)]
    fn bootstrap_registers_boot_thread() {
        let id = bootstrap_boot_thread();
        assert_eq!(current_thread(), Some(id));
        // The boot thread sits at the top of priority space.
        unsafe {
            let s = KERNEL.get();
            let tcb = s.scheduler.slab.get(id);
            assert_eq!(tcb.priority, 254);
            assert_eq!(tcb.state, ThreadStateType::Running);
        }
        arch::log("  ✓ boot thread admitted as the current TCB\n");
    }

    #[inline(never)]
    fn scheduler_state_persists_across_calls() {
        // bootstrap_boot_thread already ran above. Add a second TCB
        // and confirm we see both.
        let mut t = Tcb::default();
        t.priority = 50;
        t.state = ThreadStateType::Running;
        unsafe {
            let s = KERNEL.get();
            let id2 = s.scheduler.admit(t);
            assert!(id2 != current_thread().unwrap(),
                "second TCB should have a different id");
            // Both threads at different priorities — choose_thread
            // picks the higher one (boot thread).
            let chosen = s.scheduler.choose_thread();
            assert_eq!(chosen, current_thread());
            // Free the temp.
            s.scheduler.slab.free(id2);
        }
        arch::log("  ✓ KernelState singleton persists across calls\n");
    }
}
