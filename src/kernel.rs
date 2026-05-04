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
/// Phase 36e bumped from 5 → 6 (32 → 64 slots). Phase 42 bumped
/// further to 12 (4096 slots) because sel4test's allocman walks
/// `bi.empty` to allocate hundreds of caps in the rootserver's
/// radix-12 CSpace. Lower than 4096 silently truncates allocman's
/// addressable range and the driver can't load ELFs.
pub const CNODE_RADIX: u8 = 12;
pub const CNODE_SLOTS: usize = 1 << CNODE_RADIX;

/// Maximum pre-allocated big CNodes. 48 × 4096 × 32 = 6 MiB of
/// static BSS (kernel virt range capped at 8 MiB by link.ld's
/// 0xff800000 bootboot reservation). Bumping further requires
/// either growing the kernel virtual window or splitting into a
/// small-CNode pool — see `MAX_SMALL_CNODES`.
pub const MAX_CNODES: usize = 48;

/// One pre-allocated CNode: 32 slots × 32 bytes = 1 KiB.
#[repr(C, align(32))]
pub struct CNodePage(pub [Cte; CNODE_SLOTS]);

impl Default for CNodePage {
    fn default() -> Self { Self([Cte::null(); CNODE_SLOTS]) }
}

/// Small CNode pool — radix ≤ 6 (64 slots). Lets CSPACE0001
/// allocate 64 simultaneous radix-1 CNodes without burning the
/// 128 KiB-per-slot big pool. 96 entries × 64 slots × 32 bytes
/// = 192 KiB of static BSS — sized to CSPACE0001's exact 64
/// demand plus headroom for parallel test churn. Bigger pushes
/// the kernel image past the 8 MiB virt cap.
pub const SMALL_CNODE_RADIX: u8 = 6;
pub const SMALL_CNODE_SLOTS: usize = 1 << SMALL_CNODE_RADIX;
pub const MAX_SMALL_CNODES: usize = 96;
/// `MAX_CNODES + MAX_SMALL_CNODES` must fit in MdbId's 8-bit
/// cnode_idx (0..=254 — 0xFF is part of the SENTINEL). 48 + 96
/// = 144 ✓.
const _: () = assert!(MAX_CNODES + MAX_SMALL_CNODES <= 254);

#[repr(C, align(32))]
pub struct SmallCNodePage(pub [Cte; SMALL_CNODE_SLOTS]);

impl Default for SmallCNodePage {
    fn default() -> Self { Self([Cte::null(); SMALL_CNODE_SLOTS]) }
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
    /// Pre-allocated small-CNode pool. Used for CSPACE0001-style
    /// allocations of many radix-≤6 CNodes that would otherwise
    /// exhaust the big pool. Virtual cnode_idx range:
    /// MAX_CNODES..MAX_CNODES+MAX_SMALL_CNODES.
    pub small_cnodes: [SmallCNodePage; MAX_SMALL_CNODES],
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
    pub next_small_cnode: usize,
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
    pub small_cnodes: [u64; (MAX_SMALL_CNODES + 63) / 64],
    pub replies: [u64; (MAX_REPLIES + 63) / 64],
}

static mut POOL_BITMAPS: PoolBitmaps = PoolBitmaps {
    endpoints: [0; (MAX_ENDPOINTS + 63) / 64],
    notifications: [0; (MAX_NTFNS + 63) / 64],
    cnodes: [0; (MAX_CNODES + 63) / 64],
    small_cnodes: [0; (MAX_SMALL_CNODES + 63) / 64],
    replies: [0; (MAX_REPLIES + 63) / 64],
};

impl KernelState {
    pub const fn new() -> Self {
        const EMPTY_EP: Endpoint = Endpoint::new();
        const EMPTY_NT: Notification = Notification::new();
        const EMPTY_CN: CNodePage = CNodePage([Cte::null(); CNODE_SLOTS]);
        const EMPTY_SCN: SmallCNodePage =
            SmallCNodePage([Cte::null(); SMALL_CNODE_SLOTS]);
        const EMPTY_SC: crate::sched_context::SchedContext =
            crate::sched_context::SchedContext::new(0, 0);
        const EMPTY_REPLY: crate::reply::Reply = crate::reply::Reply::new();
        Self {
            scheduler: Scheduler::new(),
            endpoints: [EMPTY_EP; MAX_ENDPOINTS],
            notifications: [EMPTY_NT; MAX_NTFNS],
            cnodes: [EMPTY_CN; MAX_CNODES],
            small_cnodes: [EMPTY_SCN; MAX_SMALL_CNODES],
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
            next_small_cnode: 0,
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
        // Phase 43 — recycle freed slots BEFORE bumping next_cnode, so
        // the bump-allocator doesn't blow through MAX_CNODES while
        // there are perfectly good freed slots sitting at low indices.
        for i in 0..self.next_cnode.min(MAX_CNODES) {
            if !self.cnode_in_use(i) {
                for slot in self.cnodes[i].0.iter_mut() {
                    slot.set_cap(&Cap::Null);
                    slot.set_parent(None);
                }
                self.set_cnode_in_use(i, true);
                return Some(i);
            }
        }
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

    /// Pool-aware free for a virtual cnode index. Dispatches to
    /// `free_cnode` (big pool) or `free_small_cnode` (small pool)
    /// based on `vi`. Use this from cap-delete paths so callers
    /// don't have to know which pool a `Cap::CNode` lives in.
    pub fn free_cnode_virt(&mut self, vi: usize) {
        if vi < MAX_CNODES {
            self.free_cnode(vi);
        } else if vi < MAX_CNODES + MAX_SMALL_CNODES {
            self.free_small_cnode(vi);
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

    /// Allocate a slot from the small CNode pool. Returns the
    /// VIRTUAL cnode_idx (`MAX_CNODES + small_idx`) so callers
    /// can use `cnode_ptr_virt(virt_idx)` and `cnode_slots(virt_idx)`
    /// uniformly across both pools.
    pub fn alloc_small_cnode(&mut self) -> Option<usize> {
        for i in 0..self.next_small_cnode.min(MAX_SMALL_CNODES) {
            if !self.small_cnode_in_use(i) {
                for slot in self.small_cnodes[i].0.iter_mut() {
                    slot.set_cap(&Cap::Null);
                    slot.set_parent(None);
                }
                self.set_small_cnode_in_use(i, true);
                return Some(MAX_CNODES + i);
            }
        }
        if self.next_small_cnode < MAX_SMALL_CNODES {
            let i = self.next_small_cnode;
            self.next_small_cnode += 1;
            for slot in self.small_cnodes[i].0.iter_mut() {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
            }
            self.set_small_cnode_in_use(i, true);
            return Some(MAX_CNODES + i);
        }
        None
    }

    /// Free a small CNode slot. `virt_idx` is the VIRTUAL index
    /// (must be in `MAX_CNODES..MAX_CNODES+MAX_SMALL_CNODES`).
    pub fn free_small_cnode(&mut self, virt_idx: usize) {
        if virt_idx >= MAX_CNODES
            && virt_idx < MAX_CNODES + MAX_SMALL_CNODES
        {
            let i = virt_idx - MAX_CNODES;
            for slot in self.small_cnodes[i].0.iter_mut() {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
            }
            self.set_small_cnode_in_use(i, false);
        }
    }

    /// Total virtual cnode count = big + small. Used by revoke /
    /// delete walks that need to scan both pools.
    pub const fn cnode_pool_count() -> usize {
        MAX_CNODES + MAX_SMALL_CNODES
    }

    /// Backing slot slice for virtual cnode index `vi`.
    /// Dispatches to either `cnodes[vi]` (big) or
    /// `small_cnodes[vi - MAX_CNODES]` (small).
    pub fn cnode_slots_at(&self, vi: usize) -> Option<&[Cte]> {
        if vi < MAX_CNODES {
            self.cnodes.get(vi).map(|p| &p.0[..])
        } else if vi < MAX_CNODES + MAX_SMALL_CNODES {
            self.small_cnodes.get(vi - MAX_CNODES).map(|p| &p.0[..])
        } else {
            None
        }
    }

    pub fn cnode_slots_at_mut(&mut self, vi: usize) -> Option<&mut [Cte]> {
        if vi < MAX_CNODES {
            self.cnodes.get_mut(vi).map(|p| &mut p.0[..])
        } else if vi < MAX_CNODES + MAX_SMALL_CNODES {
            self.small_cnodes
                .get_mut(vi - MAX_CNODES)
                .map(|p| &mut p.0[..])
        } else {
            None
        }
    }

    /// Convenience accessor: a single Cte at `(vi, si)`.
    pub fn cnode_slot(&self, vi: usize, si: usize) -> Option<&Cte> {
        self.cnode_slots_at(vi).and_then(|s| s.get(si))
    }
    pub fn cnode_slot_mut(&mut self, vi: usize, si: usize)
        -> Option<&mut Cte>
    {
        self.cnode_slots_at_mut(vi).and_then(|s| s.get_mut(si))
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
    fn small_cnode_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.small_cnodes[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_small_cnode_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.small_cnodes[i / 64];
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
        //
        // `i` is the *virtual* cnode index — the same encoding covers
        // both the big pool (i ∈ [0, MAX_CNODES)) and the small pool
        // (i ∈ [MAX_CNODES, MAX_CNODES + MAX_SMALL_CNODES)). Dispatch
        // happens in `cnode_slots_at`.
        PPtr::<CNodeStorage>::new(((i as u64) + 1) << 1).expect("non-zero")
    }
    pub fn cnode_index(p: PPtr<CNodeStorage>) -> usize {
        ((p.addr() >> 1) - 1) as usize
    }
    /// Returns true if `vi` indexes the small pool.
    pub const fn is_small_cnode_idx(vi: usize) -> bool {
        vi >= MAX_CNODES && vi < MAX_CNODES + MAX_SMALL_CNODES
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
        let slots = self.cnode_slots_at(idx)?;
        // Caller may ask for fewer than the backing storage capacity —
        // lookup_cap bounds the slice on `slot_count = 1 << radix`.
        // Both pools use the same dispatch via `cnode_slots_at`.
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
        small_cnode_pool_alloc_free_dispatch();
        arch::log("KernelState tests completed\n");
    }

    /// Phase 43 — small CNode pool. `alloc_small_cnode` returns a
    /// VIRTUAL index ≥ MAX_CNODES that `cnode_slots_at` dispatches to
    /// `small_cnodes[]`. CSPACE0001 in sel4test relies on having 64
    /// simultaneous radix-1 CNodes; the big pool's 48-slot cap can't
    /// fit them and the kernel virt range can't grow further.
    #[inline(never)]
    fn small_cnode_pool_alloc_free_dispatch() {
        unsafe {
            let s = KERNEL.get();
            let vi = s.alloc_small_cnode().expect("alloc_small_cnode");
            assert!(vi >= MAX_CNODES,
                "small alloc returned virtual index {} (must be >= MAX_CNODES={})",
                vi, MAX_CNODES);
            assert!(vi < MAX_CNODES + MAX_SMALL_CNODES);
            // `cnode_slots_at` must dispatch to the small backing array
            // and surface SMALL_CNODE_SLOTS slots (not CNODE_SLOTS).
            let slots = s.cnode_slots_at(vi).expect("slots present");
            assert_eq!(slots.len(), SMALL_CNODE_SLOTS,
                "small pool slot dispatch wrong: got {} slots, expected {}",
                slots.len(), SMALL_CNODE_SLOTS);
            // PPtr round-trip: encoding a small virtual index and
            // decoding it must come back to the same virtual index.
            let ptr = KernelState::cnode_ptr(vi);
            assert_eq!(KernelState::cnode_index(ptr), vi);
            assert!(KernelState::is_small_cnode_idx(vi));
            s.free_small_cnode(vi);
            assert!(!s.small_cnode_in_use(vi - MAX_CNODES));
            arch::log(
                "  \u{2713} small CNode pool alloc/free dispatch via virtual index\n");
        }
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
