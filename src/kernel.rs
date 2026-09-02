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

use crate::cap::{CNodeStorage, Cap, EndpointObj, NotificationObj, PPtr};
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
pub const MAX_ENDPOINTS: usize = 384;

/// Maximum notifications in the in-kernel pool.
pub const MAX_NTFNS: usize = 384;

/// Maximum SchedContexts in the in-kernel pool (Phase 32c). The extern NT rootserver can churn
/// hundreds of short-lived hosted worker threads before the desktop is stable; keep the slab large
/// enough for that stress until SchedContexts are backed directly by Untyped allocations.
#[cfg(not(feature = "extern-rootserver"))]
pub const MAX_SCHED_CONTEXTS: usize = 384;
#[cfg(feature = "extern-rootserver")]
pub const MAX_SCHED_CONTEXTS: usize = 1024;

/// Maximum Reply objects in the in-kernel pool (Phase 34e). The extern NT rootserver parks many
/// simultaneous user threads on MCS replies while also reserving dedicated replies for component
/// channels, so it needs the same larger profile treatment as sched contexts.
#[cfg(not(feature = "extern-rootserver"))]
pub const MAX_REPLIES: usize = 384;
#[cfg(feature = "extern-rootserver")]
pub const MAX_REPLIES: usize = 1024;

/// CTEs per pre-allocated CNode in the in-kernel pool.
///
/// Phase 36e bumped from 5 → 6 (32 → 64 slots). Phase 42 bumped
/// further to 12 (4096 slots) because sel4test's allocman walks
/// `bi.empty` to allocate hundreds of caps in the rootserver's
/// radix-12 CSpace. Lower than 4096 silently truncates allocman's
/// addressable range and the driver can't load ELFs.
pub const CNODE_RADIX: u8 = 12;
pub const CNODE_SLOTS: usize = 1 << CNODE_RADIX;

/// Direct-index CNodes retained by the standalone/spec profile. Production CapTables, including
/// the root CSpace, use exact physical storage registered in `dynamic_cnodes`.
#[cfg(any(not(feature = "extern-rootserver"), feature = "spec"))]
pub const MAX_CNODES: usize = 48;
#[cfg(all(feature = "extern-rootserver", not(feature = "spec")))]
pub const MAX_CNODES: usize = 0;

/// One direct-index CNode: 4096 slots x 32 bytes = 128 KiB.
#[repr(C, align(32))]
pub struct CNodePage(pub [Cte; CNODE_SLOTS]);

impl Default for CNodePage {
    fn default() -> Self {
        Self([Cte::null(); CNODE_SLOTS])
    }
}

/// Direct-index small CNodes used only by specs that exercise this pool allocator itself.
pub const SMALL_CNODE_RADIX: u8 = 6;
pub const SMALL_CNODE_SLOTS: usize = 1 << SMALL_CNODE_RADIX;
#[cfg(feature = "spec")]
pub const MAX_SMALL_CNODES: usize = 96;
#[cfg(not(feature = "spec"))]
pub const MAX_SMALL_CNODES: usize = 0;

#[repr(C, align(32))]
pub struct SmallCNodePage(pub [Cte; SMALL_CNODE_SLOTS]);

impl Default for SmallCNodePage {
    fn default() -> Self {
        Self([Cte::null(); SMALL_CNODE_SLOTS])
    }
}

/// Virtual cnode index space:
///   [0, MAX_CNODES)                      big (radix 12)
///   [MAX_CNODES, +MAX_SMALL_CNODES)      small (radix <= 6)
///   [.., +MAX_DYNAMIC_CNODES)            exact Untyped-backed CNodes

/// Compact identities for CNodes whose CTE storage is the physical memory consumed from their
/// source Untyped. Descriptor capacity is metadata only; CTE capacity comes from RAM at Retype.
pub const MAX_DYNAMIC_CNODES: usize = 1024;
pub const DYNAMIC_CNODE_BASE: usize = MAX_CNODES + MAX_SMALL_CNODES;

#[derive(Copy, Clone)]
pub struct DynamicCNodeDescriptor {
    pub paddr: u64,
    pub radix: u8,
    pub in_use: bool,
}

impl DynamicCNodeDescriptor {
    pub const EMPTY: Self = Self {
        paddr: 0,
        radix: 0,
        in_use: false,
    };
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
    pub sched_contexts: [crate::sched_context::SchedContext; MAX_SCHED_CONTEXTS],
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
    /// Exact CapTable objects created from Untyped memory. Their CTE arrays live in the carved
    /// physical spans; the kernel retains only lookup/lifetime metadata here.
    pub dynamic_cnodes: [DynamicCNodeDescriptor; MAX_DYNAMIC_CNODES],
    /// Per-IRQ binding table.
    pub irqs: IrqTable,

    /// Direct-index CNode allocation hints retained by the standalone/spec profile. Production
    /// CapTables are registered from the exact Untyped backing span instead.
    pub next_cnode: usize,
    pub next_small_cnode: usize,
}

/// Phase 43 — pool-recycling bitmap. Bit set means slot is in use.
/// Separate static so we can mutate without borrowing all of
/// `KernelState`. BKL serialises access.
struct PoolBitmaps {
    pub endpoints: [u64; (MAX_ENDPOINTS + 63) / 64],
    pub notifications: [u64; (MAX_NTFNS + 63) / 64],
    pub cnodes: [u64; (MAX_CNODES + 63) / 64],
    pub small_cnodes: [u64; (MAX_SMALL_CNODES + 63) / 64],
    pub sched_contexts: [u64; (MAX_SCHED_CONTEXTS + 63) / 64],
    pub replies: [u64; (MAX_REPLIES + 63) / 64],
}

static mut POOL_BITMAPS: PoolBitmaps = PoolBitmaps {
    endpoints: [0; (MAX_ENDPOINTS + 63) / 64],
    notifications: [0; (MAX_NTFNS + 63) / 64],
    cnodes: [0; (MAX_CNODES + 63) / 64],
    small_cnodes: [0; (MAX_SMALL_CNODES + 63) / 64],
    sched_contexts: [0; (MAX_SCHED_CONTEXTS + 63) / 64],
    replies: [0; (MAX_REPLIES + 63) / 64],
};

impl KernelState {
    pub const fn new() -> Self {
        const EMPTY_EP: Endpoint = Endpoint::new();
        const EMPTY_NT: Notification = Notification::new();
        const EMPTY_CN: CNodePage = CNodePage([Cte::null(); CNODE_SLOTS]);
        const EMPTY_SCN: SmallCNodePage = SmallCNodePage([Cte::null(); SMALL_CNODE_SLOTS]);
        const EMPTY_SC: crate::sched_context::SchedContext =
            crate::sched_context::SchedContext::new(0, 0);
        const EMPTY_REPLY: crate::reply::Reply = crate::reply::Reply::new();
        Self {
            scheduler: Scheduler::new(),
            endpoints: [EMPTY_EP; MAX_ENDPOINTS],
            notifications: [EMPTY_NT; MAX_NTFNS],
            cnodes: [EMPTY_CN; MAX_CNODES],
            small_cnodes: [EMPTY_SCN; MAX_SMALL_CNODES],
            dynamic_cnodes: [DynamicCNodeDescriptor::EMPTY; MAX_DYNAMIC_CNODES],
            sched_contexts: [EMPTY_SC; MAX_SCHED_CONTEXTS],
            replies: [EMPTY_REPLY; MAX_REPLIES],
            irqs: IrqTable::new(),
            // Reserve direct CNodes 0..3 for standalone/spec bootstrap fixtures. Production does
            // not instantiate this array.
            next_cnode: 4,
            next_small_cnode: 0,
        }
    }

    /// Allocate an Endpoint identity. Object state is not ownership: an idle live endpoint remains
    /// unavailable until its last capability releases it.
    pub fn alloc_endpoint(&mut self) -> Option<usize> {
        for i in 0..MAX_ENDPOINTS {
            if !self.ep_in_use(i) {
                self.set_ep_in_use(i, true);
                self.endpoints[i] = Endpoint::new();
                return Some(i);
            }
        }
        None
    }

    pub fn claim_endpoint(&mut self, i: usize) {
        assert!(i < MAX_ENDPOINTS, "claimed Endpoint identity out of range");
        assert!(!self.ep_in_use(i), "Endpoint identity already owned");
        self.set_ep_in_use(i, true);
    }

    pub fn available_endpoints(&self) -> usize {
        (0..MAX_ENDPOINTS).filter(|&i| !self.ep_in_use(i)).count()
    }

    pub fn free_endpoint(&mut self, i: usize) {
        if i < MAX_ENDPOINTS {
            self.endpoints[i] = Endpoint::new();
            self.set_ep_in_use(i, false);
        }
    }

    pub fn alloc_notification(&mut self) -> Option<usize> {
        for i in 0..MAX_NTFNS {
            if !self.ntfn_in_use(i) {
                self.set_ntfn_in_use(i, true);
                self.notifications[i] = Notification::new();
                return Some(i);
            }
        }
        None
    }

    pub fn available_notifications(&self) -> usize {
        (0..MAX_NTFNS).filter(|&i| !self.ntfn_in_use(i)).count()
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

    pub fn available_dynamic_cnodes(&self) -> usize {
        self.dynamic_cnodes
            .iter()
            .filter(|descriptor| !descriptor.in_use)
            .count()
    }

    /// Bind one compact CNode identity to the exact physical CapTable span consumed from Untyped.
    pub fn alloc_dynamic_cnode(&mut self, paddr: u64, radix: u8) -> Option<usize> {
        if radix == 0 || radix as u32 > crate::cte::MdbId::SLOT_BITS {
            return None;
        }
        let size = (1u64 << radix).checked_mul(Cte::SIZE_BYTES as u64)?;
        if paddr & (size - 1) != 0 {
            return None;
        }
        let index = self
            .dynamic_cnodes
            .iter()
            .position(|descriptor| !descriptor.in_use)?;
        self.dynamic_cnodes[index] = DynamicCNodeDescriptor {
            paddr,
            radix,
            in_use: true,
        };
        Some(DYNAMIC_CNODE_BASE + index)
    }

    pub fn free_dynamic_cnode(&mut self, vi: usize) {
        let Some(index) = vi.checked_sub(DYNAMIC_CNODE_BASE) else {
            return;
        };
        if index >= MAX_DYNAMIC_CNODES || !self.dynamic_cnodes[index].in_use {
            return;
        }
        if let Some(slots) = self.cnode_slots_at_mut(vi) {
            for slot in slots {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
                slot.set_child_count(0);
                slot.set_revoke_epoch(0);
            }
        }
        self.dynamic_cnodes[index] = DynamicCNodeDescriptor::EMPTY;
    }

    pub fn dynamic_cnode_backing(&self, vi: usize) -> Option<(u64, u64)> {
        let descriptor = self
            .dynamic_cnodes
            .get(vi.checked_sub(DYNAMIC_CNODE_BASE)?)?;
        if !descriptor.in_use {
            return None;
        }
        Some((
            descriptor.paddr,
            (1u64 << descriptor.radix) * Cte::SIZE_BYTES as u64,
        ))
    }

    /// Pool-aware free for a virtual cnode index. Dispatches to
    /// `free_cnode` (big pool) or `free_small_cnode` (small pool)
    /// based on `vi`. Use this from cap-delete paths so callers
    /// don't have to know which pool a `Cap::CNode` lives in.
    pub fn free_cnode_virt(&mut self, vi: usize) {
        // Metadata is stored in the CTEs themselves and must be cleared while a dynamic descriptor
        // still resolves its physical backing.
        unsafe { crate::invocation::child_counts_reset_page(vi) };
        if vi < MAX_CNODES {
            self.free_cnode(vi);
        } else if vi < MAX_CNODES + MAX_SMALL_CNODES {
            self.free_small_cnode(vi);
        } else {
            self.free_dynamic_cnode(vi);
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
        if virt_idx >= MAX_CNODES && virt_idx < MAX_CNODES + MAX_SMALL_CNODES {
            let i = virt_idx - MAX_CNODES;
            for slot in self.small_cnodes[i].0.iter_mut() {
                slot.set_cap(&Cap::Null);
                slot.set_parent(None);
            }
            self.set_small_cnode_in_use(i, false);
        }
    }

    /// Total virtual CNode identity count. Used by revoke/delete walks that scan registered pools.
    pub const fn cnode_pool_count() -> usize {
        DYNAMIC_CNODE_BASE + MAX_DYNAMIC_CNODES
    }

    /// Backing slot slice for virtual cnode index `vi`.
    /// Dispatches to direct-index spec storage or exact physical dynamic backing.
    pub fn cnode_slots_at(&self, vi: usize) -> Option<&[Cte]> {
        if vi < MAX_CNODES {
            self.cnodes.get(vi).map(|p| &p.0[..])
        } else if vi < MAX_CNODES + MAX_SMALL_CNODES {
            self.small_cnodes.get(vi - MAX_CNODES).map(|p| &p.0[..])
        } else if vi < Self::cnode_pool_count() {
            let descriptor = self.dynamic_cnodes.get(vi - DYNAMIC_CNODE_BASE)?;
            if !descriptor.in_use || descriptor.radix as u32 > crate::cte::MdbId::SLOT_BITS {
                return None;
            }
            let len = 1usize << descriptor.radix;
            let base = crate::arch::phys_to_virt(descriptor.paddr) as *const Cte;
            Some(unsafe { core::slice::from_raw_parts(base, len) })
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
        } else if vi < Self::cnode_pool_count() {
            let descriptor = self.dynamic_cnodes.get(vi - DYNAMIC_CNODE_BASE)?;
            if !descriptor.in_use || descriptor.radix as u32 > crate::cte::MdbId::SLOT_BITS {
                return None;
            }
            let len = 1usize << descriptor.radix;
            let base = crate::arch::phys_to_virt(descriptor.paddr) as *mut Cte;
            Some(unsafe { core::slice::from_raw_parts_mut(base, len) })
        } else {
            None
        }
    }

    /// Convenience accessor: a single Cte at `(vi, si)`.
    pub fn cnode_slot(&self, vi: usize, si: usize) -> Option<&Cte> {
        self.cnode_slots_at(vi).and_then(|s| s.get(si))
    }
    pub fn cnode_slot_mut(&mut self, vi: usize, si: usize) -> Option<&mut Cte> {
        self.cnode_slots_at_mut(vi).and_then(|s| s.get_mut(si))
    }

    // Phase 43 — bitmap-based "in-use" tracking for pool recycling.
    fn ep_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.endpoints[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_ep_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.endpoints[i / 64];
            if v {
                *w |= 1 << (i % 64);
            } else {
                *w &= !(1 << (i % 64));
            }
        }
    }
    fn ntfn_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.notifications[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_ntfn_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.notifications[i / 64];
            if v {
                *w |= 1 << (i % 64);
            } else {
                *w &= !(1 << (i % 64));
            }
        }
    }
    fn cnode_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.cnodes[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_cnode_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.cnodes[i / 64];
            if v {
                *w |= 1 << (i % 64);
            } else {
                *w &= !(1 << (i % 64));
            }
        }
    }
    fn small_cnode_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.small_cnodes[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_small_cnode_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.small_cnodes[i / 64];
            if v {
                *w |= 1 << (i % 64);
            } else {
                *w &= !(1 << (i % 64));
            }
        }
    }
    fn sc_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.sched_contexts[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_sc_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.sched_contexts[i / 64];
            if v {
                *w |= 1 << (i % 64);
            } else {
                *w &= !(1 << (i % 64));
            }
        }
    }
    fn reply_in_use(&self, i: usize) -> bool {
        unsafe { (POOL_BITMAPS.replies[i / 64] >> (i % 64)) & 1 == 1 }
    }
    fn set_reply_in_use(&self, i: usize, v: bool) {
        unsafe {
            let w = &mut POOL_BITMAPS.replies[i / 64];
            if v {
                *w |= 1 << (i % 64);
            } else {
                *w &= !(1 << (i % 64));
            }
        }
    }

    pub fn free_reply(&mut self, i: usize) {
        if i < MAX_REPLIES {
            self.replies[i] = crate::reply::Reply::new();
            self.set_reply_in_use(i, false);
        }
    }

    /// Allocate a SchedContext identity. A live, unconfigured SC has empty runtime state but remains
    /// owned, so only the ownership bitmap may authorize reuse.
    pub fn alloc_sched_context(&mut self) -> Option<usize> {
        for i in 0..MAX_SCHED_CONTEXTS {
            if !self.sc_in_use(i) {
                self.set_sc_in_use(i, true);
                self.sched_contexts[i] = crate::sched_context::SchedContext::new(0, 0);
                return Some(i);
            }
        }
        None
    }

    pub fn available_sched_contexts(&self) -> usize {
        (0..MAX_SCHED_CONTEXTS)
            .filter(|&i| !self.sc_in_use(i))
            .count()
    }

    /// Phase 43 — release a SchedContext slot for reuse.
    pub fn free_sched_context(&mut self, i: usize) {
        if i < MAX_SCHED_CONTEXTS {
            // SCHED0018 — a yielder waiting on this SC gets its
            // consumed-report when the SC dies, not a dangling link.
            if let Some(yielder) = self.sched_contexts[i].yield_from {
                crate::sched_context::complete_yield_to(self, yielder, i);
            }
            // SCHED0010 — if a TCB is bound to this SC, clear that
            // link so the scheduler sees `tcb.sc == None` and won't
            // consider the thread schedulable. Mirror on any
            // notification holding the SC for passive-server use.
            if let Some(tcb_id) = self.sched_contexts[i].bound_tcb {
                if self.scheduler.slab.try_get(tcb_id).is_some() {
                    // Cross-core delete race (SCHED_CONTEXT_0014): if the
                    // bound thread is currently running on another core,
                    // stall that core off it before we tear the binding
                    // down. Otherwise the core keeps executing a thread
                    // that has just lost its scheduling context (its
                    // ready-queue entry and `current` are cleared out from
                    // under it here) and the next trap delivers a garbage
                    // fault. seL4 does the same `remoteTCBStall` before
                    // unbinding an SC. No-op unless the thread is live on a
                    // different core; gated to the smp build.
                    #[cfg(feature = "smp")]
                    crate::smp::remote_tcb_stall(tcb_id);
                    // Remove from the ready queue / surrender the CPU
                    // before clearing the SC so a runnable thread that
                    // loses its SC can't keep being scheduled.
                    self.scheduler.on_sc_lost(tcb_id);
                    self.scheduler.slab.get_mut(tcb_id).sc = None;
                }
            }
            for ntfn in self.notifications.iter_mut() {
                if ntfn.bound_sc == Some(i as u16) {
                    ntfn.bound_sc = None;
                }
            }
            // IPC0023 — if this SC was donated to a passive server on
            // an in-flight Call, the donor TCB (BlockedOnReply) still
            // records it in `donated_sc` so a reply would move it back.
            // Once the SC is deleted, that link must go too, otherwise
            // the reply returns a freed SC and the donor wrongly
            // becomes schedulable ("client should not run as it has no
            // scheduling context"). Mirrors upstream removing the SC
            // from the reply call-stack on schedContext deletion.
            for e in self.scheduler.slab.entries.iter_mut() {
                if let Some(t) = e.as_mut() {
                    if t.donated_sc == Some(i as u16) {
                        t.donated_sc = None;
                    }
                }
            }
            self.sched_contexts[i] = crate::sched_context::SchedContext::new(0, 0);
            self.set_sc_in_use(i, false);
        }
    }

    /// `PPtr<SchedContextStorage>` for SC pool slot `i` — encodes
    /// `i + 1` into the address so it stays NonZero.
    pub fn sched_context_ptr(i: usize) -> PPtr<crate::cap::SchedContextStorage> {
        PPtr::<crate::cap::SchedContextStorage>::new(i as u64 + 1).expect("non-zero")
    }
    pub fn sched_context_index(p: PPtr<crate::cap::SchedContextStorage>) -> usize {
        (p.addr() - 1) as usize
    }

    /// Phase 34e — allocate the next free Reply slot.
    pub fn alloc_reply(&mut self) -> Option<usize> {
        for i in 0..MAX_REPLIES {
            if !self.reply_in_use(i) {
                self.set_reply_in_use(i, true);
                self.replies[i] = crate::reply::Reply::new();
                return Some(i);
            }
        }
        None
    }

    pub fn available_replies(&self) -> usize {
        (0..MAX_REPLIES).filter(|&i| !self.reply_in_use(i)).count()
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
        // big, small, and XL pools. Dispatch happens in `cnode_slots_at`.
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

// ---------------------------------------------------------------------------
// Phase 44 — per-object and per-IRQ-handler cap refcounts.
//
// `same_obj_lives` used to answer "does any other cap reference this
// pool object?" by sweeping EVERY slot of EVERY CNode pool page on
// every cap delete — O(pool) per delete, and O(slots × pool) for a
// CNode destroy. With honest large cspace backing (131k-slot pages for
// sel4test, 262k for the extern NT rootserver) those sweeps made the suite
// crawl.
//
// Instead: `Cte::set_cap` notes every cap overwrite in a per-object
// refcount (gated on the slot actually living inside a kernel CNode
// pool — stack-built `Cte` temporaries in specs don't count). Boot
// and spec-era writes that predate or bypass the hook are absorbed
// by one `recount_refcounts()` sweep at production start
// (launch_rootserver). Decrements saturate at zero so pre-recount
// noise can't underflow.
// ---------------------------------------------------------------------------

struct ObjRefCounts {
    endpoints: [u32; MAX_ENDPOINTS],
    ntfns: [u32; MAX_NTFNS],
    scs: [u32; MAX_SCHED_CONTEXTS],
    replies: [u32; MAX_REPLIES],
    cnodes: [u32; DYNAMIC_CNODE_BASE + MAX_DYNAMIC_CNODES],
    tcbs: [u32; crate::tcb::MAX_TCBS],
    irq_handlers: [u32; crate::interrupt::MAX_IRQ],
}

static mut OBJ_REFCOUNTS: ObjRefCounts = ObjRefCounts {
    endpoints: [0; MAX_ENDPOINTS],
    ntfns: [0; MAX_NTFNS],
    scs: [0; MAX_SCHED_CONTEXTS],
    replies: [0; MAX_REPLIES],
    cnodes: [0; DYNAMIC_CNODE_BASE + MAX_DYNAMIC_CNODES],
    tcbs: [0; crate::tcb::MAX_TCBS],
    irq_handlers: [0; crate::interrupt::MAX_IRQ],
};

/// Map a cap to the refcount cell of the object or exclusive IRQ vector it references.
/// Other non-pooled caps (Frame, Untyped, ...) have no cell.
fn refcount_cell(cap: &Cap) -> Option<*mut u32> {
    let rc = core::ptr::addr_of_mut!(OBJ_REFCOUNTS);
    unsafe {
        Some(match cap {
            Cap::Endpoint { ptr, .. } => {
                let i = KernelState::endpoint_index(*ptr);
                if i >= MAX_ENDPOINTS {
                    return None;
                }
                &mut (*rc).endpoints[i] as *mut u32
            }
            Cap::Notification { ptr, .. } => {
                let i = KernelState::ntfn_index(*ptr);
                if i >= MAX_NTFNS {
                    return None;
                }
                &mut (*rc).ntfns[i] as *mut u32
            }
            Cap::SchedContext { ptr, .. } => {
                let i = KernelState::sched_context_index(*ptr);
                if i >= MAX_SCHED_CONTEXTS {
                    return None;
                }
                &mut (*rc).scs[i] as *mut u32
            }
            Cap::Reply { ptr, .. } => {
                let i = KernelState::reply_index(*ptr);
                if i >= MAX_REPLIES {
                    return None;
                }
                &mut (*rc).replies[i] as *mut u32
            }
            Cap::CNode { ptr, .. } => {
                let i = KernelState::cnode_index(*ptr);
                if i >= KernelState::cnode_pool_count() {
                    return None;
                }
                &mut (*rc).cnodes[i] as *mut u32
            }
            Cap::Thread { tcb } => {
                let i = tcb.addr() as usize;
                if i >= crate::tcb::MAX_TCBS {
                    return None;
                }
                &mut (*rc).tcbs[i] as *mut u32
            }
            Cap::IrqHandler { irq } => {
                let i = *irq as usize;
                if i >= crate::interrupt::MAX_IRQ {
                    return None;
                }
                &mut (*rc).irq_handlers[i] as *mut u32
            }
            _ => return None,
        })
    }
}

/// Live references to the tracked object or IRQ vector behind `cap` (0 for untracked caps).
pub fn cap_refcount(cap: &Cap) -> u32 {
    refcount_cell(cap).map(|p| unsafe { *p }).unwrap_or(0)
}

/// Called by `Cte::set_cap` for slots inside the kernel CNode pools.
pub(crate) fn note_cap_write(old: &Cap, new: &Cap) {
    unsafe {
        if let Some(p) = refcount_cell(old) {
            *p = (*p).saturating_sub(1);
        }
        if let Some(p) = refcount_cell(new) {
            *p = (*p).checked_add(1).expect("cap refcount overflow");
        }
    }
}

/// Does `addr` point inside one of the kernel CNode pools? Filters
/// `Cte::set_cap` calls on stack temporaries / spec-local arrays out
/// of the refcounting.
pub(crate) fn slot_in_pools(addr: usize) -> bool {
    let s = unsafe { KERNEL.get() };
    let within = |base: *const u8, len: usize| {
        let b = base as usize;
        addr >= b && addr < b + len
    };
    within(
        s.cnodes.as_ptr() as *const u8,
        core::mem::size_of_val(&s.cnodes),
    ) || within(
        s.small_cnodes.as_ptr() as *const u8,
        core::mem::size_of_val(&s.small_cnodes),
    ) || s.dynamic_cnodes.iter().any(|descriptor| {
        if !descriptor.in_use {
            return false;
        }
        let base = crate::arch::phys_to_virt(descriptor.paddr) as usize;
        let len = (1usize << descriptor.radix) * Cte::SIZE_BYTES;
        addr >= base && addr < base.saturating_add(len)
    })
}

/// Rebuild every refcount from the actual pool contents. Run once at
/// production start (launch_rootserver) to absorb boot/spec-era
/// writes that bypassed the `set_cap` hook.
pub fn recount_refcounts() {
    unsafe {
        let rc = core::ptr::addr_of_mut!(OBJ_REFCOUNTS);
        (*rc).endpoints = [0; MAX_ENDPOINTS];
        (*rc).ntfns = [0; MAX_NTFNS];
        (*rc).scs = [0; MAX_SCHED_CONTEXTS];
        (*rc).replies = [0; MAX_REPLIES];
        (*rc).cnodes = [0; DYNAMIC_CNODE_BASE + MAX_DYNAMIC_CNODES];
        (*rc).tcbs = [0; crate::tcb::MAX_TCBS];
        (*rc).irq_handlers = [0; crate::interrupt::MAX_IRQ];
        let s = KERNEL.get();
        for vi in 0..KernelState::cnode_pool_count() {
            let n = s.cnode_slots_at(vi).map(|sl| sl.len()).unwrap_or(0);
            for si in 0..n {
                let cap = s.cnode_slot(vi, si).map(|c| c.cap()).unwrap_or(Cap::Null);
                if let Some(p) = refcount_cell(&cap) {
                    *p = (*p).checked_add(1).expect("cap refcount overflow");
                }
            }
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
                          // Upstream gives the root task tcbMCP = seL4_MaxPrio (255).
                          // sel4test-driver configures test processes with mcp=255;
                          // anything lower here makes that SetSchedParams hit the
                          // authority RangeError and the whole MCP chain (driver →
                          // test → helpers) silently collapses to 0.
        t.mcp = 255;
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

    #[repr(C, align(2048))]
    struct DynamicSpecCNode([Cte; SMALL_CNODE_SLOTS]);

    static mut DYNAMIC_SPEC_CNODE: DynamicSpecCNode =
        DynamicSpecCNode([Cte::null(); SMALL_CNODE_SLOTS]);

    pub fn test_kernel_state() {
        arch::log("Running KernelState tests...\n");
        bootstrap_registers_boot_thread();
        scheduler_state_persists_across_calls();
        pooled_object_ownership_is_explicit();
        claim_cnode_pins_directly_initialised_slot();
        small_cnode_pool_alloc_free_dispatch();
        dynamic_cnode_uses_exact_physical_backing();
        arch::log("KernelState tests completed\n");
    }

    #[inline(never)]
    fn pooled_object_ownership_is_explicit() {
        unsafe {
            let s = KERNEL.get();

            let ep_before = s.available_endpoints();
            let ep0 = s.alloc_endpoint().expect("first Endpoint identity");
            let ep1 = s.alloc_endpoint().expect("second Endpoint identity");
            assert_ne!(ep0, ep1);
            assert_eq!(s.available_endpoints(), ep_before - 2);
            s.free_endpoint(ep0);
            s.free_endpoint(ep1);
            assert_eq!(s.available_endpoints(), ep_before);

            let ntfn_before = s.available_notifications();
            let ntfn = s.alloc_notification().expect("Notification identity");
            assert_eq!(s.available_notifications(), ntfn_before - 1);
            s.free_notification(ntfn);
            assert_eq!(s.available_notifications(), ntfn_before);

            let sc_before = s.available_sched_contexts();
            let sc0 = s.alloc_sched_context().expect("first SC identity");
            let sc1 = s.alloc_sched_context().expect("second SC identity");
            assert_ne!(sc0, sc1, "two live unconfigured SCs must not alias");
            assert_eq!(s.available_sched_contexts(), sc_before - 2);
            s.free_sched_context(sc0);
            s.free_sched_context(sc1);
            assert_eq!(s.available_sched_contexts(), sc_before);

            let reply_before = s.available_replies();
            let reply = s.alloc_reply().expect("Reply identity");
            assert_eq!(s.available_replies(), reply_before - 1);
            s.free_reply(reply);
            assert_eq!(s.available_replies(), reply_before);

            let tcb_before = s.scheduler.available_cap_tcbs();
            let tcb = s
                .scheduler
                .try_admit_cap(Tcb {
                    state: ThreadStateType::Inactive,
                    ..Default::default()
                })
                .expect("cap-backed TCB identity");
            assert_ne!(tcb, TcbId(0));
            assert_eq!(s.scheduler.available_cap_tcbs(), tcb_before - 1);
            s.scheduler.slab.free(tcb);
            assert_eq!(s.scheduler.available_cap_tcbs(), tcb_before);
        }
        arch::log("  \u{2713} pooled object ownership and availability are exact\n");
    }

    #[inline(never)]
    fn dynamic_cnode_uses_exact_physical_backing() {
        unsafe {
            let s = KERNEL.get();
            let kva = core::ptr::addr_of_mut!(DYNAMIC_SPEC_CNODE) as u64;
            let paddr = crate::arch::virt_to_phys(kva);
            let vi = s
                .alloc_dynamic_cnode(paddr, SMALL_CNODE_RADIX)
                .expect("dynamic descriptor");
            assert!(vi >= DYNAMIC_CNODE_BASE);
            assert_eq!(s.dynamic_cnode_backing(vi), Some((paddr, 2048)));
            let slots = s.cnode_slots_at_mut(vi).expect("dynamic slots");
            assert_eq!(slots.len(), SMALL_CNODE_SLOTS);
            slots[SMALL_CNODE_SLOTS - 1].set_cap(&Cap::Domain);
            assert!(matches!(
                DYNAMIC_SPEC_CNODE.0[SMALL_CNODE_SLOTS - 1].cap(),
                Cap::Domain
            ));
            let wide = crate::cte::MdbId::pack(1000, (1 << 19) + 7);
            assert_eq!(wide.cnode_idx(), 1000);
            assert_eq!(wide.slot(), (1 << 19) + 7);
            s.free_cnode_virt(vi);
            assert!(s.cnode_slots_at(vi).is_none());
            arch::log("  \u{2713} dynamic CNode uses exact Untyped-style physical backing\n");
        }
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
            assert!(
                vi >= MAX_CNODES,
                "small alloc returned virtual index {} (must be >= MAX_CNODES={})",
                vi,
                MAX_CNODES
            );
            assert!(vi < MAX_CNODES + MAX_SMALL_CNODES);
            // `cnode_slots_at` must dispatch to the small backing array
            // and surface SMALL_CNODE_SLOTS slots (not CNODE_SLOTS).
            let slots = s.cnode_slots_at(vi).expect("slots present");
            assert_eq!(
                slots.len(),
                SMALL_CNODE_SLOTS,
                "small pool slot dispatch wrong: got {} slots, expected {}",
                slots.len(),
                SMALL_CNODE_SLOTS
            );
            // PPtr round-trip: encoding a small virtual index and
            // decoding it must come back to the same virtual index.
            let ptr = KernelState::cnode_ptr(vi);
            assert_eq!(KernelState::cnode_index(ptr), vi);
            assert!(KernelState::is_small_cnode_idx(vi));
            s.free_small_cnode(vi);
            assert!(!s.small_cnode_in_use(vi - MAX_CNODES));
            arch::log("  \u{2713} small CNode pool alloc/free dispatch via virtual index\n");
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
            assert!(
                s.cnode_in_use(target),
                "claim_cnode should mark slot in-use"
            );
            assert!(
                s.next_cnode > target,
                "next_cnode should advance past a claimed slot"
            );
            // alloc_cnode must NOT now hand back our claimed slot.
            let alloced = s.alloc_cnode().expect("alloc_cnode");
            assert!(
                alloced != target,
                "alloc_cnode handed back our claimed slot {} (got {})",
                target,
                alloced
            );
            // Cleanup: free both back so other specs see the original
            // bookkeeping.
            s.free_cnode(alloced);
            if !was_in_use {
                s.free_cnode(target);
            }
            s.next_cnode = was_next;
            arch::log("  \u{2713} claim_cnode pins a directly-initialised CNode\n");
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
            assert!(
                id2 != current_thread().unwrap(),
                "second TCB should have a different id"
            );
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
