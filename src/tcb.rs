//! Thread Control Block — kernel-side state of a single thread.
//!
//! Mirrors `seL4/include/object/structures.h::tcb_t` (the
//! arch-independent fields). This phase keeps the struct simple
//! enough that the scheduler can act on it; arch register state,
//! IPC buffer pointer, and the bound-notification linkage land in
//! later phases as those features come online.
//!
//! TCBs live in a fixed-size slab (`TcbSlab` below). Every reference
//! into the slab is by `TcbId` rather than raw pointer — that lets
//! us implement intrusive scheduler links without `unsafe` and
//! without lifetime gymnastics. In the production kernel a TCB
//! lives at a fixed kernel-half address and is reachable via a
//! `PPtr<Tcb>`; bridging the two representations is the job of a
//! tiny `unsafe` accessor in a later phase.

use crate::region::align_up;
use crate::types::seL4_Word as Word;

// ---------------------------------------------------------------------------
// Discriminants must match `enum _thread_state` in
// seL4/include/object/structures.h byte-for-byte so the values we
// store in the `ThreadState` bitfield match what userspace
// introspection expects.
// ---------------------------------------------------------------------------

#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum ThreadStateType {
    #[default]
    Inactive = 0,
    Running = 1,
    Restart = 2,
    BlockedOnReceive = 3,
    BlockedOnSend = 4,
    BlockedOnReply = 5,
    BlockedOnNotification = 6,
    /// VTX-only — kept here so the discriminant matches seL4 even
    /// though we never enter this state without VT-x support.
    RunningVM = 7,
    Idle = 8,
}

impl ThreadStateType {
    /// True if this thread is eligible to run on the CPU. The
    /// scheduler only enqueues threads whose state is runnable.
    pub const fn is_runnable(self) -> bool {
        matches!(self, ThreadStateType::Running | ThreadStateType::Restart)
    }

    pub const fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Inactive),
            1 => Some(Self::Running),
            2 => Some(Self::Restart),
            3 => Some(Self::BlockedOnReceive),
            4 => Some(Self::BlockedOnSend),
            5 => Some(Self::BlockedOnReply),
            6 => Some(Self::BlockedOnNotification),
            7 => Some(Self::RunningVM),
            8 => Some(Self::Idle),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TcbId — slab index. Deliberately small (u16) so `Option<TcbId>` is
// 4 bytes via niche optimisation only when wrapped manually; we keep
// the explicit `Option<TcbId>` form for clarity.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
#[repr(transparent)]
pub struct TcbId(pub u16);

impl TcbId {
    pub const fn raw(self) -> u16 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// The TCB itself. Fields are public so the scheduler / IPC paths can
// mutate them directly; we don't hide behind setters because every
// kernel module is part of the same trust boundary.
// ---------------------------------------------------------------------------

pub const NUM_PRIORITIES: usize = 256;
pub const MAX_PRIORITY: u8 = (NUM_PRIORITIES - 1) as u8;

/// Maximum number of message-register words we model in this phase.
/// seL4's `seL4_MsgMaxLength` is 120 — we keep the full ABI value as
/// a constant in `types.rs` but cap the in-kernel staging buffer to
/// keep TCB size sane during specs. Production TCB stores the full
/// register set in arch-side `tcbContext` instead.
pub const SCRATCH_MSG_LEN: usize = 8;

/// Per-TCB kernel stack size. seL4 uses 4 KiB; we match that.
pub const KERNEL_STACK_BYTES: usize = 4096;

/// Architecture-private CPU context. Mirrors `tcbContext` in seL4.
/// On x86_64 we store the kernel stack pointer (used by the
/// switch_context primitive in `arch::x86_64::context`) and the
/// CR3 the thread runs against.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct CpuContext {
    /// Kernel-stack pointer at the moment this thread was last
    /// switched out. The switch primitive saves callee-saved
    /// registers onto the stack first; reading the regs back is
    /// implicit in `pop` after the swap.
    pub ksp: u64,
    /// Page-table root the CPU loads when this thread is scheduled
    /// (CR3 on x86_64). Zero means "no per-thread vspace, keep
    /// whatever's loaded".
    pub cr3: u64,
}

#[derive(Copy, Clone, Debug)]
pub struct Tcb {
    pub state: ThreadStateType,
    /// Priority used for scheduling decisions. 0..255.
    pub priority: u8,
    /// Maximum-controllable-priority — caps what one thread can
    /// raise another's priority to via `TCB::SetPriority`. Mirrors
    /// `tcbMCP` in seL4.
    pub mcp: u8,
    /// Single domain only for now. `tcbDomain` in seL4.
    pub domain: u8,
    /// Remaining timeslice in scheduler ticks (non-MCS).
    pub time_slice: u32,
    /// Fault handler CPtr. 0 = no handler.
    pub fault_handler: Word,
    /// User-mode IPC-buffer virtual address.
    pub ipc_buffer: Word,
    /// Intrusive scheduler-list links. `None` for a thread that
    /// isn't currently enqueued.
    pub sched_next: Option<TcbId>,
    pub sched_prev: Option<TcbId>,
    /// Intrusive endpoint-queue links. Used while the thread is
    /// blocked on an Endpoint or Notification. `None` when not
    /// queued. Mirrors `tcbEPNext` / `tcbEPPrev` in seL4.
    pub ep_next: Option<TcbId>,
    pub ep_prev: Option<TcbId>,
    /// Message info for the in-flight IPC (label / length / extra
    /// caps). Set on send-side, read on receive-side.
    pub ipc_label: Word,
    pub ipc_length: u32,
    /// Tiny in-kernel message register buffer. Long messages use the
    /// per-thread IPC buffer page (mapped at `ipc_buffer`); the
    /// short fast-path uses just these registers. Staged here so
    /// specs can verify the byte-by-byte transfer without setting up
    /// real virtual memory.
    pub msg_regs: [Word; SCRATCH_MSG_LEN],
    /// IPC badge stamped onto the message during a badged-send. The
    /// receiver reads it as the seL4 `badge` syscall return.
    pub ipc_badge: Word,
    /// Architecture context for context-switching.
    pub cpu_context: CpuContext,
    /// Root of this thread's CSpace. Must be `Cap::CNode` for any
    /// invocation that does cap lookup; defaults to `Cap::Null` for
    /// boot threads that haven't been wired up yet.
    pub cspace_root: crate::cap::Cap,
    /// Saved user-mode register state for SYSCALL/SYSRET. The
    /// arch-specific syscall dispatcher copies the in-flight
    /// SYSCALL_SAVE area into here on entry and back out before
    /// sysretq, so each thread's user state survives across
    /// schedule() calls.
    #[cfg(target_arch = "x86_64")]
    pub user_context: crate::arch::x86_64::syscall_entry::UserContext,
    /// Phase 15b — non-MCS reply tracking. When this thread is on
    /// the receive side of a Call, `reply_to` holds the TCB of the
    /// caller that's waiting for SysReply. seL4 calls this
    /// `tcbCaller` and stores it in a dedicated CSpace slot;
    /// we keep it as a direct TcbId to skip the cap-derivation
    /// dance (added later in Phase 17).
    pub reply_to: Option<TcbId>,
    /// Phase 20 — VSpace root cap (set via TCB::SetSpace).
    /// Currently opaque (stored but not consulted) since we run
    /// every thread in the shared kernel page tables; per-thread
    /// CR3 lands when ASID management does.
    pub vspace_root: crate::cap::Cap,
    /// Phase 20 — bound notification slot index (within the
    /// kernel notification pool). `None` if not bound.
    /// (`fault_handler` cptr already exists above.)
    pub bound_notification: Option<u16>,
}

impl Default for Tcb {
    fn default() -> Self {
        Self {
            state: ThreadStateType::Inactive,
            priority: 0,
            mcp: 0,
            domain: 0,
            time_slice: 0,
            fault_handler: 0,
            ipc_buffer: 0,
            sched_next: None,
            sched_prev: None,
            ep_next: None,
            ep_prev: None,
            ipc_label: 0,
            ipc_length: 0,
            msg_regs: [0; SCRATCH_MSG_LEN],
            ipc_badge: 0,
            cpu_context: CpuContext { ksp: 0, cr3: 0 },
            cspace_root: crate::cap::Cap::Null,
            #[cfg(target_arch = "x86_64")]
            user_context:
                crate::arch::x86_64::syscall_entry::UserContext::new_zero(),
            reply_to: None,
            vspace_root: crate::cap::Cap::Null,
            bound_notification: None,
        }
    }
}

impl Tcb {
    pub const fn is_runnable(&self) -> bool {
        self.state.is_runnable()
    }
}

// ---------------------------------------------------------------------------
// Slab — fixed-size pool of TCBs addressed by `TcbId`.
// ---------------------------------------------------------------------------

/// Maximum live TCBs in the kernel. Picks a small bound so the
/// slab is BSS-allocatable without alloc() and a `Scheduler` value
/// fits on a 16 KiB BOOTBOOT stack with margin. Production seL4
/// uses real Untyped retypes for TCBs and there is no upper bound;
/// raising this here costs ~128 bytes per TCB in BSS plus stack
/// when a Scheduler is constructed in a spec, so we keep it modest
/// until phases that actually need more.
pub const MAX_TCBS: usize = 16;

#[derive(Copy, Clone, Debug)]
pub struct TcbSlab {
    pub entries: [Option<Tcb>; MAX_TCBS],
}

impl TcbSlab {
    pub const fn new() -> Self {
        Self { entries: [None; MAX_TCBS] }
    }

    /// Insert a TCB at the next free slot. Returns the assigned id,
    /// or `None` if the slab is full.
    pub fn alloc(&mut self, tcb: Tcb) -> Option<TcbId> {
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(tcb);
                return Some(TcbId(i as u16));
            }
        }
        None
    }

    pub fn get(&self, id: TcbId) -> &Tcb {
        self.entries[id.0 as usize]
            .as_ref()
            .expect("TcbSlab::get on empty slot")
    }

    pub fn get_mut(&mut self, id: TcbId) -> &mut Tcb {
        self.entries[id.0 as usize]
            .as_mut()
            .expect("TcbSlab::get_mut on empty slot")
    }

    pub fn free(&mut self, id: TcbId) {
        self.entries[id.0 as usize] = None;
    }
}

// ---------------------------------------------------------------------------
// Helpers shared with the scheduler.
// ---------------------------------------------------------------------------

/// Round a virtual address up to the natural alignment of a TCB
/// block (`1 << TCB_SIZE_BITS` bytes). Used by the boot/rootserver
/// placement code in a later phase.
pub fn tcb_align_up(addr: Word) -> Word {
    align_up(addr, crate::object_type::TCB_SIZE_BITS)
}

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_tcb() {
        arch::log("Running TCB tests...\n");
        thread_state_runnable();
        slab_alloc_get_free();
        arch::log("TCB tests completed\n");
    }

    fn thread_state_runnable() {
        assert!(ThreadStateType::Running.is_runnable());
        assert!(ThreadStateType::Restart.is_runnable());
        assert!(!ThreadStateType::Inactive.is_runnable());
        assert!(!ThreadStateType::BlockedOnReceive.is_runnable());
        assert!(!ThreadStateType::BlockedOnNotification.is_runnable());
        assert!(!ThreadStateType::Idle.is_runnable());
        // from_u64 rejects out-of-range.
        assert_eq!(ThreadStateType::from_u64(99), None);
        // and accepts every valid discriminant.
        for v in 0u64..=8 {
            assert!(ThreadStateType::from_u64(v).is_some());
        }
        arch::log("  ✓ thread state runnability matches seL4 convention\n");
    }

    fn slab_alloc_get_free() {
        let mut slab = TcbSlab::new();
        let mut tcb = Tcb::default();
        tcb.priority = 42;
        tcb.state = ThreadStateType::Running;
        let id = slab.alloc(tcb).unwrap();
        assert_eq!(id, TcbId(0));
        assert_eq!(slab.get(id).priority, 42);
        slab.get_mut(id).priority = 99;
        assert_eq!(slab.get(id).priority, 99);
        slab.free(id);
        // After free, the slot is empty and re-allocation reuses it.
        let id2 = slab.alloc(Tcb::default()).unwrap();
        assert_eq!(id2, TcbId(0));
        arch::log("  ✓ TcbSlab alloc / get_mut / free\n");
    }
}
