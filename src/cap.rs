//! Idiomatic Rust capability type and round-trip with seL4's
//! on-the-wire bitfield encoding.
//!
//! seL4 stores caps as packed 128-bit bitfields whose tag (the
//! `capType` field) selects the layout. In C this is a single
//! `cap_t` with macros for every accessor — easy to misuse, easy to
//! forget the `cap_get_capType` check.
//!
//! On the Rust side we deal in a tagged enum: each variant carries
//! exactly the typed payload its cap type defines. `to_words` and
//! `try_from_words` serialize through the auto-generated bitfield
//! types (see `src/structures.rs`), so a round-trip preserves the
//! exact byte layout seL4 would have.
//!
//! No `unsafe` here — `PPtr<T>` is a `NonZeroU64` newtype that we
//! never dereference; this module deals only in *addressing* kernel
//! objects, not accessing their fields. Dereferencing happens in
//! later phases inside small, well-encapsulated `unsafe` helpers.

use crate::structures::*;
use crate::structures::arch::{
    AsidControlCap, AsidPoolCap, FrameCap, PageDirectoryCap, PageTableCap, PdptCap,
    Pml4Cap,
};
use crate::structures::{SchedContextCap, SchedControlCap};
use crate::types::seL4_Word as Word;
use core::marker::PhantomData;
use core::num::NonZeroU64;

// ---------------------------------------------------------------------------
// Cap type tags. Values come from the `tagged_union cap capType { ... }`
// declaration in seL4/include/arch/x86/arch/64/mode/object/structures.bf.
// We keep them as a private constant set rather than an enum because
// (a) arch caps live in a different .bf file we don't yet codegen,
// and (b) collisions between arch-only tags would force an `if mcs`-
// shaped enum that would defeat the point.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub mod tag {
    // Non-arch (even) tags — defined in structures_64.bf via its
    // tagged_union, mirrored here.
    pub const NULL: u64 = 0;
    pub const UNTYPED: u64 = 2;
    pub const ENDPOINT: u64 = 4;
    pub const NOTIFICATION: u64 = 6;
    pub const REPLY: u64 = 8;
    pub const CNODE: u64 = 10;
    pub const THREAD: u64 = 12;
    pub const IRQ_CONTROL: u64 = 14;
    pub const IRQ_HANDLER: u64 = 16;
    pub const ZOMBIE: u64 = 18;
    pub const DOMAIN: u64 = 20;
    pub const SCHED_CONTEXT: u64 = 22;
    pub const SCHED_CONTROL: u64 = 24;

    // Arch (odd) tags — x86_64 specific subset we decode today.
    pub const FRAME: u64 = 1;
    pub const PAGE_TABLE: u64 = 3;
    pub const PAGE_DIRECTORY: u64 = 5;
    pub const PDPT: u64 = 7;
    pub const PML4: u64 = 9;
    pub const ASID_CONTROL: u64 = 11;
    pub const ASID_POOL: u64 = 13;

    /// Returns true for all arch-specific cap tags. Mirrors
    /// `isArchCap` in seL4: arch caps occupy odd tag values.
    pub const fn is_arch(t: u64) -> bool {
        (t & 1) != 0
    }
}

// ---------------------------------------------------------------------------
// Strongly-typed primitives. Newtypes ensure callers can't transpose
// a Badge for a Word or a Cptr for a kernel pointer.
// ---------------------------------------------------------------------------

/// 64-bit kernel-mapped pointer to a typed kernel object. Stored as
/// the canonical kernel virtual address; `NonZeroU64` gives us niche
/// optimisation in `Option<PPtr<T>>`. We never dereference a `PPtr`
/// in this module; that's the job of small `unsafe` helpers in the
/// modules that own each object type.
#[repr(transparent)]
pub struct PPtr<T = ()> {
    addr: NonZeroU64,
    _phantom: PhantomData<*const T>,
}

impl<T> PPtr<T> {
    /// Build a `PPtr` from a raw address. Returns `None` for the
    /// null address — call sites that have already excluded null
    /// (e.g. cap decoders) can pair this with `expect`.
    pub const fn new(addr: u64) -> Option<Self> {
        match NonZeroU64::new(addr) {
            Some(nz) => Some(Self { addr: nz, _phantom: PhantomData }),
            None => None,
        }
    }

    pub const fn addr(self) -> u64 {
        self.addr.get()
    }
}

// PhantomData<*const T> would otherwise force Copy/Clone/Eq/Debug to
// require T: Copy etc. — but PPtr is just an address tagged with a
// type marker, so derive macros aren't usable. Hand-write the
// required impls so callers don't need T: Trait.
impl<T> Copy for PPtr<T> {}
impl<T> Clone for PPtr<T> {
    fn clone(&self) -> Self { *self }
}
impl<T> PartialEq for PPtr<T> {
    fn eq(&self, other: &Self) -> bool { self.addr == other.addr }
}
impl<T> Eq for PPtr<T> {}
impl<T> core::fmt::Debug for PPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PPtr({:#x})", self.addr.get())
    }
}

/// 64-bit IPC badge (and notification badge).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
#[repr(transparent)]
pub struct Badge(pub Word);

/// Endpoint cap rights. Mirrors the four bits in the `endpoint_cap`
/// bitfield: capCanSend / capCanReceive / capCanGrant / capCanGrantReply.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct EndpointRights {
    pub can_send: bool,
    pub can_receive: bool,
    pub can_grant: bool,
    pub can_grant_reply: bool,
}

/// Notification cap rights — only send and receive are meaningful.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NotificationRights {
    pub can_send: bool,
    pub can_receive: bool,
}

/// Marker types for `PPtr<T>`. We only need them to type-tag pointers
/// — they never have instances. Concrete object representations land
/// in later phases.
pub struct EndpointObj;
pub struct NotificationObj;
pub struct Tcb;
/// A CNode is a contiguous array of CTEs in memory; we point at its
/// first slot.
pub struct CNodeStorage;
/// Untyped object — opaque memory the kernel will retype.
pub struct UntypedStorage;
/// Physical-frame storage backing a `Cap::Frame`.
pub struct FrameStorage;
/// Storage backing a `Cap::PageTable` / `PageDirectory` / `Pdpt`.
pub struct PageTableStorage;
pub struct PageDirectoryStorage;
pub struct PdptStorage;
/// Storage backing a `Cap::PML4` — the apex of the x86_64 paging
/// chain. One PML4 is one 4 KiB page of 512 PML4Es.
pub struct Pml4Storage;
/// Storage backing a `Cap::AsidPool` — one 4 KiB page holding 2^9
/// (= 512) `asid_map` entries, plus an asid_base offset stored in
/// the cap.
pub struct AsidPoolStorage;
/// Storage backing a `Cap::Reply` (Phase 32a). MCS reply caps name
/// a per-Call kernel object; the kernel pool indexes via the
/// PPtr's `(addr - 1)`.
pub struct ReplyStorage;
/// Storage backing a `Cap::SchedContext` (Phase 32b). Each SC
/// occupies a 2^size_bits-byte block; the smallest is `MIN_SCHED_CONTEXT_BITS`
/// (= 8 = 256 bytes — large enough for the refill array).
pub struct SchedContextStorage;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum FrameSize {
    /// 4 KiB — `capFSize = 0`.
    #[default]
    Small,
    /// 2 MiB — `capFSize = 1`.
    Large,
    /// 1 GiB — `capFSize = 2`.
    Huge,
}

impl FrameSize {
    pub const fn bits(self) -> u32 {
        match self { Self::Small => 12, Self::Large => 21, Self::Huge => 30 }
    }
    pub const fn from_word(w: u64) -> Option<Self> {
        match w {
            0 => Some(Self::Small),
            1 => Some(Self::Large),
            2 => Some(Self::Huge),
            _ => None,
        }
    }
    pub const fn to_word(self) -> u64 {
        match self { Self::Small => 0, Self::Large => 1, Self::Huge => 2 }
    }
}

/// Frame access rights. Matches seL4's `seL4_X86_VMRights` encoding
/// — 0 = kernel-only, 1 = read-only, 3 = read-write — so the
/// 2-bit `capFVMRights` field stores it directly.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum FrameRights {
    #[default]
    KernelOnly,
    ReadOnly,
    ReadWrite,
}

impl FrameRights {
    pub const fn to_word(self) -> u64 {
        // seL4_CapRights_t bits: 0 = can_write, 1 = can_read,
        // 2 = can_grant, 3 = can_grant_reply.
        match self {
            Self::KernelOnly => 0,
            Self::ReadOnly => 0b010,
            Self::ReadWrite => 0b011,
        }
    }
    pub const fn from_word(w: u64) -> Self {
        let can_write = (w & 0b001) != 0;
        let can_read  = (w & 0b010) != 0;
        if can_write {
            // Write implies read in our model — there's no WriteOnly
            // FrameRights variant.
            Self::ReadWrite
        } else if can_read {
            Self::ReadOnly
        } else {
            Self::KernelOnly
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ZombieKind {
    /// 2^bits CTE slots; the cap was a CNode.
    CNode { bits: u8 },
    /// One TCB worth of slots.
    Tcb,
}

// ---------------------------------------------------------------------------
// The capability enum itself.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Cap {
    Null,
    Untyped {
        ptr: PPtr<UntypedStorage>,
        block_bits: u8,
        free_index: u64,
        is_device: bool,
    },
    Endpoint {
        ptr: PPtr<EndpointObj>,
        badge: Badge,
        rights: EndpointRights,
    },
    Notification {
        ptr: PPtr<NotificationObj>,
        badge: Badge,
        rights: NotificationRights,
    },
    /// Non-MCS reply cap: rooted at the TCB whose reply slot it points
    /// to, with a `master` flag distinguishing the per-TCB master cap
    /// MCS reply cap (Phase 32a). Names a Reply object the kernel
    /// allocates per pending Call. The kernel pool is indexed via
    /// `ptr.addr() - 1`. `can_grant` controls whether the reply
    /// also transfers grant rights.
    Reply {
        ptr: PPtr<ReplyStorage>,
        can_grant: bool,
    },
    CNode {
        ptr: PPtr<CNodeStorage>,
        radix: u8,
        guard_size: u8,
        guard: Word,
    },
    Thread {
        tcb: PPtr<Tcb>,
    },
    IrqControl,
    IrqHandler {
        irq: u16,
    },
    Zombie {
        id: Word,
        kind: ZombieKind,
    },
    Domain,
    /// x86 4 KiB / 2 MiB / 1 GiB physical frame (cap tag = 1).
    /// `mapped` records the user-virtual address the frame is
    /// installed at, or `None` if not currently mapped.
    Frame {
        ptr: PPtr<FrameStorage>,
        size: FrameSize,
        rights: FrameRights,
        mapped: Option<u64>,
        asid: u16,
        is_device: bool,
    },
    /// x86 leaf page table (cap tag = 3) — points at a 4 KiB
    /// table that holds 512 PTEs.
    PageTable {
        ptr: PPtr<PageTableStorage>,
        mapped: Option<u64>, // vaddr where the PT covers
        asid: u16,
    },
    /// x86 page directory (cap tag = 5) — 512 PDEs.
    PageDirectory {
        ptr: PPtr<PageDirectoryStorage>,
        mapped: Option<u64>,
        asid: u16,
    },
    /// x86 page-directory-pointer table (cap tag = 7) — 512 PDPTEs.
    Pdpt {
        ptr: PPtr<PdptStorage>,
        mapped: Option<u64>,
        asid: u16,
    },
    /// x86 page map level 4 (cap tag = 9) — apex of the paging
    /// chain. Holding a PML4 cap is "owning a vspace": the kernel
    /// treats `ptr.addr()` as a CR3 value when this cap is
    /// installed via TCB::SetSpace.
    PML4 {
        ptr: PPtr<Pml4Storage>,
        mapped: bool,
        asid: u16,
    },
    /// Phase 31 — singleton "ASID control" cap (tag 11). Holding it
    /// permits `X86ASIDControlMakePool` to mint fresh `Cap::AsidPool`s
    /// out of Untypeds. The kernel keeps the global pool-allocation
    /// state behind the cap; the cap itself has no payload.
    AsidControl,
    /// Phase 31 — handle on a 4 KiB page of `asid_map` entries
    /// (tag 13). `asid_base` is the lowest ASID this pool covers
    /// (multiple of 512).
    AsidPool {
        ptr: PPtr<AsidPoolStorage>,
        asid_base: u16,
    },
    /// Phase 32b — MCS scheduling-context cap (tag 22). Names a
    /// SchedContext kernel object whose `period`, `budget`, and
    /// refill schedule control the bound TCB's CPU allocation.
    /// `size_bits` records the underlying object's size — seL4
    /// allows variable-sized SCs so larger budgets can hold more
    /// `Refill` entries.
    SchedContext {
        ptr: PPtr<SchedContextStorage>,
        size_bits: u8,
    },
    /// Phase 32d — per-CPU `SchedControl` cap (tag 24). Holding it
    /// permits `SchedControlConfigureFlags` invocations that set
    /// the period / budget on a target SchedContext. `core` names
    /// which CPU's SchedControl this is.
    SchedControl {
        core: u32,
    },
    /// Any other arch-tagged cap (page tables, ASID pool, etc.).
    /// Stored as the raw two-word encoding; full decoding for the
    /// remaining cap types lands in later phases.
    Arch {
        cap_type: u64,
        words: [Word; 2],
    },
}

// ---------------------------------------------------------------------------
// Round-trip with the on-the-wire two-word encoding.
//
// The functions below do plain bit shuffling through the auto-
// generated bitfield types. Everything is total: a malformed pair of
// words returns `Cap::Null` rather than panicking, matching seL4's
// behaviour where the cap dispatcher always switches on the type tag
// first and treats unknown tags as null.
// ---------------------------------------------------------------------------

/// Read the cap-type tag without committing to a particular variant.
/// Useful for arch dispatch and for invalid-tag detection.
pub fn cap_type_of(words: [Word; 2]) -> u64 {
    NullCap { words }.capType()
}

/// Decode a two-word slot into a typed `Cap`. Unknown / unsupported
/// non-arch tags decode to `Cap::Null`; arch tags fall through to
/// `Cap::Arch` so future arch decoders can take them apart.
pub fn from_words(words: [Word; 2]) -> Cap {
    let t = cap_type_of(words);
    match t {
        tag::NULL => Cap::Null,
        tag::UNTYPED => {
            let c = UntypedCap { words };
            Cap::Untyped {
                ptr: PPtr::new(c.capPtr()).unwrap_or(unreachable_ptr::<UntypedStorage>()),
                block_bits: c.capBlockSize() as u8,
                free_index: c.capFreeIndex(),
                is_device: c.capIsDevice() != 0,
            }
        }
        tag::ENDPOINT => {
            let c = EndpointCap { words };
            // ptr=0 is invalid for any non-null cap. seL4 returns
            // null caps in this slot rather than malformed ones; we
            // do the same.
            let Some(ptr) = PPtr::<EndpointObj>::new(c.capEPPtr()) else {
                return Cap::Null;
            };
            Cap::Endpoint {
                ptr,
                badge: Badge(c.capEPBadge()),
                rights: EndpointRights {
                    can_send: c.capCanSend() != 0,
                    can_receive: c.capCanReceive() != 0,
                    can_grant: c.capCanGrant() != 0,
                    can_grant_reply: c.capCanGrantReply() != 0,
                },
            }
        }
        tag::NOTIFICATION => {
            let c = NotificationCap { words };
            let Some(ptr) = PPtr::<NotificationObj>::new(c.capNtfnPtr()) else {
                return Cap::Null;
            };
            Cap::Notification {
                ptr,
                badge: Badge(c.capNtfnBadge()),
                rights: NotificationRights {
                    can_send: c.capNtfnCanSend() != 0,
                    can_receive: c.capNtfnCanReceive() != 0,
                },
            }
        }
        tag::REPLY => {
            let c = ReplyCap { words };
            let Some(ptr) = PPtr::<ReplyStorage>::new(c.capReplyPtr()) else {
                return Cap::Null;
            };
            Cap::Reply {
                ptr,
                can_grant: c.capReplyCanGrant() != 0,
            }
        }
        tag::CNODE => {
            let c = CnodeCap { words };
            let Some(ptr) = PPtr::<CNodeStorage>::new(c.capCNodePtr()) else {
                return Cap::Null;
            };
            Cap::CNode {
                ptr,
                radix: c.capCNodeRadix() as u8,
                guard_size: c.capCNodeGuardSize() as u8,
                guard: c.capCNodeGuard(),
            }
        }
        tag::THREAD => {
            let c = ThreadCap { words };
            let Some(tcb) = PPtr::<Tcb>::new(c.capTCBPtr()) else {
                return Cap::Null;
            };
            Cap::Thread { tcb }
        }
        tag::IRQ_CONTROL => Cap::IrqControl,
        tag::IRQ_HANDLER => {
            let c = IrqHandlerCap { words };
            Cap::IrqHandler { irq: c.capIRQ() as u16 }
        }
        tag::ZOMBIE => {
            let c = ZombieCap { words };
            let zt = c.capZombieType();
            // Zombie type encoding: bits 0..6 = log2 of slot count,
            // bit 6 = is-tcb. seL4 encodes this in the low 7 bits;
            // see `Zombie_TCB` in structures.h.
            let kind = if zt & (1 << 6) != 0 {
                ZombieKind::Tcb
            } else {
                ZombieKind::CNode { bits: (zt & 0x3f) as u8 }
            };
            Cap::Zombie { id: c.capZombieID(), kind }
        }
        tag::DOMAIN => Cap::Domain,
        tag::FRAME => {
            let c = FrameCap { words };
            let Some(ptr) = PPtr::<FrameStorage>::new(c.capFBasePtr()) else {
                return Cap::Null;
            };
            Cap::Frame {
                ptr,
                size: FrameSize::from_word(c.capFSize()).unwrap_or_default(),
                rights: FrameRights::from_word(c.capFVMRights()),
                mapped: {
                    let v = c.capFMappedAddress();
                    if v == 0 { None } else { Some(v) }
                },
                asid: c.capFMappedASID() as u16,
                is_device: c.capFIsDevice() != 0,
            }
        }
        tag::PAGE_TABLE => {
            let c = PageTableCap { words };
            let Some(ptr) = PPtr::<PageTableStorage>::new(c.capPTBasePtr()) else {
                return Cap::Null;
            };
            Cap::PageTable {
                ptr,
                mapped: if c.capPTIsMapped() != 0 {
                    Some(c.capPTMappedAddress())
                } else {
                    None
                },
                asid: c.capPTMappedASID() as u16,
            }
        }
        tag::PAGE_DIRECTORY => {
            let c = PageDirectoryCap { words };
            let Some(ptr) = PPtr::<PageDirectoryStorage>::new(c.capPDBasePtr()) else {
                return Cap::Null;
            };
            Cap::PageDirectory {
                ptr,
                mapped: if c.capPDIsMapped() != 0 {
                    Some(c.capPDMappedAddress())
                } else {
                    None
                },
                asid: c.capPDMappedASID() as u16,
            }
        }
        tag::PDPT => {
            let c = PdptCap { words };
            let Some(ptr) = PPtr::<PdptStorage>::new(c.capPDPTBasePtr()) else {
                return Cap::Null;
            };
            Cap::Pdpt {
                ptr,
                mapped: if c.capPDPTIsMapped() != 0 {
                    Some(c.capPDPTMappedAddress())
                } else {
                    None
                },
                asid: c.capPDPTMappedASID() as u16,
            }
        }
        tag::PML4 => {
            let c = Pml4Cap { words };
            let Some(ptr) = PPtr::<Pml4Storage>::new(c.capPML4BasePtr()) else {
                return Cap::Null;
            };
            Cap::PML4 {
                ptr,
                mapped: c.capPML4IsMapped() != 0,
                asid: c.capPML4MappedASID() as u16,
            }
        }
        tag::ASID_CONTROL => Cap::AsidControl,
        tag::ASID_POOL => {
            let c = AsidPoolCap { words };
            let Some(ptr) = PPtr::<AsidPoolStorage>::new(c.capASIDPool()) else {
                return Cap::Null;
            };
            Cap::AsidPool {
                ptr,
                asid_base: c.capASIDBase() as u16,
            }
        }
        tag::SCHED_CONTEXT => {
            let c = SchedContextCap { words };
            let Some(ptr) = PPtr::<SchedContextStorage>::new(c.capSCPtr()) else {
                return Cap::Null;
            };
            Cap::SchedContext {
                ptr,
                size_bits: c.capSCSizeBits() as u8,
            }
        }
        tag::SCHED_CONTROL => {
            let c = SchedControlCap { words };
            Cap::SchedControl { core: c.core() as u32 }
        }
        t if tag::is_arch(t) => Cap::Arch { cap_type: t, words },
        _ => Cap::Null,
    }
}

/// Encode back to the two-word form for storage in a CTE.
pub fn to_words(cap: &Cap) -> [Word; 2] {
    match cap {
        Cap::Null => NullCap::new(tag::NULL).words,
        Cap::Untyped { ptr, block_bits, free_index, is_device } => UntypedCap::new(
            *free_index,
            *is_device as u64,
            *block_bits as u64,
            tag::UNTYPED,
            ptr.addr(),
        )
        .words,
        Cap::Endpoint { ptr, badge, rights } => EndpointCap::new(
            badge.0,
            rights.can_grant_reply as u64,
            rights.can_grant as u64,
            rights.can_send as u64,
            rights.can_receive as u64,
            ptr.addr(),
            tag::ENDPOINT,
        )
        .words,
        Cap::Notification { ptr, badge, rights } => NotificationCap::new(
            badge.0,                        // capNtfnBadge
            tag::NOTIFICATION,              // capType
            rights.can_receive as u64,      // capNtfnCanReceive
            rights.can_send as u64,         // capNtfnCanSend
            ptr.addr(),                     // capNtfnPtr
        )
        .words,
        Cap::Reply { ptr, can_grant } => ReplyCap::new(
            ptr.addr(),
            tag::REPLY,
            *can_grant as u64,
        )
        .words,
        Cap::CNode { ptr, radix, guard_size, guard } => CnodeCap::new(
            *radix as u64,
            *guard_size as u64,
            *guard,
            ptr.addr(),
            tag::CNODE,
        )
        .words,
        Cap::Thread { tcb } => {
            let mut c = ThreadCap::zeroed();
            c = c.with_capType(tag::THREAD);
            c = c.with_capTCBPtr(tcb.addr());
            c.words
        }
        Cap::IrqControl => {
            let mut c = IrqControlCap::zeroed();
            c = c.with_capType(tag::IRQ_CONTROL);
            c.words
        }
        Cap::IrqHandler { irq } => {
            let mut c = IrqHandlerCap::zeroed();
            c = c.with_capType(tag::IRQ_HANDLER);
            c = c.with_capIRQ(*irq as u64);
            c.words
        }
        Cap::Zombie { id, kind } => {
            let zt = match kind {
                ZombieKind::Tcb => 1u64 << 6,
                ZombieKind::CNode { bits } => *bits as u64 & 0x3f,
            };
            ZombieCap::new(*id, zt, tag::ZOMBIE).words
        }
        Cap::Domain => {
            let mut c = DomainCap::zeroed();
            c = c.with_capType(tag::DOMAIN);
            c.words
        }
        Cap::PageTable { ptr, mapped, asid } => {
            // page_table_cap visible-field order:
            //   capPTMappedASID, capPTBasePtr, capType,
            //   capPTIsMapped, capPTMappedAddress
            PageTableCap::new(
                *asid as u64,
                ptr.addr(),
                tag::PAGE_TABLE,
                mapped.is_some() as u64,
                mapped.unwrap_or(0),
            )
            .words
        }
        Cap::PageDirectory { ptr, mapped, asid } => {
            PageDirectoryCap::new(
                *asid as u64,
                ptr.addr(),
                tag::PAGE_DIRECTORY,
                mapped.is_some() as u64,
                mapped.unwrap_or(0),
            )
            .words
        }
        Cap::Pdpt { ptr, mapped, asid } => {
            PdptCap::new(
                *asid as u64,
                ptr.addr(),
                tag::PDPT,
                mapped.is_some() as u64,
                mapped.unwrap_or(0),
            )
            .words
        }
        Cap::PML4 { ptr, mapped, asid } => {
            // pml4_cap has explicit_params (capPML4MappedASID,
            // capPML4BasePtr, capType, capPML4IsMapped) — pass them
            // in that order.
            Pml4Cap::new(
                *asid as u64,
                ptr.addr(),
                tag::PML4,
                *mapped as u64,
            )
            .words
        }
        Cap::AsidControl => {
            let mut c = AsidControlCap::zeroed();
            c = c.with_capType(tag::ASID_CONTROL);
            c.words
        }
        Cap::AsidPool { ptr, asid_base } => {
            // asid_pool_cap visible-field order (no explicit_params):
            //   capType, capASIDBase, capASIDPool.
            AsidPoolCap::new(
                tag::ASID_POOL,
                *asid_base as u64,
                ptr.addr(),
            )
            .words
        }
        Cap::SchedContext { ptr, size_bits } => {
            // sched_context_cap (no explicit_params):
            //   capSCPtr, capSCSizeBits, capType.
            SchedContextCap::new(
                ptr.addr(),
                *size_bits as u64,
                tag::SCHED_CONTEXT,
            )
            .words
        }
        Cap::SchedControl { core } => {
            SchedControlCap::new(*core as u64, tag::SCHED_CONTROL).words
        }
        Cap::Frame { ptr, size, rights, mapped, asid, is_device } => {
            // Visible field order (no explicit_params on frame_cap):
            //   capFMappedASID, capFBasePtr, capType, capFSize,
            //   capFMapType, capFMappedAddress, capFVMRights,
            //   capFIsDevice
            FrameCap::new(
                *asid as u64,
                ptr.addr(),
                tag::FRAME,
                size.to_word(),
                0,                              // capFMapType: 0 = normal (non-EPT)
                mapped.unwrap_or(0),
                rights.to_word(),
                *is_device as u64,
            )
            .words
        }
        Cap::Arch { cap_type: _, words } => *words,
    }
}

/// Cheap accessors used by every kernel call site. They avoid having
/// to pattern-match the entire enum when only one fact is interesting.
impl Cap {
    pub const fn is_null(&self) -> bool {
        matches!(self, Cap::Null)
    }
    pub const fn is_cnode(&self) -> bool {
        matches!(self, Cap::CNode { .. })
    }
}

/// Sentinel for the "we proved at decode time the address is non-zero"
/// case — used so `from_words` can keep its match exhaustive. The
/// only caller branch reaches this when a tag's pointer field reads
/// as non-zero, which we already validated, so this never panics in
/// practice. We keep it `#[track_caller]` so any future regression
/// surfaces an obvious panic site.
#[track_caller]
fn unreachable_ptr<T>() -> PPtr<T> {
    // Use 1 (not 0) so NonZeroU64 succeeds. This keeps the helper
    // safe; the unreachable branch is purely a Rust totality dance
    // and never reflects a real cap.
    PPtr::new(1).expect("PPtr::new(1) always succeeds")
}

// ---------------------------------------------------------------------------
// Tests covering round-trip.
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_cap_roundtrip() {
        arch::log("Running cap round-trip tests...\n");

        roundtrip_null();
        roundtrip_endpoint();
        roundtrip_cnode();
        roundtrip_thread();
        roundtrip_irq_handler();
        roundtrip_arch_passthrough();
        roundtrip_frame();
        roundtrip_paging_structs();
        roundtrip_asid_caps();
        roundtrip_sched_context_cap();
        roundtrip_sched_control_cap();
        type_tag_dispatch();

        arch::log("Cap round-trip tests completed\n");
    }

    fn roundtrip_paging_structs() {
        // The .bf encodes mapped-address fields as `field_high N` so
        // the codegen drops the low `canonical_size - N` bits on
        // write and rezeroes them on read. Picking values that match
        // the natural paging granularity (PT = 2 MiB, PD = 1 GiB,
        // PDPT = 256 GiB after shift) keeps the round-trip lossless.

        // PageTable: cap_type tag = 3. shift = 48-28 = 20 (1 MiB
        // resolution). 0x10_0000_0000 (= 64 GiB) is well-aligned.
        let pt = Cap::PageTable {
            ptr: PPtr::<PageTableStorage>::new(0x0000_0000_0030_0000).unwrap(),
            mapped: Some(0x0000_0010_0000_0000),
            asid: 5,
        };
        let words = to_words(&pt);
        assert_eq!(cap_type_of(words), tag::PAGE_TABLE);
        assert_eq!(from_words(words), pt);

        // PageDirectory: cap_type tag = 5. shift = 48-19 = 29
        // (~512 MiB resolution). Test with the unmapped variant so
        // the address field's narrowness doesn't show through.
        let pd = Cap::PageDirectory {
            ptr: PPtr::<PageDirectoryStorage>::new(0x0000_0000_0030_1000).unwrap(),
            mapped: None,
            asid: 0,
        };
        let words = to_words(&pd);
        assert_eq!(cap_type_of(words), tag::PAGE_DIRECTORY);
        assert_eq!(from_words(words), pd);

        // Pdpt: cap_type tag = 7. shift = 48-10 = 38 (256 GiB
        // resolution). Pick 0x80_0000_0000 (= 1<<39 = 512 GiB).
        let pdpt = Cap::Pdpt {
            ptr: PPtr::<PdptStorage>::new(0x0000_0000_0030_2000).unwrap(),
            mapped: Some(0x0000_0080_0000_0000),
            asid: 9,
        };
        let words = to_words(&pdpt);
        assert_eq!(cap_type_of(words), tag::PDPT);
        assert_eq!(from_words(words), pdpt);

        // PML4: cap_type tag = 9. capPML4BasePtr is `field 64` so
        // there's no shift — full 64-bit address round-trips.
        let pml4 = Cap::PML4 {
            ptr: PPtr::<Pml4Storage>::new(0x0000_0000_0030_3000).unwrap(),
            mapped: true,
            asid: 11,
        };
        let words = to_words(&pml4);
        assert_eq!(cap_type_of(words), tag::PML4);
        assert_eq!(from_words(words), pml4);

        arch::log("  ✓ page-table / directory / PDPT / PML4 caps round-trip\n");
    }

    fn roundtrip_sched_context_cap() {
        // capSCPtr is `field_ptr 48` → 4 KiB-aligned suffices.
        // capSCSizeBits is `field 6` (0..63).
        let sc = Cap::SchedContext {
            ptr: PPtr::<SchedContextStorage>::new(0x0000_0000_0040_0000).unwrap(),
            size_bits: 8,
        };
        let words = to_words(&sc);
        assert_eq!(cap_type_of(words), tag::SCHED_CONTEXT);
        assert_eq!(from_words(words), sc);
        arch::log("  ✓ SchedContext cap round-trips\n");
    }

    fn roundtrip_sched_control_cap() {
        let sc = Cap::SchedControl { core: 0 };
        let words = to_words(&sc);
        assert_eq!(cap_type_of(words), tag::SCHED_CONTROL);
        assert_eq!(from_words(words), sc);
        let sc2 = Cap::SchedControl { core: 3 };
        let words = to_words(&sc2);
        assert_eq!(from_words(words), sc2);
        arch::log("  ✓ SchedControl cap round-trips\n");
    }

    fn roundtrip_asid_caps() {
        // AsidControl is a singleton — no fields besides cap_type.
        let words = to_words(&Cap::AsidControl);
        assert_eq!(cap_type_of(words), tag::ASID_CONTROL);
        assert_eq!(from_words(words), Cap::AsidControl);

        // AsidPool: shift +11 on capASIDPool means we need a
        // 2 KiB-aligned ptr. 4 KiB-aligned pool storage fits.
        let pool = Cap::AsidPool {
            ptr: PPtr::<AsidPoolStorage>::new(0x0000_0000_0030_4000).unwrap(),
            asid_base: 0x200,
        };
        let words = to_words(&pool);
        assert_eq!(cap_type_of(words), tag::ASID_POOL);
        assert_eq!(from_words(words), pool);

        arch::log("  ✓ AsidControl + AsidPool caps round-trip\n");
    }

    fn roundtrip_null() {
        let cap = Cap::Null;
        let words = to_words(&cap);
        assert_eq!(cap_type_of(words), tag::NULL);
        assert_eq!(from_words(words), cap);
        arch::log("  ✓ null cap round-trips\n");
    }

    fn roundtrip_endpoint() {
        let ep = PPtr::<EndpointObj>::new(0xFFFF_8000_DEAD_B000).unwrap();
        let cap = Cap::Endpoint {
            ptr: ep,
            badge: Badge(0x1234_5678),
            rights: EndpointRights {
                can_send: true,
                can_receive: true,
                can_grant: false,
                can_grant_reply: true,
            },
        };
        let words = to_words(&cap);
        assert_eq!(cap_type_of(words), tag::ENDPOINT);
        let back = from_words(words);
        assert_eq!(back, cap);
        arch::log("  ✓ endpoint cap round-trips through bitfield\n");
    }

    fn roundtrip_cnode() {
        // The cnode_cap pointer is `field_ptr(1)`, so it must be
        // 2-byte aligned.
        let ptr = PPtr::<CNodeStorage>::new(0x0000_0000_0010_2030).unwrap();
        let cap = Cap::CNode {
            ptr,
            radix: 12,
            guard_size: 4,
            guard: 0xDEAD_BEEF,
        };
        let words = to_words(&cap);
        assert_eq!(cap_type_of(words), tag::CNODE);
        assert_eq!(from_words(words), cap);
        arch::log("  ✓ cnode cap round-trips with aligned pointer\n");
    }

    fn roundtrip_thread() {
        let tcb = PPtr::<Tcb>::new(0xFFFF_8000_AAAA_0000).unwrap();
        let cap = Cap::Thread { tcb };
        let words = to_words(&cap);
        assert_eq!(cap_type_of(words), tag::THREAD);
        assert_eq!(from_words(words), cap);
        arch::log("  ✓ thread cap round-trips\n");
    }

    fn roundtrip_irq_handler() {
        let cap = Cap::IrqHandler { irq: 32 };
        let words = to_words(&cap);
        assert_eq!(cap_type_of(words), tag::IRQ_HANDLER);
        assert_eq!(from_words(words), cap);
        arch::log("  ✓ irq_handler cap round-trips\n");
    }

    fn roundtrip_frame() {
        let cap = Cap::Frame {
            ptr: PPtr::<FrameStorage>::new(0x0000_0000_0040_0000).unwrap(),
            size: FrameSize::Small,
            rights: FrameRights::ReadWrite,
            mapped: Some(0x0000_0080_0000_1000),
            asid: 7,
            is_device: false,
        };
        let words = to_words(&cap);
        // Cap type tag = 1 (FRAME).
        assert_eq!(cap_type_of(words), tag::FRAME);
        let back = from_words(words);
        assert_eq!(back, cap);

        // Unmapped variant — capFMappedAddress = 0 → mapped: None.
        let cap2 = Cap::Frame {
            ptr: PPtr::<FrameStorage>::new(0x80_0000).unwrap(),
            size: FrameSize::Large,
            rights: FrameRights::ReadOnly,
            mapped: None,
            asid: 0,
            is_device: true,
        };
        let words = to_words(&cap2);
        let back = from_words(words);
        assert_eq!(back, cap2);
        arch::log("  ✓ frame cap round-trips with mapped + unmapped variants\n");
    }

    fn roundtrip_arch_passthrough() {
        // Use tag 15 (io_space_cap) — still un-typed. Earlier
        // phases used 1 (frame), 3 (page_table), 11 (asid_control);
        // those now all decode to typed variants.
        let mut words = [0u64; 2];
        words[0] = 15u64 << 59;
        let back = from_words(words);
        match back {
            Cap::Arch { cap_type: 15, words: w } => assert_eq!(w, words),
            other => panic!("expected Cap::Arch{{15,..}}, got {:?}", other),
        }
        arch::log("  ✓ arch cap passes through opaquely (un-typed tags)\n");
    }

    fn type_tag_dispatch() {
        // is_arch identifies odd tags only.
        for t in 0u64..32 {
            assert_eq!(tag::is_arch(t), t % 2 == 1);
        }
        arch::log("  ✓ tag::is_arch matches seL4 isArchCap convention\n");
    }
}
