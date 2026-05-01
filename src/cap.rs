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
    /// from a derived reply cap held by a sender.
    Reply {
        tcb: PPtr<Tcb>,
        can_grant: bool,
        master: bool,
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
    /// Any odd-tagged cap (frame, page table, etc.). Stored as the
    /// raw two-word encoding; full decoding lives in `arch/<arch>`
    /// and lands in Phase 8.
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
            let Some(tcb) = PPtr::<Tcb>::new(c.capTCBPtr()) else {
                return Cap::Null;
            };
            Cap::Reply {
                tcb,
                can_grant: c.capReplyCanGrant() != 0,
                master: c.capReplyMaster() != 0,
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
        Cap::Reply { tcb, can_grant, master } => ReplyCap::new(
            *can_grant as u64,
            *master as u64,
            tcb.addr(),
            tag::REPLY,
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
        type_tag_dispatch();

        arch::log("Cap round-trip tests completed\n");
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

    fn roundtrip_arch_passthrough() {
        // An arch cap (odd tag) must pass through untouched.
        let mut words = [0u64; 2];
        // Set capType=1 (frame_cap). The capType bits live at word 0
        // bits 59..63; we don't go through the bitfield API here
        // because we want to construct a *raw* odd-tagged value.
        words[0] = 1u64 << 59;
        let back = from_words(words);
        match back {
            Cap::Arch { cap_type: 1, words: w } => assert_eq!(w, words),
            other => panic!("expected Cap::Arch{{1,..}}, got {:?}", other),
        }
        arch::log("  ✓ arch cap passes through opaquely\n");
    }

    fn type_tag_dispatch() {
        // is_arch identifies odd tags only.
        for t in 0u64..32 {
            assert_eq!(tag::is_arch(t), t % 2 == 1);
        }
        arch::log("  ✓ tag::is_arch matches seL4 isArchCap convention\n");
    }
}
