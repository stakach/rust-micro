//! Public seL4 ABI types — what userspace sees.
//!
//! Every type in this module is layout-locked: a Rust struct here
//! must match the corresponding C type in `seL4/libsel4/include/sel4/`
//! byte-for-byte. The `spec/abi_layout_tests.rs` spec asserts this at
//! boot via `core::mem::size_of` / `align_of` / `offset_of!`.
//!
//! Naming: we keep seL4's `seL4_Foo` casing on every public type so a
//! user binary written in C can be ported across without renaming. We
//! relax that for types that are already idiomatic Rust on the kernel
//! side (e.g. error codes, where we expose a `KError` newtype later).

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// ---------------------------------------------------------------------------
// Word-sized aliases. seL4_Word is the native machine word.
// ---------------------------------------------------------------------------

pub type seL4_Word = u64;
pub type seL4_CPtr = seL4_Word;
pub type seL4_NodeId = seL4_Word;
pub type seL4_PAddr = seL4_Word;
pub type seL4_Domain = seL4_Word;
pub type seL4_SlotPos = seL4_Word;
pub type seL4_Uint8 = u8;
pub type seL4_Uint16 = u16;
pub type seL4_Uint32 = u32;
pub type seL4_Uint64 = u64;

// ---------------------------------------------------------------------------
// Constants. These are the values shipped by libsel4 for x86_64 with
// the default config.cmake — the rest of the kernel and the spec
// suite assume them.
// ---------------------------------------------------------------------------

pub const seL4_WordBits: usize = 64;
pub const seL4_PageBits: usize = 12;
pub const seL4_PageSize: usize = 1 << seL4_PageBits;

pub const seL4_MsgLengthBits: usize = 7;
pub const seL4_MsgExtraCapBits: usize = 2;
pub const seL4_MsgMaxLength: usize = 120;
pub const seL4_MsgMaxExtraCaps: usize = (1 << seL4_MsgExtraCapBits) - 1;

pub const seL4_CapRightsBits: usize = 4;

/// Default from `config.cmake` (`KernelMaxNumBootinfoUntypedCaps`).
pub const CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS: usize = 230;

/// Default from `config.cmake` (`KernelNumPriorities`).
pub const CONFIG_NUM_PRIORITIES: usize = 256;

// ---------------------------------------------------------------------------
// Slot positions in the root CNode the boot phase hands the initial
// thread.
// ---------------------------------------------------------------------------

#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum seL4_RootCNodeCapSlots {
    seL4_CapNull = 0,
    seL4_CapInitThreadTCB = 1,
    seL4_CapInitThreadCNode = 2,
    seL4_CapInitThreadVSpace = 3,
    seL4_CapIRQControl = 4,
    seL4_CapASIDControl = 5,
    seL4_CapInitThreadASIDPool = 6,
    seL4_CapIOPortControl = 7,
    seL4_CapIOSpace = 8,
    seL4_CapBootInfoFrame = 9,
    seL4_CapInitThreadIPCBuffer = 10,
    seL4_CapDomain = 11,
    seL4_CapSMMUSIDControl = 12,
    seL4_CapSMMUCBControl = 13,
    seL4_CapInitThreadSC = 14,
    seL4_CapSMC = 15,
    seL4_NumInitialCaps = 16,
}

// ---------------------------------------------------------------------------
// User-visible object types. The MCS-only variants are kept in the
// enum (with explicit discriminants) so we don't shift the tags when
// MCS is disabled — that would be an ABI break.
// ---------------------------------------------------------------------------

#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum seL4_ObjectType {
    seL4_UntypedObject = 0,
    seL4_TCBObject = 1,
    seL4_EndpointObject = 2,
    seL4_NotificationObject = 3,
    seL4_CapTableObject = 4,
    /// MCS-only. Reserved here so the enum discriminants are stable
    /// regardless of build configuration.
    seL4_SchedContextObject = 5,
    /// MCS-only.
    seL4_ReplyObject = 6,
    /// First arch-specific tag; subclasses live in the `arch` module.
    seL4_NonArchObjectTypeCount = 7,
}

// ---------------------------------------------------------------------------
// Errors and lookup-failure types. These appear in the message
// register layout returned to userspace on a syscall error.
// ---------------------------------------------------------------------------

#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum seL4_Error {
    seL4_NoError = 0,
    seL4_InvalidArgument = 1,
    seL4_InvalidCapability = 2,
    seL4_IllegalOperation = 3,
    seL4_RangeError = 4,
    seL4_AlignmentError = 5,
    seL4_FailedLookup = 6,
    seL4_TruncatedMessage = 7,
    seL4_DeleteFirst = 8,
    seL4_RevokeFirst = 9,
    seL4_NotEnoughMemory = 10,
    seL4_NumErrors = 11,
}

#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum seL4_LookupFailureType {
    seL4_NoFailure = 0,
    seL4_InvalidRoot = 1,
    seL4_MissingCapability = 2,
    seL4_DepthMismatch = 3,
    seL4_GuardMismatch = 4,
}

// ---------------------------------------------------------------------------
// CapFault message register layout.
// ---------------------------------------------------------------------------

#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum seL4_CapFault_Msg {
    seL4_CapFault_IP = 0,
    seL4_CapFault_Addr = 1,
    seL4_CapFault_InRecvPhase = 2,
    seL4_CapFault_LookupFailureType = 3,
    seL4_CapFault_BitsLeft = 4,
    seL4_CapFault_DepthMismatch_BitsFound = 5,
    /// Aliased with `..._DepthMismatch_BitsFound` in C; preserved as
    /// a `const` rather than another enum variant since a Rust enum
    /// cannot have two variants with the same discriminant.
    seL4_CapFault_GuardMismatch_BitsFound = 6,
}

pub const seL4_CapFault_GuardMismatch_GuardFound: u64 =
    seL4_CapFault_Msg::seL4_CapFault_DepthMismatch_BitsFound as u64;

// ---------------------------------------------------------------------------
// Message info, slot region, untyped descriptor, boot info frame.
// ---------------------------------------------------------------------------

/// Tag word at the start of every IPC. seL4 packs label, capsUnwrapped,
/// extraCaps, and length into a single 64-bit word.
///
/// We keep the storage as a single `seL4_Word` (matching the C
/// `seL4_MessageInfo_t { seL4_Word words[1]; }` layout) and expose
/// typed accessors. Bit positions match libsel4's bitfield definition
/// exactly (label at the top, length at the bottom).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct seL4_MessageInfo_t {
    pub words: [seL4_Word; 1],
}

impl seL4_MessageInfo_t {
    /// Build a fresh tag. Argument names follow libsel4.
    pub const fn new(label: u64, caps_unwrapped: u64, extra_caps: u64, length: u64) -> Self {
        let mut w: u64 = 0;
        w |= length & ((1 << seL4_MsgLengthBits) - 1);
        w |= (extra_caps & ((1 << seL4_MsgExtraCapBits) - 1)) << seL4_MsgLengthBits;
        // capsUnwrapped is 3 bits, sitting just above extraCaps.
        w |= (caps_unwrapped & 0x7) << (seL4_MsgLengthBits + seL4_MsgExtraCapBits);
        // The label fills the remaining high bits.
        let label_shift = seL4_MsgLengthBits + seL4_MsgExtraCapBits + 3;
        w |= label << label_shift;
        Self { words: [w] }
    }
    pub const fn length(self) -> u64 {
        self.words[0] & ((1 << seL4_MsgLengthBits) - 1)
    }
    pub const fn extra_caps(self) -> u64 {
        (self.words[0] >> seL4_MsgLengthBits) & ((1 << seL4_MsgExtraCapBits) - 1)
    }
    pub const fn caps_unwrapped(self) -> u64 {
        (self.words[0] >> (seL4_MsgLengthBits + seL4_MsgExtraCapBits)) & 0x7
    }
    pub const fn label(self) -> u64 {
        self.words[0] >> (seL4_MsgLengthBits + seL4_MsgExtraCapBits + 3)
    }
}

/// Cap rights bitmask. seL4 stores it as a single word with the low
/// `seL4_CapRightsBits` (=4) bits used.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct seL4_CapRights_t {
    pub words: [seL4_Word; 1],
}

impl seL4_CapRights_t {
    pub const fn new(can_grant_reply: u64, can_grant: u64, can_read: u64, can_write: u64) -> Self {
        let w = (can_write & 1)
            | ((can_read & 1) << 1)
            | ((can_grant & 1) << 2)
            | ((can_grant_reply & 1) << 3);
        Self { words: [w] }
    }
    pub const fn can_write(self) -> bool { (self.words[0] & 1) != 0 }
    pub const fn can_read(self) -> bool { (self.words[0] >> 1) & 1 != 0 }
    pub const fn can_grant(self) -> bool { (self.words[0] >> 2) & 1 != 0 }
    pub const fn can_grant_reply(self) -> bool { (self.words[0] >> 3) & 1 != 0 }
}

/// `seL4_CapRights_new(0, 0, 1, 1)` from libsel4.
pub const seL4_ReadWrite: seL4_CapRights_t = seL4_CapRights_t::new(0, 0, 1, 1);
pub const seL4_AllRights: seL4_CapRights_t = seL4_CapRights_t::new(1, 1, 1, 1);
pub const seL4_CanRead: seL4_CapRights_t = seL4_CapRights_t::new(0, 0, 1, 0);
pub const seL4_CanWrite: seL4_CapRights_t = seL4_CapRights_t::new(0, 0, 0, 1);
pub const seL4_CanGrant: seL4_CapRights_t = seL4_CapRights_t::new(0, 1, 0, 0);
pub const seL4_CanGrantReply: seL4_CapRights_t = seL4_CapRights_t::new(1, 0, 0, 0);
pub const seL4_NoWrite: seL4_CapRights_t = seL4_CapRights_t::new(1, 1, 1, 0);
pub const seL4_NoRead: seL4_CapRights_t = seL4_CapRights_t::new(1, 1, 0, 1);
pub const seL4_NoRights: seL4_CapRights_t = seL4_CapRights_t::new(0, 0, 0, 0);

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct seL4_SlotRegion {
    /// First slot position OF the region.
    pub start: seL4_SlotPos,
    /// First slot position AFTER the region.
    pub end: seL4_SlotPos,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct seL4_UntypedDesc {
    pub paddr: seL4_Word,
    pub sizeBits: seL4_Uint8,
    pub isDevice: seL4_Uint8,
    /// Padding so `sizeof(seL4_UntypedDesc) == 2 * sizeof(seL4_Word)`.
    /// The C definition is `seL4_Uint8 padding[sizeof(seL4_Word) - 2 *
    /// sizeof(seL4_Uint8)]`, which on a 64-bit target is 6 bytes.
    pub padding: [seL4_Uint8; 6],
}

/// IPC buffer layout. Each thread has one mapped at a known virtual
/// address and addressed via the kernel's per-thread `tcbIPCBuffer`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct seL4_IPCBuffer {
    pub tag: seL4_MessageInfo_t,
    pub msg: [seL4_Word; seL4_MsgMaxLength],
    pub userData: seL4_Word,
    pub caps_or_badges: [seL4_Word; seL4_MsgMaxExtraCaps],
    pub receiveCNode: seL4_CPtr,
    pub receiveIndex: seL4_CPtr,
    pub receiveDepth: seL4_Word,
}

/// The boot-info frame the kernel hands to the initial thread. The
/// type is laid out exactly like the C `seL4_BootInfo` under
/// `CONFIG_KERNEL_MCS=true` — Phase 32a flipped MCS on, and Phase
/// 36c added the `schedcontrol` slot region between
/// `initThreadDomain` and `untyped` to match upstream.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct seL4_BootInfo {
    pub extraLen: seL4_Word,
    pub nodeID: seL4_NodeId,
    pub numNodes: seL4_Word,
    pub numIOPTLevels: seL4_Word,
    pub ipcBuffer: *mut seL4_IPCBuffer,
    pub empty: seL4_SlotRegion,
    pub sharedFrames: seL4_SlotRegion,
    pub userImageFrames: seL4_SlotRegion,
    pub userImagePaging: seL4_SlotRegion,
    pub ioSpaceCaps: seL4_SlotRegion,
    pub extraBIPages: seL4_SlotRegion,
    pub initThreadCNodeSizeBits: seL4_Word,
    pub initThreadDomain: seL4_Domain,
    /// Phase 36c — per-CPU SchedControl caps under MCS. Slot
    /// region inside the rootserver's CNode; one cap per CPU
    /// in `[start, end)`. Populated empty (`start == end`) for
    /// now until the initial-cap layout fix lands (audit item 4).
    pub schedcontrol: seL4_SlotRegion,
    pub untyped: seL4_SlotRegion,
    pub untypedList: [seL4_UntypedDesc; CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS],
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct seL4_BootInfoHeader {
    pub id: seL4_Word,
    pub len: seL4_Word,
}

#[repr(u64)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum seL4_BootInfoID {
    SEL4_BOOTINFO_HEADER_PADDING = 0,
    SEL4_BOOTINFO_HEADER_X86_VBE = 1,
    SEL4_BOOTINFO_HEADER_X86_MBMMAP = 2,
    SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP = 3,
    SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER = 4,
    SEL4_BOOTINFO_HEADER_X86_TSC_FREQ = 5,
    SEL4_BOOTINFO_HEADER_FDT = 6,
    SEL4_BOOTINFO_HEADER_NUM = 7,
}

// Note on faults: the `seL4_Fault_t` tagged union is *not* exposed
// directly here — userspace receives it as message-register words
// dispatched on `seL4_FaultType`, so the wire format is a sequence
// of `seL4_Word`s rather than a single C struct. The discriminant
// values come from the per-fault `block` definitions in
// `codegen/structures_64.bf` (`NullFault`, `CapFault`,
// `UnknownSyscall`, `UserException`).
