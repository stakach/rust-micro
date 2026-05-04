//! Layout-locking specs for the public ABI.
//!
//! These tests confirm that every Rust type which appears at the
//! kernel/userspace boundary has the same size, alignment, and (where
//! applicable) field offsets as the corresponding C type in
//! libsel4. If any of these change, a userspace binary built against
//! upstream `libsel4` would no longer be ABI-compatible with this
//! kernel — exactly the kind of regression we want to catch loudly.
//!
//! Most of the assertions are `const _: () = assert!(...)`, which
//! become compile-time errors. The runtime entry point exists so the
//! spec's pass message reaches the serial log.

use crate::arch;
use crate::structures::*;
use crate::syscalls::{InvocationLabel, Syscall};
use crate::types::*;
use core::mem::{align_of, size_of};

// ---------------------------------------------------------------------------
// Compile-time layout asserts.
// ---------------------------------------------------------------------------

// seL4_Word is 8 bytes on x86_64.
const _: () = assert!(size_of::<seL4_Word>() == 8);

// Public scalar types.
const _: () = assert!(size_of::<seL4_MessageInfo_t>() == 8);
const _: () = assert!(align_of::<seL4_MessageInfo_t>() == 8);
const _: () = assert!(size_of::<seL4_CapRights_t>() == 8);
const _: () = assert!(size_of::<seL4_SlotRegion>() == 16);

// libsel4's SEL4_COMPILE_ASSERT pins these:
//   sizeof(seL4_UntypedDesc) == 2 * sizeof(seL4_Word) == 16
//   sizeof(seL4_BootInfoHeader) == 2 * sizeof(seL4_Word) == 16
const _: () = assert!(size_of::<seL4_UntypedDesc>() == 16);
const _: () = assert!(size_of::<seL4_BootInfoHeader>() == 16);

// seL4_IPCBuffer layout, taking the documented field sizes:
//   tag(8) + msg(120*8=960) + userData(8) + caps(3*8=24)
//     + receiveCNode(8) + receiveIndex(8) + receiveDepth(8)
//   = 1024 bytes
const _: () = assert!(size_of::<seL4_IPCBuffer>() == 1024);

// seL4_BootInfo must fit in a single page (4 KiB on x86_64) because
// the kernel maps it as one frame to the initial thread.
const _: () = assert!(size_of::<seL4_BootInfo>() <= 4096);

// Generated bitfield types — sizes from .bf comments.
const _: () = assert!(NullCap::SIZE_BYTES == 16);
const _: () = assert!(UntypedCap::SIZE_BYTES == 16);
const _: () = assert!(EndpointCap::SIZE_BYTES == 16);
const _: () = assert!(NotificationCap::SIZE_BYTES == 16);
const _: () = assert!(ReplyCap::SIZE_BYTES == 16);
const _: () = assert!(CnodeCap::SIZE_BYTES == 16);
const _: () = assert!(ThreadCap::SIZE_BYTES == 16);
const _: () = assert!(IrqHandlerCap::SIZE_BYTES == 16);
const _: () = assert!(Endpoint::SIZE_BYTES == 16);
// Phase 32a — MCS notifications carry an extra word for
// `ntfnSchedContext` plus 3 words of padding, doubling the size.
const _: () = assert!(Notification::SIZE_BYTES == 64);
const _: () = assert!(MdbNode::SIZE_BYTES == 16);
const _: () = assert!(ThreadState::SIZE_BYTES == 24);

// Syscall numbering anchor: the very first user-facing syscall is -1.
const _: () = assert!(Syscall::SysCall as i32 == -1);

// Invocation labelling: 0 is reserved, common ranges start at 1.
const _: () = assert!(InvocationLabel::InvalidInvocation as u32 == 0);
const _: () = assert!(InvocationLabel::UntypedRetype as u32 == 1);

// ---------------------------------------------------------------------------
// Runtime spec entry point.
// ---------------------------------------------------------------------------

pub fn test_abi_layout() {
    arch::log("Running ABI layout tests...\n");

    test_runtime_offsets();
    test_message_info_roundtrip();
    test_cap_rights_constants();
    test_syscall_decoding();
    test_invocation_decoding();

    arch::log("ABI layout tests completed\n");
}

fn test_runtime_offsets() {
    // The compile-time asserts cover sizes; this runtime check covers
    // a couple of field offsets that would be expensive to express
    // in a const context (offset_of! is stable but verbose for
    // arrays). Pick the offsets that are most exposed to the ABI.
    let bi = unsafe { core::mem::zeroed::<seL4_BootInfo>() };
    let base = &bi as *const _ as usize;

    let off = |p: *const u8| (p as usize) - base;
    assert_eq!(off(&bi.extraLen as *const _ as *const u8), 0);
    assert_eq!(off(&bi.nodeID as *const _ as *const u8), 8);
    assert_eq!(off(&bi.numNodes as *const _ as *const u8), 16);
    assert_eq!(off(&bi.numIOPTLevels as *const _ as *const u8), 24);
    assert_eq!(off(&bi.ipcBuffer as *const _ as *const u8), 32);
    // empty starts after ipcBuffer (a pointer = 8 bytes on x86_64).
    assert_eq!(off(&bi.empty as *const _ as *const u8), 40);
    // Phase 36c — schedcontrol region sits between initThreadDomain
    // and untyped under CONFIG_KERNEL_MCS=true. Cumulative layout
    // (each SlotRegion = 16 bytes; each Word = 8):
    //   ipcBuffer @  32, empty @  40, sharedFrames @  56,
    //   userImageFrames @  72, userImagePaging @  88,
    //   ioSpaceCaps @ 104, extraBIPages @ 120,
    //   initThreadCNodeSizeBits @ 136, initThreadDomain @ 144,
    //   schedcontrol @ 152, untyped @ 168, untypedList @ 184.
    assert_eq!(off(&bi.initThreadCNodeSizeBits as *const _ as *const u8), 136);
    assert_eq!(off(&bi.initThreadDomain        as *const _ as *const u8), 144);
    assert_eq!(off(&bi.schedcontrol            as *const _ as *const u8), 152);
    assert_eq!(off(&bi.untyped                 as *const _ as *const u8), 168);
    assert_eq!(off(&bi.untypedList             as *const _ as *const u8), 184);
    arch::log("  ✓ seL4_BootInfo field offsets match libsel4 layout\n");
}

fn test_message_info_roundtrip() {
    // Pick distinct values per packed sub-field; check round-trip and
    // bit positions.
    let mi = seL4_MessageInfo_t::new(
        /* label */ 0xCAFE,
        /* caps_unwrapped */ 0b011,
        /* extra_caps */ 0b10,
        /* length */ 5,
    );
    assert_eq!(mi.length(), 5);
    assert_eq!(mi.extra_caps(), 0b10);
    assert_eq!(mi.caps_unwrapped(), 0b011);
    assert_eq!(mi.label(), 0xCAFE);

    // Layout: length in low 7 bits, extra_caps in bits 7..9,
    // caps_unwrapped in bits 9..12, label above.
    let w = mi.words[0];
    assert_eq!(w & 0x7f, 5);
    assert_eq!((w >> 7) & 0x3, 0b10);
    assert_eq!((w >> 9) & 0x7, 0b011);
    assert_eq!(w >> 12, 0xCAFE);
    arch::log("  ✓ seL4_MessageInfo_t round-trips and packs per spec\n");
}

fn test_cap_rights_constants() {
    // Spot-check the macros. seL4_AllRights = (1, 1, 1, 1).
    assert!(seL4_AllRights.can_read());
    assert!(seL4_AllRights.can_write());
    assert!(seL4_AllRights.can_grant());
    assert!(seL4_AllRights.can_grant_reply());

    // seL4_NoRights is empty.
    assert!(!seL4_NoRights.can_read());
    assert!(!seL4_NoRights.can_write());
    assert!(!seL4_NoRights.can_grant());
    assert!(!seL4_NoRights.can_grant_reply());

    // seL4_ReadWrite = (0, 0, 1, 1).
    assert!(seL4_ReadWrite.can_read());
    assert!(seL4_ReadWrite.can_write());
    assert!(!seL4_ReadWrite.can_grant());
    assert!(!seL4_ReadWrite.can_grant_reply());

    arch::log("  ✓ seL4_CapRights constants match libsel4 macros\n");
}

fn test_syscall_decoding() {
    assert_eq!(Syscall::from_i32(-1), Some(Syscall::SysCall));
    assert_eq!(Syscall::from_i32(-2), Some(Syscall::SysReplyRecv));
    // Phase 36b — MCS layout (api-mcs block):
    //   -3 NBSendRecv, -4 NBSendWait, -5 Send, -6 NBSend,
    //   -7 Recv, -8 NBRecv, -9 Wait, -10 NBWait, -11 Yield,
    //   -12 DebugPutChar.
    assert_eq!(Syscall::from_i32(-5),  Some(Syscall::SysSend));
    assert_eq!(Syscall::from_i32(-9),  Some(Syscall::SysWait));
    assert_eq!(Syscall::from_i32(-12), Some(Syscall::SysDebugPutChar));
    assert_eq!(Syscall::from_i32(0), None);
    assert_eq!(Syscall::from_i32(-1000), None);
    arch::log("  ✓ Syscall::from_i32 decodes per generator output\n");
}

fn test_invocation_decoding() {
    assert_eq!(InvocationLabel::from_u64(0), Some(InvocationLabel::InvalidInvocation));
    assert_eq!(InvocationLabel::from_u64(1), Some(InvocationLabel::UntypedRetype));
    // Last common label, then first arch-specific tag (X86PDPTMap).
    // We don't hard-code numbers other than the anchor points, since
    // adding methods upstream would shift them — but we do confirm
    // the X86 range exists.
    let some_x86 = InvocationLabel::from_u64(InvocationLabel::X86PDPTMap as u64);
    assert_eq!(some_x86, Some(InvocationLabel::X86PDPTMap));
    arch::log("  ✓ InvocationLabel::from_u64 decodes per generator output\n");
}
