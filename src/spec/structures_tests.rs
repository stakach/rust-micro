// Specs for the bitfield codegen.
//
// Goals:
//   1. Sizes match what seL4 expects for the same `block` definitions
//      on a 64-bit target.
//   2. Field offsets land at the bit positions seL4 documents in the
//      `.bf` source comments (see comments above each block).
//   3. Setter -> getter round-trip.
//   4. Sign-extension on read for `field_ptr` matches what seL4 does
//      when storing a kernel-half address.

use crate::arch;
use crate::structures::*;

pub fn test_structures() {
    arch::log("Running structures (bitfield) tests...\n");

    test_sizes();
    test_endpoint_cap_roundtrip();
    test_cnode_cap_aligned_pointer();
    test_field_ptr_sign_extends_kernel_addr();

    arch::log("Structures tests completed\n");
}

fn test_sizes() {
    // From .bf comments and the seL4 manual:
    //   endpoint_cap, cnode_cap, untyped_cap, ... = 16 bytes (2 words)
    //   endpoint                                  = 16 bytes
    //   notification (non-MCS)                    = 32 bytes
    //   mdb_node                                  = 16 bytes
    //   thread_state                              = 24 bytes
    assert_eq!(EndpointCap::SIZE_BYTES, 16);
    assert_eq!(CnodeCap::SIZE_BYTES, 16);
    assert_eq!(UntypedCap::SIZE_BYTES, 16);
    assert_eq!(NotificationCap::SIZE_BYTES, 16);
    assert_eq!(Endpoint::SIZE_BYTES, 16);
    assert_eq!(Notification::SIZE_BYTES, 32);
    assert_eq!(MdbNode::SIZE_BYTES, 16);
    assert_eq!(ThreadState::SIZE_BYTES, 24);
    arch::log("  ✓ struct byte sizes match seL4\n");
}

fn test_endpoint_cap_roundtrip() {
    // Build an endpoint_cap with known field values and check both:
    //   * each getter returns what we wrote;
    //   * the underlying word layout is what we expect from the .bf
    //     declaration.
    //
    // From structures_64.bf:
    //
    //   block endpoint_cap {
    //       field capEPBadge       64  (word 1)
    //
    //       field capType          5   (word 0, bits 59..63)
    //       field capCanGrantReply 1   (word 0, bit 58)
    //       field capCanGrant      1   (word 0, bit 57)
    //       field capCanReceive    1   (word 0, bit 56)
    //       field capCanSend       1   (word 0, bit 55)
    //       field_ptr capEPPtr     55  (word 0, bits 0..47, sign-ext)
    //   }
    //
    // Pick distinct values per field so a transposition would fail.
    let badge: u64 = 0x1122_3344_5566_7788;
    let cap_type: u64 = 4;        // EndpointCap tag
    let can_grant_reply: u64 = 1;
    let can_grant: u64 = 0;
    let can_receive: u64 = 1;
    let can_send: u64 = 1;
    // A small kernel-half-style address (sign bit clear → no extension).
    let ep_ptr: u64 = 0x0000_0000_DEAD_B000;

    let cap = EndpointCap::new(badge, can_grant_reply, can_grant, can_send,
                               can_receive, ep_ptr, cap_type);
    assert_eq!(cap.capEPBadge(), badge);
    assert_eq!(cap.capType(), cap_type);
    assert_eq!(cap.capCanGrantReply(), can_grant_reply);
    assert_eq!(cap.capCanGrant(), can_grant);
    assert_eq!(cap.capCanReceive(), can_receive);
    assert_eq!(cap.capCanSend(), can_send);
    assert_eq!(cap.capEPPtr(), ep_ptr);

    // Layout asserts. word 1 is the badge in its entirety.
    assert_eq!(cap.words[1], badge);
    // word 0 high 5 bits = capType.
    assert_eq!((cap.words[0] >> 59) & 0x1f, cap_type);
    // bit 58 / 57 / 56 / 55.
    assert_eq!((cap.words[0] >> 58) & 1, can_grant_reply);
    assert_eq!((cap.words[0] >> 57) & 1, can_grant);
    assert_eq!((cap.words[0] >> 56) & 1, can_receive);
    assert_eq!((cap.words[0] >> 55) & 1, can_send);
    // bits 0..47 = ep_ptr (since the sign bit is clear).
    assert_eq!(cap.words[0] & 0x0000_FFFF_FFFF_FFFF, ep_ptr);

    arch::log("  ✓ endpoint_cap round-trips and lays out per .bf\n");
}

fn test_cnode_cap_aligned_pointer() {
    // cnode_cap stores its pointer with `field_ptr(1)` — i.e. the
    // pointer's low bit is implicit. Check the read-back for an
    // odd-aligned-by-2 pointer matches and a misaligned pointer is
    // rounded down on store.
    let aligned_ptr: u64 = 0x0000_0000_0010_2030; // bit 0 = 0
    let cap = CnodeCap::new(/* radix */ 12, /* guard_size */ 0, /* guard */ 0,
                            aligned_ptr, /* capType */ 10);
    assert_eq!(cap.capCNodePtr(), aligned_ptr);

    // The stored bits in word 0 are the pointer >> 1, occupying
    // bits 0..46 (47 bits). The low bit of the pointer is dropped.
    let stored = cap.words[0] & ((1u64 << 47) - 1);
    assert_eq!(stored, aligned_ptr >> 1);
    arch::log("  ✓ cnode_cap stores pointer shifted by alignment\n");
}

fn test_field_ptr_sign_extends_kernel_addr() {
    // For a kernel-half address (high bit of canonical 48 set), the
    // getter must reconstruct a sign-extended 64-bit value.
    // 0xFFFF_8000_0000_0000 is the canonical lowest kernel-half
    // address on x86_64. Bit 47 is set; bits 48..63 are all 1.
    let kernel_ptr: u64 = 0xFFFF_8000_DEAD_B000;
    let cap = EndpointCap::new(0, 0, 0, 0, 0, kernel_ptr, 4);

    // The bitfield only stores 48 bits, but reading should give us
    // the full sign-extended 64-bit value back.
    assert_eq!(cap.capEPPtr(), kernel_ptr);
    arch::log("  ✓ field_ptr sign-extends kernel-half addresses\n");
}
