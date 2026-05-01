//! Cross-subsystem integration tests — the closest analogue to
//! seL4test we can run without real usermode.
//!
//! These specs deliberately exercise multiple modules together:
//! Untyped retype produces a CNode, the CNode lives in a real CSpace,
//! TCBs are scheduled, endpoints carry IPC, IRQs deliver via
//! notifications, and frames map into page-tables. Each test is a
//! focused scenario; if any of these break, a single subsystem-level
//! spec might still pass while the system-as-a-whole has regressed.

use crate::arch;
use crate::cap::{
    Badge, Cap, CNodeStorage, EndpointObj, EndpointRights, NotificationObj,
    NotificationRights, PPtr,
};
use crate::cspace::{lookup_cap, CSpace};
use crate::cte::Cte;
use crate::endpoint::{
    receive_ipc, send_ipc, Endpoint, IpcOutcome, RecvOptions, SendOptions,
};
use crate::interrupt::{handle_interrupt, set_notification, IrqTable};
use crate::notification::{wait, Notification, WaitOutcome};
use crate::object_type::ObjectType;
use crate::scheduler::Scheduler;
use crate::structures::arch::Pte;
use crate::tcb::{Tcb, TcbId, ThreadStateType};
use crate::untyped::{retype, UntypedState};
use crate::vspace::{frame_map_4k, decompose_vaddr, CacheAttr, VmRights, ENTRIES_PER_TABLE};

pub fn test_integration() {
    arch::log("Running integration (sel4test subset) tests...\n");
    untyped_to_cnode_to_lookup();
    two_thread_endpoint_pingpong();
    irq_drives_thread_unblock();
    badge_identifies_sender();
    untyped_to_frame_map();
    arch::log("Integration tests completed\n");
}

// ---------------------------------------------------------------------------
// Test 1: classic init flow.
//
// "Carve a CNode out of an Untyped, drop a cap into one of its
// slots, look it up via the CSpace lookup we'd use in a real
// syscall." This is the smallest scenario that proves the cap
// allocator and the lookup path agree on layout.
// ---------------------------------------------------------------------------

#[inline(never)]
fn untyped_to_cnode_to_lookup() {
    let cnode_base: u64 = 0x0000_0000_0040_0000;
    let mut ut = UntypedState::new(cnode_base, /* block_bits */ 14, /* device */ false);

    // Retype 1 CNode of radix 5 (32 slots → 1 KiB).
    let mut produced: Option<Cap> = None;
    retype(&mut ut, ObjectType::CapTable, 5, 1, |c| produced = Some(c)).unwrap();
    let cnode_cap = produced.unwrap();
    let (ptr, radix) = match cnode_cap {
        Cap::CNode { ptr, radix, .. } => (ptr, radix),
        _ => panic!("expected CNode cap"),
    };
    assert_eq!(radix, 5);

    // Back the new CNode with real CTE storage and write a known
    // endpoint cap into slot 7.
    let mut slots = [Cte::null(); 32];
    let target = Cap::Endpoint {
        ptr: PPtr::<EndpointObj>::new(0xFFFF_8000_DEAD_B000).unwrap(),
        badge: Badge(0xC0FFEE),
        rights: EndpointRights::default(),
    };
    slots[7] = Cte::with_cap(&target);

    // Build a CSpace with the new CNode as root and look up slot 7.
    struct OneCNode<'a> {
        ptr: PPtr<CNodeStorage>,
        slots: &'a [Cte],
    }
    impl<'a> CSpace for OneCNode<'a> {
        fn cnode_at(&self, p: PPtr<CNodeStorage>, _: usize) -> Option<&[Cte]> {
            if p == self.ptr { Some(self.slots) } else { None }
        }
    }
    let cspace = OneCNode { ptr, slots: &slots };
    let root = Cap::CNode { ptr, radix, guard_size: 64 - radix, guard: 0 };
    let found = lookup_cap(&cspace, &root, 7).expect("lookup ok");
    assert_eq!(found, target);
    arch::log("  ✓ Untyped → CNode → write slot → lookup_cap end-to-end\n");
}

// ---------------------------------------------------------------------------
// Test 2: two userland threads ping-ponging through an endpoint.
//
// The scheduler holds both threads; one calls send, blocks; the
// other calls recv and pairs them off; both end up runnable;
// scheduler picks the next. Repeat in the reverse direction.
// ---------------------------------------------------------------------------

#[inline(never)]
fn two_thread_endpoint_pingpong() {
    let mut sched = Scheduler::new();
    let mut ep = Endpoint::new();

    let alice = sched.admit(running(50));
    let bob = sched.admit(running(50));

    // Alice sends "ping".
    sched.slab.get_mut(alice).ipc_label = 0x1;
    sched.slab.get_mut(alice).ipc_length = 1;
    sched.slab.get_mut(alice).msg_regs[0] = 0x70696E67; // "ping"
    let r = send_ipc(&mut ep, &mut sched, alice, SendOptions::blocking(0));
    assert_eq!(r, IpcOutcome::Blocked);

    // Bob receives "ping", flips it to "pong", sends back.
    let r = receive_ipc(&mut ep, &mut sched, bob, RecvOptions::blocking());
    assert_eq!(r, IpcOutcome::Transferred { peer: alice });
    assert_eq!(sched.slab.get(bob).msg_regs[0], 0x70696E67);
    sched.slab.get_mut(bob).msg_regs[0] = 0x706F6E67; // "pong"

    // Alice now needs to be in BlockedOnReceive to take Bob's reply.
    sched.block(alice, ThreadStateType::BlockedOnReceive);
    // Sneak Alice onto the recv queue manually for the spec — in
    // production she'd issue Recv as part of a Call syscall. We
    // mimic that by re-running receive_ipc with `alice`.
    sched.make_runnable(alice);
    let r = receive_ipc(&mut ep, &mut sched, alice, RecvOptions::blocking());
    assert_eq!(r, IpcOutcome::Blocked);
    let r = send_ipc(&mut ep, &mut sched, bob, SendOptions::blocking(0));
    assert_eq!(r, IpcOutcome::Transferred { peer: alice });
    assert_eq!(sched.slab.get(alice).msg_regs[0], 0x706F6E67);
    arch::log("  ✓ two-thread endpoint ping-pong over scheduler\n");
}

// ---------------------------------------------------------------------------
// Test 3: an IRQ unblocks a thread waiting on the bound notification.
//
// Real-world flow: driver thread waits on an IRQHandler-bound
// notification → hardware fires → kernel signals → thread wakes.
// ---------------------------------------------------------------------------

#[inline(never)]
fn irq_drives_thread_unblock() {
    let mut sched = Scheduler::new();
    let mut ntfns = [Notification::new(); 4];
    let mut irqs = IrqTable::new();
    let driver = sched.admit(running(100));

    // Bind IRQ 12 to notification slot 2.
    set_notification(&mut irqs, 12, 2).unwrap();
    // Driver waits on the notification — blocks.
    wait(&mut ntfns[2], &mut sched, driver);
    assert_eq!(sched.slab.get(driver).state, ThreadStateType::BlockedOnNotification);

    // Hardware fires IRQ 12 → handle_interrupt signals notification 2
    // → driver wakes.
    let woken = handle_interrupt(&mut irqs, &mut ntfns, &mut sched, 12);
    assert_eq!(woken, Some(driver));
    assert_eq!(sched.slab.get(driver).state, ThreadStateType::Running);
    arch::log("  ✓ IRQ → notification → driver thread unblocked\n");
}

// ---------------------------------------------------------------------------
// Test 4: badge-identified senders.
//
// A server thread waits on one endpoint that has multiple senders.
// Each sender identifies itself by its badge. The server can tell
// which sender's message it just received without per-sender
// coordination — the canonical seL4 idiom for client/server.
// ---------------------------------------------------------------------------

#[inline(never)]
fn badge_identifies_sender() {
    let mut sched = Scheduler::new();
    let mut ep = Endpoint::new();
    let server = sched.admit(running(100));
    let client_a = sched.admit(running(50));
    let client_b = sched.admit(running(50));

    // Both clients send with distinct badges.
    sched.slab.get_mut(client_a).ipc_label = 1;
    sched.slab.get_mut(client_a).ipc_badge = 0xAAAA;
    send_ipc(&mut ep, &mut sched, client_a, SendOptions::blocking(0xAAAA));
    sched.slab.get_mut(client_b).ipc_label = 2;
    sched.slab.get_mut(client_b).ipc_badge = 0xBBBB;
    send_ipc(&mut ep, &mut sched, client_b, SendOptions::blocking(0xBBBB));

    // Server receives — picks up client_a first (FIFO).
    receive_ipc(&mut ep, &mut sched, server, RecvOptions::blocking());
    assert_eq!(sched.slab.get(server).ipc_badge, 0xAAAA);
    assert_eq!(sched.slab.get(server).ipc_label, 1);

    // Block server again, receive client_b's message.
    sched.block(server, ThreadStateType::BlockedOnReceive);
    sched.make_runnable(server);
    receive_ipc(&mut ep, &mut sched, server, RecvOptions::blocking());
    assert_eq!(sched.slab.get(server).ipc_badge, 0xBBBB);
    assert_eq!(sched.slab.get(server).ipc_label, 2);
    arch::log("  ✓ server distinguishes badged senders on shared endpoint\n");
}

// ---------------------------------------------------------------------------
// Test 5: Untyped → page-table → frame map.
//
// Carve a page table out of an Untyped (CapTable size suffices for
// the spec — same 4 KiB), then map a frame into the resulting PT
// slice. Demonstrates the cap allocator and vspace layer agree on
// page-aligned addresses.
// ---------------------------------------------------------------------------

#[inline(never)]
fn untyped_to_frame_map() {
    // Page table = one page = 4 KiB = block_bits 12.
    let pt_base: u64 = 0x0000_0000_0080_0000;
    let mut ut = UntypedState::new(pt_base, /* block_bits */ 14, false);

    // Cap-allocate a "page table" using the CapTable retype path —
    // it picks a page-aligned address out of the untyped. This is
    // the same allocation discipline the real x86 PageTable retype
    // uses, just via a different cap type.
    let mut produced: Option<Cap> = None;
    retype(&mut ut, ObjectType::CapTable, /* radix */ 9, 1, |c| produced = Some(c)).unwrap();
    let pt_paddr = match produced.unwrap() {
        Cap::CNode { ptr, .. } => ptr.addr(),
        _ => panic!("expected CNode cap as PT stand-in"),
    };
    // 9-bit radix × 32-byte CTE = 16 KiB; same alignment class as a
    // 4 KiB page from the retype's POV (page_bits = 12). The address
    // is 4 KiB-aligned by construction.
    assert_eq!(pt_paddr & 0xFFF, 0);

    // Now exercise the vspace mapper directly. Use a host PT slice
    // since we can't dereference pt_paddr in the spec.
    let mut pt = [Pte::zeroed(); ENTRIES_PER_TABLE];
    let user_vaddr: Word = 0x0000_0000_4000_1000;
    let frame_paddr: Word = 0x0000_0000_0090_0000;
    frame_map_4k(
        &mut pt,
        user_vaddr,
        frame_paddr,
        VmRights::UserRW,
        CacheAttr::Writeback,
        true,
    )
    .unwrap();

    // The PTE landed at the slot the decomposition predicted, with
    // the right physical-address payload.
    let idx = decompose_vaddr(user_vaddr).pt as usize;
    assert_eq!(pt[idx].present(), 1);
    assert_eq!(pt[idx].page_base_address(), frame_paddr);
    arch::log("  ✓ Untyped → PT-shaped allocation + frame_map_4k\n");
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

use crate::types::seL4_Word as Word;

fn running(prio: u8) -> Tcb {
    let mut t = Tcb::default();
    t.priority = prio;
    t.state = ThreadStateType::Running;
    t
}

#[allow(unused_imports)] // for the badge_identifies_sender wait_outcome match
use core::option::Option as _;
