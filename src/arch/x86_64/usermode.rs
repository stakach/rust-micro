//! Phase 13c / 14d — user-mode launch & two-thread IPC demo.
//!
//! Phase 13c proved a single ring-3 thread can SYSCALL into the
//! kernel and back. Phase 14d turns that into a real microkernel
//! demonstration: two threads share an Endpoint cap. Thread A sends
//! a one-byte message; thread B receives it and prints both bytes
//! via `SysDebugPutChar` — a 'P' it ships itself plus the 'M' it
//! got from A. The kernel watches for the second print and exits
//! QEMU.
//!
//! Both threads live in the same address space (different vaddr
//! ranges) — per-thread CR3 isolation lands when we have ASID
//! management. Each gets its own CSpace (separate CNode page) with
//! a Cap::Endpoint at slot 1 pointing at the same kernel-side
//! Endpoint object.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use super::gdt::{USER_CS, USER_DS};
use super::paging::{
    install_kernel_page_tables, kernel_virt_to_phys, read_cr3,
    PTE_PRESENT, PTE_RW, PTE_USER,
};
use super::syscall_entry::{enter_user_via_sysret, set_syscall_kernel_rsp, UserContext};
use crate::cap::{Badge, Cap, EndpointRights, PPtr};
use crate::cte::Cte;
use crate::kernel::{KernelState, KERNEL};
use crate::syscalls::Syscall;
use crate::tcb::{Tcb, ThreadStateType};

// ---------------------------------------------------------------------------
// User payloads. Hand-assembled, since we don't drag in a separate
// build pipeline for a one-off demo.
//
// Sender (thread A): sends one byte over endpoint cap_ptr=1, then
// spin-loops:
//   48 c7 c2 4d 00 00 00   mov rdx, 'M'         ; first msg reg
//   48 c7 c6 00 00 00 00   mov rsi, 0           ; MessageInfo = 0
//   48 c7 c7 01 00 00 00   mov rdi, 1           ; cap_ptr = 1
//   48 c7 c0 fd ff ff ff   mov rax, -3          ; SysSend
//   0f 05                  syscall
//   eb fe                  jmp $-0
//
// Receiver (thread B): SysDebugPutChar('P'), then SysRecv, then
// SysDebugPutChar(received byte from rdx), then spin-loops:
//   48 c7 c7 50 00 00 00   mov rdi, 'P'
//   48 c7 c0 f7 ff ff ff   mov rax, -9          ; SysDebugPutChar
//   0f 05                  syscall
//   48 c7 c7 01 00 00 00   mov rdi, 1           ; cap_ptr = 1
//   48 c7 c0 fb ff ff ff   mov rax, -5          ; SysRecv
//   0f 05                  syscall
//   48 8b 39               mov rdi, [rcx]       ; nope — need rdx not [rcx]
//                                              ; receiver got msg in rdx
//   48 89 d7               mov rdi, rdx         ; arg 0 = received byte
//   48 c7 c0 f7 ff ff ff   mov rax, -9          ; SysDebugPutChar
//   0f 05                  syscall
//   eb fe                  jmp $-0
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const SENDER_PAYLOAD: &[u8] = &[
    0x48, 0xC7, 0xC2, 0x4D, 0x00, 0x00, 0x00, // mov rdx, 'M' (msg_regs[0])
    0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, // mov rsi, 1   (MsgInfo: len=1)
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1   (cap_ptr)
    0x48, 0xC7, 0xC0, 0xFD, 0xFF, 0xFF, 0xFF, // mov rax, -3  (SysSend)
    0x0F, 0x05,                               // syscall
    0xEB, 0xFE,                               // jmp $-0
];

#[rustfmt::skip]
const RECEIVER_PAYLOAD: &[u8] = &[
    // First, putchar('P') so we know the receiver started.
    0x48, 0xC7, 0xC7, 0x50, 0x00, 0x00, 0x00, // mov rdi, 'P'
    0x48, 0xC7, 0xC0, 0xF7, 0xFF, 0xFF, 0xFF, // mov rax, -9
    0x0F, 0x05,                               // syscall
    // Recv on cap_ptr=1.
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
    0x48, 0xC7, 0xC0, 0xFB, 0xFF, 0xFF, 0xFF, // mov rax, -5 (SysRecv)
    0x0F, 0x05,                               // syscall
    // Phase 15a: kernel parents msg_regs[0] into rdx on the way
    // out, so the byte the sender shipped lives in rdx now.
    // Print it.
    0x48, 0x89, 0xD7,                         // mov rdi, rdx
    0x48, 0xC7, 0xC0, 0xF7, 0xFF, 0xFF, 0xFF, // mov rax, -9
    0x0F, 0x05,                               // syscall
    0xEB, 0xFE,                               // jmp $-0
];

#[repr(C, align(4096))]
struct UserPage([u8; 4096]);

static mut SENDER_CODE_PAGE: UserPage = UserPage([0; 4096]);
static mut SENDER_STACK_PAGE: UserPage = UserPage([0; 4096]);
static mut RECEIVER_CODE_PAGE: UserPage = UserPage([0; 4096]);
static mut RECEIVER_STACK_PAGE: UserPage = UserPage([0; 4096]);

const SENDER_CODE_VBASE: u64 = 0x0000_0100_0000_0000;
const SENDER_STACK_VBASE: u64 = 0x0000_0100_0001_0000;
const RECEIVER_CODE_VBASE: u64 = 0x0000_0100_0002_0000;
const RECEIVER_STACK_VBASE: u64 = 0x0000_0100_0003_0000;

/// Trigger flag for the original Phase 13c single-thread demo.
/// Phase 14d uses its own counter (see RECEIVED_BYTES) so the two
/// stand alongside each other and the single-thread launcher in
/// `launch_user_mode_test` still works for the spec runner that
/// calls it from a context where we don't want IPC.
pub static USERMODE_TEST_TRIGGERED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Phase 14d two-thread launcher.
// ---------------------------------------------------------------------------

/// Number of `SysDebugPutChar` invocations seen since the two-
/// thread test was armed. The syscall dispatcher exits QEMU once
/// it observes both 'P' and 'M' (i.e. counter ≥ 2).
pub static IPC_PRINTED: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);
pub static IPC_DEMO_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn launch_two_thread_ipc_demo() -> ! {
    unsafe {
        install_kernel_page_tables();

        // Copy payloads into their pages.
        copy_payload(&raw const SENDER_CODE_PAGE, SENDER_PAYLOAD);
        copy_payload(&raw const RECEIVER_CODE_PAGE, RECEIVER_PAYLOAD);

        // Map all four pages (code RX, stacks RW) into the live
        // page tables.
        map_user_4k(SENDER_CODE_VBASE,
            kernel_virt_to_phys((&raw const SENDER_CODE_PAGE) as u64), false);
        map_user_4k(SENDER_STACK_VBASE,
            kernel_virt_to_phys((&raw const SENDER_STACK_PAGE) as u64), true);
        map_user_4k(RECEIVER_CODE_VBASE,
            kernel_virt_to_phys((&raw const RECEIVER_CODE_PAGE) as u64), false);
        map_user_4k(RECEIVER_STACK_VBASE,
            kernel_virt_to_phys((&raw const RECEIVER_STACK_PAGE) as u64), true);

        // Build the kernel-side state: an endpoint, two CNodes
        // (one per thread) each containing the same endpoint cap
        // at slot 1.
        let s = KERNEL.get();
        let ep_ptr = KernelState::endpoint_ptr(0);
        let sender_cnode = KernelState::cnode_ptr(1);
        let receiver_cnode = KernelState::cnode_ptr(2);
        let ep_cap = Cap::Endpoint {
            ptr: ep_ptr,
            badge: Badge(0xCAFE),
            rights: EndpointRights {
                can_send: true, can_receive: true,
                can_grant: true, can_grant_reply: true,
            },
        };
        // CNodes 1 and 2 each hold the endpoint cap at slot 1.
        s.cnodes[1].0[1] = Cte::with_cap(&ep_cap);
        s.cnodes[2].0[1] = Cte::with_cap(&ep_cap);

        // Spawn the two TCBs.
        let sender = spawn_thread(
            sender_cnode,
            SENDER_CODE_VBASE,
            SENDER_STACK_VBASE + 0x1000 - 8,
        );
        let receiver = spawn_thread(
            receiver_cnode,
            RECEIVER_CODE_VBASE,
            RECEIVER_STACK_VBASE + 0x1000 - 8,
        );

        // Set the kernel rsp the SYSCALL entry stub uses.
        let rsp: u64;
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
        set_syscall_kernel_rsp(rsp);

        // Demote the boot thread out of the way: keep it as a TCB
        // for fallback but mark it Inactive so choose_thread skips
        // it. Both demo TCBs sit at higher priority anyway.
        if let Some(boot) = s.scheduler.current {
            s.scheduler.block(boot, ThreadStateType::Inactive);
        }
        // Pick the receiver to run first — that way it'll park on
        // SysRecv and the sender's first SysSend has a peer waiting.
        // Actually, simpler: run the sender first; with no waiter
        // it blocks on the endpoint queue, scheduler picks the
        // receiver next, receiver receives, both unblock, both
        // continue (and each issues the putchar).
        s.scheduler.current = Some(sender);

        // Arm the demo flag. The syscall dispatcher checks this on
        // every SysDebugPutChar and bumps IPC_PRINTED; once it sees
        // ≥ 2 it exits QEMU.
        IPC_DEMO_ACTIVE.store(true, Ordering::Relaxed);

        // First-launch the sender.
        let ctx = s.scheduler.slab.get(sender).user_context;
        let _ = receiver; // suppress unused if receiver isn't reached on first hop
        enter_user_via_sysret(&ctx);
    }
}

unsafe fn spawn_thread(
    cspace_root_ptr: PPtr<crate::cap::CNodeStorage>,
    user_rip: u64,
    user_rsp: u64,
) -> crate::tcb::TcbId {
    let s = KERNEL.get();
    let mut t = Tcb::default();
    t.priority = 100;
    t.state = ThreadStateType::Running;
    t.cspace_root = Cap::CNode {
        ptr: cspace_root_ptr,
        radix: 5,
        guard_size: 59,
        guard: 0,
    };
    t.user_context = UserContext::for_entry(user_rip, user_rsp, /* arg0 */ 0);
    s.scheduler.admit(t)
}

unsafe fn copy_payload(page_va: *const UserPage, src: &[u8]) {
    let dst = page_va as *mut u8;
    for (i, b) in src.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
}

// ---------------------------------------------------------------------------
// Phase 13c single-thread launch — kept for backward compatibility.
// Either this or `launch_two_thread_ipc_demo` runs at boot, never both.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const PHASE_13C_PAYLOAD: &[u8; 18] = &[
    0x48, 0xC7, 0xC7, 0x41, 0x00, 0x00, 0x00, // mov rdi, 0x41
    0x48, 0xC7, 0xC0, 0xF7, 0xFF, 0xFF, 0xFF, // mov rax, -9
    0x0F, 0x05,                               // syscall
    0xEB, 0xFE,                               // jmp $-0
];

static mut PHASE13C_CODE: UserPage = UserPage([0; 4096]);
static mut PHASE13C_STACK: UserPage = UserPage([0; 4096]);
const PHASE13C_CODE_VBASE: u64 = 0x0000_0080_0000_0000; // PML4[1]
const PHASE13C_STACK_VBASE: u64 = 0x0000_0080_0001_0000;

pub fn launch_user_mode_test() -> ! {
    unsafe {
        install_kernel_page_tables();
        copy_payload(&raw const PHASE13C_CODE, PHASE_13C_PAYLOAD);
        map_user_4k(PHASE13C_CODE_VBASE,
            kernel_virt_to_phys((&raw const PHASE13C_CODE) as u64), false);
        map_user_4k(PHASE13C_STACK_VBASE,
            kernel_virt_to_phys((&raw const PHASE13C_STACK) as u64), true);
        let rsp: u64;
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
        set_syscall_kernel_rsp(rsp);
        USERMODE_TEST_TRIGGERED.store(true, Ordering::Relaxed);

        let user_rip = PHASE13C_CODE_VBASE;
        let user_rsp = PHASE13C_STACK_VBASE + 0x1000 - 8;
        let user_rflags: u64 = 0x202;
        asm!(
            "push {ss}",
            "push {rsp}",
            "push {flags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss    = in(reg) USER_DS as u64,
            rsp   = in(reg) user_rsp,
            flags = in(reg) user_rflags,
            cs    = in(reg) USER_CS as u64,
            rip   = in(reg) user_rip,
            options(noreturn),
        );
    }
}

// ---------------------------------------------------------------------------
// Page-table helpers (shared with Phase 13c).
// ---------------------------------------------------------------------------

unsafe fn map_user_4k(vaddr: u64, paddr: u64, writable: bool) {
    let pml4 = (read_cr3() & 0xFFFF_F000) as *mut u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    let mid_flags = PTE_PRESENT | PTE_RW | PTE_USER;
    let leaf_flags = PTE_PRESENT
        | PTE_USER
        | if writable { PTE_RW } else { 0 };

    let pdpt = ensure_user_table(pml4.add(pml4_idx), mid_flags);
    let pd = ensure_user_table(pdpt.add(pdpt_idx), mid_flags);
    let pt = ensure_user_table(pd.add(pd_idx), mid_flags);

    core::ptr::write_volatile(pt.add(pt_idx), (paddr & !0xFFF) | leaf_flags);
    asm!("invlpg [{a}]", a = in(reg) vaddr, options(nostack, preserves_flags));
}

unsafe fn ensure_user_table(entry_ptr: *mut u64, flags: u64) -> *mut u64 {
    use super::paging::{PTE_PRESENT, PTE_PS};
    let entry = core::ptr::read_volatile(entry_ptr);
    if entry & PTE_PRESENT != 0 {
        if entry & PTE_PS != 0 {
            panic!("ensure_user_table: walked into a large page");
        }
        let updated = entry | flags;
        if updated != entry {
            core::ptr::write_volatile(entry_ptr, updated);
        }
        return (entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
    }
    let table_v = super::paging::alloc_user_table_va();
    let table_p = kernel_virt_to_phys(table_v as u64);
    core::ptr::write_volatile(entry_ptr, (table_p & !0xFFF) | flags);
    table_p as *mut u64
}

// Make Syscall referenced so unused-import lint doesn't fire when
// the demo code paths sit alongside.
#[allow(dead_code)]
const _SYSCALL_USED: Syscall = Syscall::SysDebugPutChar;
