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
    0x48, 0xC7, 0xC2, 0x59, 0x00, 0x00, 0x00, // mov rdx, 'Y' (msg_regs[0])
    0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, // mov rsi, 1   (MsgInfo: len=1)
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1   (cap_ptr)
    0x48, 0xC7, 0xC0, 0xFD, 0xFF, 0xFF, 0xFF, // mov rax, -3  (SysSend)
    0x0F, 0x05,                               // syscall
    0xEB, 0xFE,                               // jmp $-0
];

// Phase 21: receiver allocates a Frame from an Untyped (slot 2),
// maps it at a fixed user-virtual address V, receives the
// sender's byte, stores it through the new mapping, loads it back,
// and prints it. If the assembled stream of syscalls works the
// boot output is `AY` and the test exits.
//
// Hand-assembled. Layout:
//
//   // 1) putchar('A')
//   48 C7 C7 41 00 00 00   mov rdi, 'A'
//   48 C7 C0 F7 FF FF FF   mov rax, -9
//   0F 05                  syscall
//
//   // 2) SysSend(cap=2 = Untyped, MsgInfo=UntypedRetype<<12,
//   //           type=X86_4K=7, num=1, dest_offset=3)
//   48 C7 C7 02 00 00 00   mov rdi, 2          ; cap_ptr
//   48 C7 C6 00 10 00 00   mov rsi, 0x1000     ; (1<<12) MsgInfo
//   48 C7 C2 07 00 00 00   mov rdx, 7          ; X86_4K
//   49 C7 C2 01 00 00 00   mov r10, 1          ; (size_bits<<32)|num
//   49 C7 C0 03 00 00 00   mov r8,  3          ; dest_offset
//   48 C7 C0 FD FF FF FF   mov rax, -3         ; SysSend
//   0F 05                  syscall
//
//   // 3) SysSend(cap=3 = Frame, MsgInfo=X86PageMap<<12, vaddr=V,
//   //           rights=ReadWrite=3)
//   48 C7 C7 03 00 00 00   mov rdi, 3
//   48 C7 C6 00 70 02 00   mov rsi, 0x27000    ; (39<<12) PageMap
//   48 BA <V64>            mov rdx, V          ; 0x0000_0100_0050_0000
//   49 C7 C2 03 00 00 00   mov r10, 3          ; ReadWrite
//   48 C7 C0 FD FF FF FF   mov rax, -3
//   0F 05                  syscall
//
//   // 4) SysRecv(cap=1) — fetches the sender's byte into rdx.
//   48 C7 C7 01 00 00 00   mov rdi, 1
//   48 C7 C0 FB FF FF FF   mov rax, -5
//   0F 05                  syscall
//
//   // 5) save received rdx, then store + load through V.
//   48 89 D1               mov rcx, rdx        ; rcx = received byte
//   48 BA <V64>            mov rdx, V
//   88 0A                  mov [rdx], cl       ; store low byte
//   48 0F B6 3A            movzx rdi, byte [rdx] ; load back
//
//   // 6) putchar(loaded byte)
//   48 C7 C0 F7 FF FF FF   mov rax, -9
//   0F 05                  syscall
//
//   // 7) spin
//   EB FE                  jmp $-0
//
// V = 0x0000_0100_0050_0000 → little-endian: 00 00 50 00 00 01 00 00.
#[rustfmt::skip]
const RECEIVER_PAYLOAD: &[u8] = &[
    // 1) putchar('A')
    0x48, 0xC7, 0xC7, 0x41, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC0, 0xF7, 0xFF, 0xFF, 0xFF,
    0x0F, 0x05,

    // 2) Untyped::Retype
    0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00,         // rdi=2
    0x48, 0xC7, 0xC6, 0x00, 0x10, 0x00, 0x00,         // rsi=0x1000
    0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00,         // rdx=7
    0x49, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,         // r10=1
    0x49, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00,         // r8=3
    0x48, 0xC7, 0xC0, 0xFD, 0xFF, 0xFF, 0xFF,         // rax=-3
    0x0F, 0x05,

    // 3) Frame::Map(V, RW)
    0x48, 0xC7, 0xC7, 0x03, 0x00, 0x00, 0x00,         // rdi=3
    0x48, 0xC7, 0xC6, 0x00, 0x70, 0x02, 0x00,         // rsi=0x27000
    0x48, 0xBA, 0x00, 0x00, 0x50, 0x00, 0x00, 0x01, 0x00, 0x00, // rdx=V
    0x49, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00,         // r10=3
    0x48, 0xC7, 0xC0, 0xFD, 0xFF, 0xFF, 0xFF,         // rax=-3
    0x0F, 0x05,

    // 4) SysRecv(cap=1)
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,         // rdi=1
    0x48, 0xC7, 0xC0, 0xFB, 0xFF, 0xFF, 0xFF,         // rax=-5
    0x0F, 0x05,

    // 5) save rdx → rcx, reload V, store, load
    0x48, 0x89, 0xD1,                                 // mov rcx, rdx
    0x48, 0xBA, 0x00, 0x00, 0x50, 0x00, 0x00, 0x01, 0x00, 0x00, // mov rdx, V
    0x88, 0x0A,                                       // mov [rdx], cl
    0x48, 0x0F, 0xB6, 0x3A,                           // movzx rdi, byte [rdx]

    // 6) putchar(rdi)
    0x48, 0xC7, 0xC0, 0xF7, 0xFF, 0xFF, 0xFF,         // rax=-9
    0x0F, 0x05,

    // 7) spin
    0xEB, 0xFE,
];

#[repr(C, align(4096))]
struct UserPage([u8; 4096]);

static mut SENDER_CODE_PAGE: UserPage = UserPage([0; 4096]);
static mut SENDER_STACK_PAGE: UserPage = UserPage([0; 4096]);
static mut RECEIVER_CODE_PAGE: UserPage = UserPage([0; 4096]);
static mut RECEIVER_STACK_PAGE: UserPage = UserPage([0; 4096]);

/// Phase 28h — ping thread for the SMP demo. Runs on AP1 (or the
/// first available AP) in user mode; loops on `SysYield` so each
/// iteration ticks `smp::SYSCALL_COUNT_PER_CPU[1]` and the BSP can
/// observe AP execution end-to-end.
///
/// Hand-assembled:
///   00: 48 C7 C0 F9 FF FF FF    mov rax, -7   (SysYield)
///   07: 0F 05                   syscall
///   09: EB F5                   jmp -11       (back to byte 0)
#[rustfmt::skip]
const PING_PAYLOAD: &[u8] = &[
    0x48, 0xC7, 0xC0, 0xF9, 0xFF, 0xFF, 0xFF, // mov rax, -7
    0x0F, 0x05,                               // syscall
    0xEB, 0xF5,                               // jmp -11
];

static mut PING_CODE_PAGE: UserPage = UserPage([0; 4096]);
static mut PING_STACK_PAGE: UserPage = UserPage([0; 4096]);

const PING_CODE_VBASE: u64 = 0x0000_0100_0010_0000;
const PING_STACK_VBASE: u64 = 0x0000_0100_0011_0000;

/// Backing memory the receiver's Untyped cap describes. The user
/// code retypes a 4 KiB Frame out of this pool and maps it; the
/// store/load through the mapping must hit real RAM, so we back
/// the Untyped with a 16 KiB BSS pool.
#[repr(C, align(4096))]
struct DemoPool([u8; 16 * 1024]);
static mut DEMO_POOL: DemoPool = DemoPool([0; 16 * 1024]);

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

        // Phase 24: each thread gets its own PML4. Map only the
        // pages each thread should be able to see — sender sees
        // sender code/stack, receiver sees receiver code/stack
        // (plus, after Retype/Map, its DEMO_POOL frame).
        let sender_pml4 = super::paging::make_user_pml4();
        let receiver_pml4 = super::paging::make_user_pml4();

        map_user_4k_into_pml4(sender_pml4, SENDER_CODE_VBASE,
            kernel_virt_to_phys((&raw const SENDER_CODE_PAGE) as u64), false);
        map_user_4k_into_pml4(sender_pml4, SENDER_STACK_VBASE,
            kernel_virt_to_phys((&raw const SENDER_STACK_PAGE) as u64), true);
        map_user_4k_into_pml4(receiver_pml4, RECEIVER_CODE_VBASE,
            kernel_virt_to_phys((&raw const RECEIVER_CODE_PAGE) as u64), false);
        map_user_4k_into_pml4(receiver_pml4, RECEIVER_STACK_VBASE,
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

        // Phase 21: receiver gets an Untyped cap at slot 2
        // pointing at DEMO_POOL. The user payload retypes a 4 KiB
        // frame out of this pool and maps it.
        let pool_va = (&raw const DEMO_POOL) as u64;
        let pool_pa = kernel_virt_to_phys(pool_va);
        let untyped_cap = Cap::Untyped {
            ptr: PPtr::<crate::cap::UntypedStorage>::new(pool_pa).unwrap(),
            block_bits: 14, // 16 KiB
            free_index: 0,
            is_device: false,
        };
        s.cnodes[2].0[2] = Cte::with_cap(&untyped_cap);

        // Spawn the two TCBs, each with its own CR3.
        let sender = spawn_thread(
            sender_cnode,
            SENDER_CODE_VBASE,
            SENDER_STACK_VBASE + 0x1000 - 8,
            sender_pml4,
        );
        let receiver = spawn_thread(
            receiver_cnode,
            RECEIVER_CODE_VBASE,
            RECEIVER_STACK_VBASE + 0x1000 - 8,
            receiver_pml4,
        );

        // Set the kernel rsp the SYSCALL entry stub uses.
        let rsp: u64;
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
        set_syscall_kernel_rsp(rsp);

        // Demote the boot thread out of the way: keep it as a TCB
        // for fallback but mark it Inactive so choose_thread skips
        // it. Both demo TCBs sit at higher priority anyway.
        if let Some(boot) = s.scheduler.current() {
            s.scheduler.block(boot, ThreadStateType::Inactive);
        }
        // Pick the receiver to run first — that way it'll park on
        // SysRecv and the sender's first SysSend has a peer waiting.
        // Actually, simpler: run the sender first; with no waiter
        // it blocks on the endpoint queue, scheduler picks the
        // receiver next, receiver receives, both unblock, both
        // continue (and each issues the putchar).
        s.scheduler.set_current(Some(sender));

        // Arm the demo flag. The syscall dispatcher checks this on
        // every SysDebugPutChar and bumps IPC_PRINTED; once it sees
        // ≥ 2 it exits QEMU.
        IPC_DEMO_ACTIVE.store(true, Ordering::Relaxed);

        // Swap CR3 to the sender's PML4 before sysretq — the
        // user code page lives in `sender_pml4`, not the kernel
        // tables we've been running in.
        asm!("mov cr3, {}", in(reg) sender_pml4,
            options(nostack, preserves_flags));

        // First-launch the sender.
        let ctx = s.scheduler.slab.get(sender).user_context;
        let _ = receiver; // suppress unused if receiver isn't reached on first hop
        enter_user_via_sysret(&ctx);
    }
}

/// Phase 28h — set up a "ping" thread pinned to CPU 1 and kick AP1
/// to dispatch it. The thread runs an endless `SysYield` loop in
/// user mode; each iteration ticks `smp::SYSCALL_COUNT_PER_CPU[1]`
/// so the BSP can verify a user thread is actually executing on
/// AP1.
///
/// Caller-side (BSP) is responsible for ensuring `install_kernel_page_tables`
/// has run (so make_user_pml4 can build a fresh PML4 with the kernel
/// half mirrored). Returns the admitted TcbId so the caller can
/// keep a handle if needed; for the spec we just discard.
pub unsafe fn launch_smp_ping_thread() -> crate::tcb::TcbId {
    install_kernel_page_tables();
    copy_payload(&raw const PING_CODE_PAGE, PING_PAYLOAD);

    let pml4 = super::paging::make_user_pml4();
    map_user_4k_into_pml4(
        pml4, PING_CODE_VBASE,
        kernel_virt_to_phys((&raw const PING_CODE_PAGE) as u64),
        false,
    );
    map_user_4k_into_pml4(
        pml4, PING_STACK_VBASE,
        kernel_virt_to_phys((&raw const PING_STACK_PAGE) as u64),
        true,
    );

    let s = KERNEL.get();
    let mut t = Tcb::default();
    t.priority = 100;
    t.state = ThreadStateType::Running;
    t.affinity = 1; // pin to CPU 1 (AP1)
    t.user_context = UserContext::for_entry(
        PING_CODE_VBASE,
        PING_STACK_VBASE + 0x1000 - 8,
        /* arg0 */ 0,
    );
    t.cpu_context.cr3 = pml4;
    let id = s.scheduler.admit(t);

    // Reschedule IPI tells AP1 to run choose_thread. After the ISR
    // returns, AP1's `ap_scheduler_loop` body sees `current=Some(id)`
    // and dispatches.
    crate::smp::kick_cpu(1);
    id
}

unsafe fn spawn_thread(
    cspace_root_ptr: PPtr<crate::cap::CNodeStorage>,
    user_rip: u64,
    user_rsp: u64,
    pml4_paddr: u64,
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
    t.cpu_context.cr3 = pml4_paddr;
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

/// Public-from-arch helper: install a 4 KiB user-accessible
/// mapping in the live (CR3) page tables. Re-export of the
/// internal `map_user_4k` so the invocation layer can call it
/// for `Cap::Frame::Map` — Frame::Map always installs in the
/// invoker's vspace, which is whatever CR3 currently points at.
pub unsafe fn map_user_4k_public(vaddr: u64, paddr: u64, writable: bool) {
    let pml4 = (read_cr3() & 0xFFFF_F000) as *mut u64;
    map_user_4k_in(pml4, vaddr, paddr, writable);
}

/// Phase 28g — clear the 4 KiB PTE for `vaddr` in the live PML4
/// and `invlpg` it on the calling CPU. The caller is responsible
/// for fanning a TLB-shootdown IPI to other CPUs that may have
/// the mapping cached.
///
/// Walks the page tables; if any intermediate level is missing or
/// uses a 1G/2M page, leaves the structure alone (the cap-state
/// invariant says we only Unmap pages that Frame::Map installed
/// at 4 KiB granularity, but we're defensive).
pub unsafe fn unmap_user_4k_public(vaddr: u64) {
    use super::paging::{PTE_PRESENT, PTE_PS};
    let pml4 = (read_cr3() & 0xFFFF_F000) as *mut u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
    if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 { return; }
    let pdpt = (pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
    if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS != 0 { return; }
    let pd = (pdpte & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pde = core::ptr::read_volatile(pd.add(pd_idx));
    if pde & PTE_PRESENT == 0 || pde & PTE_PS != 0 { return; }
    let pt = (pde & 0x000F_FFFF_FFFF_F000) as *mut u64;

    core::ptr::write_volatile(pt.add(pt_idx), 0);
    asm!("invlpg [{a}]", a = in(reg) vaddr, options(nostack, preserves_flags));
}

/// Phase 24 — install a 4 KiB mapping into an explicit PML4
/// (used at thread-spawn time before we've switched CR3 to it).
pub unsafe fn map_user_4k_into_pml4(
    pml4_paddr: u64,
    vaddr: u64,
    paddr: u64,
    writable: bool,
) {
    let pml4 = pml4_paddr as *mut u64;
    map_user_4k_in(pml4, vaddr, paddr, writable);
}

unsafe fn map_user_4k(vaddr: u64, paddr: u64, writable: bool) {
    let pml4 = (read_cr3() & 0xFFFF_F000) as *mut u64;
    map_user_4k_in(pml4, vaddr, paddr, writable);
}

unsafe fn map_user_4k_in(pml4: *mut u64, vaddr: u64, paddr: u64, writable: bool) {
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

/// Phase 26 — install an intermediate paging structure into the
/// invoker's vspace (i.e. the live CR3 PML4). `level` selects the
/// parent table the entry is written into:
///   * `level=3` → PML4 entry at index `vaddr >> 39`. Used to map a
///     `Cap::Pdpt` into a vspace.
///   * `level=2` → PDPT entry at index `vaddr >> 30`. Used to map a
///     `Cap::PageDirectory`. Walks PML4 to find the PDPT.
///   * `level=1` → PD entry at index `vaddr >> 21`. Used to map a
///     `Cap::PageTable`. Walks PML4 → PDPT to find the PD.
///
/// Returns false if a parent entry is missing (caller should map
/// the higher-level structure first) or if the target entry is
/// already present (caller should Unmap first).
pub unsafe fn install_user_table(level: u32, vaddr: u64, table_paddr: u64) -> bool {
    let pml4 = (read_cr3() & 0xFFFF_F000) as *mut u64;
    install_user_table_in(pml4, level, vaddr, table_paddr)
}

unsafe fn install_user_table_in(
    pml4: *mut u64,
    level: u32,
    vaddr: u64,
    table_paddr: u64,
) -> bool {
    use super::paging::PTE_PS;
    let flags = PTE_PRESENT | PTE_RW | PTE_USER;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;

    let entry_ptr: *mut u64 = match level {
        3 => pml4.add(pml4_idx),
        2 => {
            let e = core::ptr::read_volatile(pml4.add(pml4_idx));
            if e & PTE_PRESENT == 0 || e & PTE_PS != 0 {
                return false;
            }
            ((e & 0x000F_FFFF_FFFF_F000) as *mut u64).add(pdpt_idx)
        }
        1 => {
            let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
            if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
                return false;
            }
            let pdpt = (pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
            let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
            if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS != 0 {
                return false;
            }
            ((pdpte & 0x000F_FFFF_FFFF_F000) as *mut u64).add(pd_idx)
        }
        _ => return false,
    };

    let cur = core::ptr::read_volatile(entry_ptr);
    if cur & PTE_PRESENT != 0 {
        return false;
    }
    core::ptr::write_volatile(entry_ptr, (table_paddr & !0xFFF) | flags);
    true
}

// Make Syscall referenced so unused-import lint doesn't fire when
// the demo code paths sit alongside.
#[allow(dead_code)]
const _SYSCALL_USED: Syscall = Syscall::SysDebugPutChar;
