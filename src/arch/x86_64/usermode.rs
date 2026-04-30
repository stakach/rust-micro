//! Phase 13c — first ring-3 launch.
//!
//! Builds the smallest possible user-mode demonstration:
//!   * a hand-assembled 18-byte payload that issues one
//!     SysDebugPutChar('A') then spin-loops
//!   * a fresh user-accessible code page + stack page in BSS
//!   * an `iretq` frame that drops to CPL=3
//!
//! The kernel's SYSCALL entry stub catches the syscall, runs the
//! Rust dispatcher, and (because USERMODE_TEST_TRIGGERED is set)
//! exits QEMU with code 0 so the spec runner records success.
//! Without that signal, after `sysretq` the user code spins
//! forever — the boot-time test would never terminate.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use super::gdt::{USER_CS, USER_DS};
use super::paging::{
    install_kernel_page_tables, kernel_virt_to_phys, read_cr3,
    PTE_PRESENT, PTE_RW, PTE_USER,
};

// ---------------------------------------------------------------------------
// User payload + state pages.
//
// Hand-assembled, since we don't want to drag in a separate crate
// or build pipeline for a one-off blob:
//
//   48 c7 c7 41 00 00 00   mov rdi, 0x41        ; 'A'
//   48 c7 c0 f7 ff ff ff   mov rax, -9          ; SysDebugPutChar
//   0f 05                  syscall
//   eb fe                  jmp $-0              ; spin forever
// ---------------------------------------------------------------------------

const USER_PAYLOAD: &[u8; 18] = &[
    0x48, 0xC7, 0xC7, 0x41, 0x00, 0x00, 0x00, // mov rdi, 0x41
    0x48, 0xC7, 0xC0, 0xF7, 0xFF, 0xFF, 0xFF, // mov rax, -9
    0x0F, 0x05, // syscall
    0xEB, 0xFE, // jmp $-0
];

#[repr(C, align(4096))]
struct UserPage([u8; 4096]);

static mut USER_CODE_PAGE: UserPage = UserPage([0; 4096]);
static mut USER_STACK_PAGE: UserPage = UserPage([0; 4096]);

/// User-mode virtual addresses. BOOTBOOT identity-maps a generous
/// chunk of low physical memory using **1 GiB** pages — a 4 KiB
/// install at e.g. 0x4_0000 or 0x1_0000_0000 would collide with the
/// PS=1 PDPT entry. Place user pages in PML4[2] (1 TiB virtual)
/// where BOOTBOOT has nothing mapped, so `ensure_user_table` can
/// allocate fresh intermediate tables cleanly.
const USER_CODE_VBASE: u64 = 0x0000_0100_0000_0000; // 1 TiB
/// Stack grows down, so user `rsp` starts at
/// `USER_STACK_VBASE + 0x1000`.
const USER_STACK_VBASE: u64 = 0x0000_0100_0001_0000;

/// Set by `launch_user_mode_test` immediately before the iretq.
/// The Rust syscall dispatcher checks this flag and exits QEMU on
/// the very first SysDebugPutChar — without it, the user-mode spin
/// loop after sysretq would never let the test complete.
pub static USERMODE_TEST_TRIGGERED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Launch entry — mapped + iretq.
// ---------------------------------------------------------------------------

pub fn launch_user_mode_test() -> ! {
    unsafe {
        // Make sure the kernel's MMIO + virt→phys cache is in place.
        // (Idempotent if Phase 13b already ran.)
        install_kernel_page_tables();

        // Copy the payload into the user-mode code page.
        let code_va = (&raw const USER_CODE_PAGE) as *const u8 as *mut u8;
        for (i, b) in USER_PAYLOAD.iter().enumerate() {
            core::ptr::write_volatile(code_va.add(i), *b);
        }

        // Map both pages as user-accessible.
        let code_pa = kernel_virt_to_phys(code_va as u64);
        let stack_pa = kernel_virt_to_phys((&raw const USER_STACK_PAGE) as u64);
        map_user_4k(USER_CODE_VBASE, code_pa, /* writable */ false);
        map_user_4k(USER_STACK_VBASE, stack_pa, /* writable */ true);

        // Set the kernel rsp the SYSCALL entry stub will load when
        // user code traps in. Use the current rsp — Phase 11 left
        // a single boot stack which doubles as the kernel's syscall
        // stack until per-thread stacks land.
        let rsp: u64;
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
        super::syscall_entry::set_syscall_kernel_rsp(rsp);

        // Arm the test-done flag so the syscall dispatcher exits
        // QEMU on the first SysDebugPutChar.
        USERMODE_TEST_TRIGGERED.store(true, Ordering::Relaxed);

        // Build the iretq stack frame and drop to ring 3.
        //
        //   [rsp + 0x00] = user RIP
        //   [rsp + 0x08] = user CS  (with RPL=3)
        //   [rsp + 0x10] = user RFLAGS (IF=1 enables interrupts)
        //   [rsp + 0x18] = user RSP
        //   [rsp + 0x20] = user SS  (with RPL=3)
        let user_rip = USER_CODE_VBASE;
        let user_rsp = USER_STACK_VBASE + 0x1000 - 8; // 16-byte aligned post-push
        let user_rflags: u64 = 0x202; // bit 1 reserved=1, IF=1
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

unsafe fn map_user_4k(vaddr: u64, paddr: u64, writable: bool) {
    // Patch the live PML4 directly, same as paging::install_kernel
    // does for the LAPIC. Kernel-image identity map gives us a
    // physical-pointer view of all the page-table memory we'll
    // touch.
    let pml4 = (read_cr3() & 0xFFFF_F000) as *mut u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // Intermediate flags must include U=1 so user mode can walk
    // into them — the U/S bit is the AND of every level.
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
        // Existing entry — make sure it has U=1 so user-mode walks
        // succeed. seL4's `mapKernelWindow` does the same OR-in.
        let updated = entry | flags;
        if updated != entry {
            core::ptr::write_volatile(entry_ptr, updated);
        }
        return (entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
    }
    // Allocate a fresh table from the kernel pool.
    let table_v = super::paging::alloc_user_table_va();
    let table_p = kernel_virt_to_phys(table_v as u64);
    core::ptr::write_volatile(entry_ptr, (table_p & !0xFFF) | flags);
    table_p as *mut u64
}
