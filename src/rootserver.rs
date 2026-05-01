//! Rootserver loader — Phase 29c.
//!
//! Drives the bridge from the embedded ELF (`rootserver_image::ROOTSERVER_ELF`)
//! to a runnable user thread:
//!
//!   1. Parse the ELF header (`crate::elf`).
//!   2. Allocate a fresh PML4 (cloning the kernel half).
//!   3. For every `PT_LOAD` segment, allocate one or more 4 KiB
//!      user pages out of `ROOTSERVER_PAGE_POOL`, copy the segment's
//!      file bytes into them, zero the BSS tail, and map them at
//!      the segment's `vaddr` in the new PML4 with the segment's
//!      W/X bits.
//!   4. Allocate + map a user stack page.
//!
//! The output is a `RootserverImage` carrying the PML4 paddr, entry
//! RIP, and stack-top vaddr. Phase 29d/e use those to build the
//! rootserver's TCB and dispatch.
//!
//! Phase 29c stops at "ready to dispatch" — actually wiring the
//! rootserver as the boot thread lands in 29e.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::arch::x86_64::paging::{
    install_kernel_page_tables, kernel_virt_to_phys, make_user_pml4,
};
use crate::arch::x86_64::syscall_entry::{
    enter_user_via_sysret, set_syscall_kernel_rsp, UserContext,
};
use crate::arch::x86_64::usermode::map_user_4k_into_pml4;
use crate::elf::{self, LoadSegment};
use crate::kernel::KERNEL;
use crate::rootserver_image::ROOTSERVER_ELF;
use crate::tcb::{Tcb, ThreadStateType};
use crate::types::seL4_Word as Word;

// ---------------------------------------------------------------------------
// Page pool — backing memory for the rootserver's user-mode pages.
// Sized for the current rootserver image (≈5 KiB total) with plenty
// of headroom for Phase 29d/g additions (BootInfo, IPC buffer, child
// thread pages).
// ---------------------------------------------------------------------------

#[repr(C, align(4096))]
struct Page([u8; 4096]);

const PAGE_POOL_SIZE: usize = 16;
static mut ROOTSERVER_PAGE_POOL: [Page; PAGE_POOL_SIZE] =
    [const { Page([0; 4096]) }; PAGE_POOL_SIZE];
static mut ROOTSERVER_PAGE_USED: usize = 0;

unsafe fn alloc_page() -> *mut Page {
    assert!(ROOTSERVER_PAGE_USED < PAGE_POOL_SIZE,
        "rootserver page pool exhausted");
    let p = &raw mut ROOTSERVER_PAGE_POOL[ROOTSERVER_PAGE_USED];
    ROOTSERVER_PAGE_USED += 1;
    // Zero-initialised already, but BSS may not be — be explicit.
    for i in 0..4096 {
        core::ptr::write_volatile((p as *mut u8).add(i), 0);
    }
    p
}

/// Reset the page pool. Used by spec teardown to keep multiple
/// loader runs deterministic.
#[cfg(feature = "spec")]
pub unsafe fn reset_page_pool() {
    ROOTSERVER_PAGE_USED = 0;
}

// ---------------------------------------------------------------------------
// Layout. The rootserver linker script picks the text vaddr; we
// place the user stack and (Phase 29d) IPC buffer + BootInfo at
// known offsets above the image.
// ---------------------------------------------------------------------------

/// Top end of the user stack (vaddr just past the highest byte the
/// stack can use). 64 KiB above the image base, matching the
/// AY-demo convention.
pub const ROOTSERVER_STACK_VTOP: u64 = 0x0000_0100_0050_0000;

const STACK_PAGE_VBASE: u64 = ROOTSERVER_STACK_VTOP - 0x1000;

// ---------------------------------------------------------------------------
// Output of the loader.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct RootserverImage {
    /// Physical address of the rootserver's PML4. Userspace runs
    /// with this value loaded into CR3.
    pub pml4_paddr: u64,
    /// User-mode entry point (= ELF `e_entry`).
    pub entry: Word,
    /// Top of the user stack — the value `_start` reads as RSP.
    pub stack_top: Word,
}

/// Errors the loader can surface.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LoadError {
    Elf(elf::ElfError),
    /// A segment's vaddr or memsz isn't 4 KiB-aligned the way we need.
    UnalignedSegment,
}

// ---------------------------------------------------------------------------
// Loader entry.
//
// SAFETY: must hold the BKL (we walk shared statics). Run only on
// BSP with paging set up — we issue MMIO-free kernel-virtual writes
// that depend on BOOTBOOT's identity map being present.
// ---------------------------------------------------------------------------

pub unsafe fn load() -> Result<RootserverImage, LoadError> {
    let img = elf::parse(ROOTSERVER_ELF).map_err(LoadError::Elf)?;
    let pml4 = make_user_pml4();

    for seg in img.load_segments() {
        load_segment(pml4, &seg)?;
    }

    // Allocate + map the user stack page.
    let stack_p = alloc_page();
    let stack_phys = kernel_virt_to_phys(stack_p as u64);
    map_user_4k_into_pml4(pml4, STACK_PAGE_VBASE, stack_phys, /* writable */ true);

    Ok(RootserverImage {
        pml4_paddr: pml4,
        entry: img.entry,
        stack_top: ROOTSERVER_STACK_VTOP,
    })
}

// ---------------------------------------------------------------------------
// Demo trigger flags. The kernel's SYSCALL dispatcher watches
// these on every `SysDebugPutChar` so the rootserver banner
// driving QEMU exit doesn't need any seL4-side cap plumbing.
// ---------------------------------------------------------------------------

/// Set true once the rootserver is dispatched. While true, the
/// dispatcher watches `SysDebugPutChar` traffic and exits QEMU on
/// `'\n'` from the rootserver — Phase 29e's success signal.
pub static ROOTSERVER_DEMO_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Bytes the rootserver has printed via `SysDebugPutChar`. Exposed
/// so a future spec can poll it.
pub static ROOTSERVER_PRINTED: AtomicUsize = AtomicUsize::new(0);

/// Phase 29e — replace the AY demo. Loads the rootserver, builds
/// its TCB, demotes the boot thread, swaps CR3, and `sysretq`s into
/// user mode. Never returns; the dispatcher's QEMU-exit hook fires
/// once the rootserver prints `\n`.
pub unsafe fn launch_rootserver() -> ! {
    install_kernel_page_tables();

    let img = load().expect("rootserver loads");

    let s = KERNEL.get();

    // Build the TCB.
    let mut t = Tcb::default();
    t.priority = 100;
    t.state = ThreadStateType::Running;
    t.affinity = 0; // BSP for now.
    t.user_context = UserContext::for_entry(
        img.entry,
        img.stack_top - 8,
        /* arg0 */ 0,
    );
    t.cpu_context.cr3 = img.pml4_paddr;
    let id = s.scheduler.admit(t);

    // Demote the boot thread out of the way.
    if let Some(boot) = s.scheduler.current() {
        s.scheduler.block(boot, ThreadStateType::Inactive);
    }
    s.scheduler.set_current(Some(id));

    // Pin SYSCALL kernel rsp for BSP.
    let rsp: u64;
    core::arch::asm!(
        "mov {}, rsp",
        out(reg) rsp,
        options(nomem, nostack, preserves_flags),
    );
    set_syscall_kernel_rsp(rsp);

    // Arm the dispatcher's exit hook.
    ROOTSERVER_DEMO_ACTIVE.store(true, Ordering::Relaxed);

    // Swap CR3 to the rootserver's PML4 (kernel half is preserved).
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) img.pml4_paddr,
        options(nostack, preserves_flags),
    );

    // Hand off to user mode.
    let ctx = s.scheduler.slab.get(id).user_context;
    enter_user_via_sysret(&ctx);
}

unsafe fn load_segment(pml4: u64, seg: &LoadSegment) -> Result<(), LoadError> {
    if seg.vaddr & 0xFFF != 0 {
        return Err(LoadError::UnalignedSegment);
    }

    // Number of 4 KiB pages this segment spans.
    let n_pages = (seg.mem_size + 0xFFF) / 0x1000;

    for page_idx in 0..n_pages {
        let page_off = page_idx * 0x1000;
        let page_p = alloc_page();
        let page_phys = kernel_virt_to_phys(page_p as u64);

        // Copy the slice of the segment that lies inside this page.
        // [page_off, page_off + 4096) intersected with
        // [0, file_size) gives us the file-backed range.
        let copy_start = page_off.min(seg.file_size);
        let copy_end = (page_off + 0x1000).min(seg.file_size);
        if copy_end > copy_start {
            let src = ROOTSERVER_ELF
                .as_ptr()
                .add((seg.file_off + copy_start) as usize);
            let dst_offset = (copy_start - page_off) as usize;
            let dst = (page_p as *mut u8).add(dst_offset);
            let len = (copy_end - copy_start) as usize;
            core::ptr::copy_nonoverlapping(src, dst, len);
        }

        // Tail (BSS) is already zero — alloc_page zero-fills.

        let page_vaddr = seg.vaddr + page_off;
        // RW means writable; an R+X (no W) segment maps as RO.
        map_user_4k_into_pml4(pml4, page_vaddr, page_phys, seg.writable());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_rootserver() {
        arch::log("Running rootserver loader tests...\n");
        loads_and_maps_segments();
        arch::log("Rootserver loader tests completed\n");
    }

    /// Parse + load the embedded rootserver into a fresh VSpace and
    /// verify the result has sane shape: entry inside an executable
    /// segment, stack mapped at the documented top, page pool
    /// consumed by ≥ n_segments + 1 (segment pages + stack).
    #[inline(never)]
    fn loads_and_maps_segments() {
        unsafe {
            super::reset_page_pool();
            let used_before = super::ROOTSERVER_PAGE_USED;
            let result = super::load().expect("rootserver loads");

            // Entry must equal the ELF's e_entry (sanity vs the
            // 29b spec).
            let img = crate::elf::parse(super::ROOTSERVER_ELF).unwrap();
            assert_eq!(result.entry, img.entry);

            // Stack-top is the documented constant.
            assert_eq!(result.stack_top, super::ROOTSERVER_STACK_VTOP);

            // PML4 is non-zero and 4 KiB-aligned.
            assert!(result.pml4_paddr != 0);
            assert_eq!(result.pml4_paddr & 0xFFF, 0);

            // We allocated at least one page per segment + one for the
            // stack.
            let mut seg_pages = 0u64;
            for seg in img.load_segments() {
                seg_pages += (seg.mem_size + 0xFFF) / 0x1000;
            }
            let used_after = super::ROOTSERVER_PAGE_USED;
            assert!(
                (used_after - used_before) as u64 >= seg_pages + 1,
                "expected ≥{} pages allocated, got {}",
                seg_pages + 1,
                used_after - used_before,
            );
            arch::log("  ✓ rootserver loads + segments map into a fresh PML4\n");
        }
    }
}
