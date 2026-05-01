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
use crate::cap::{
    Cap, FrameRights, FrameSize, FrameStorage, PPtr, Pml4Storage,
    UntypedStorage,
};
use crate::cte::Cte;
use crate::elf::{self, LoadSegment};
use crate::kernel::{KernelState, KERNEL};
use crate::rootserver_image::ROOTSERVER_ELF;
use crate::tcb::{Tcb, ThreadStateType};
use crate::types::{
    seL4_BootInfo, seL4_SlotPos, seL4_SlotRegion, seL4_UntypedDesc,
    seL4_Word as Word, CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS,
};

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

/// Vaddr where the rootserver finds its IPC buffer (one 4 KiB page).
/// Maps to `seL4_CapInitThreadIPCBuffer` (slot 10) in the rootserver's
/// CNode.
pub const ROOTSERVER_IPCBUF_VBASE: u64 = 0x0000_0100_0060_0000;

/// Vaddr where the rootserver finds its `seL4_BootInfo` struct.
/// Maps to `seL4_CapBootInfoFrame` (slot 9). The kernel writes the
/// struct here before dispatch and passes this vaddr to `_start` via
/// `rdi`, so the rootserver can read it without any prior cap
/// invocation.
pub const ROOTSERVER_BOOTINFO_VBASE: u64 = 0x0000_0100_0070_0000;

/// Kernel-side CNode index reserved for the rootserver's CSpace.
/// Matches the existing convention from the AY demo (CNodes 1, 2 went
/// to sender/receiver). cnode_ptr(3) backs `Cap::CNode` slot 2 in the
/// rootserver's own CNode.
pub const ROOTSERVER_CNODE_IDX: usize = 3;

/// Backing memory for the rootserver's only Untyped cap. 16 KiB
/// (block_bits=14) is enough to retype a child TCB + CNode +
/// Endpoint in Phase 29g. Reserved as a static so the physical
/// address is stable across runs.
#[repr(C, align(4096))]
struct UntypedPool([u8; 16 * 1024]);
static mut ROOTSERVER_UNTYPED_POOL: UntypedPool = UntypedPool([0; 16 * 1024]);
const ROOTSERVER_UNTYPED_BITS: u8 = 14;

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
    /// Physical address of the rootserver's IPC buffer page. The
    /// kernel maps it at `ROOTSERVER_IPCBUF_VBASE` and stores a
    /// Frame cap pointing at this paddr in slot 10 of the
    /// rootserver's CNode.
    pub ipc_buffer_paddr: u64,
    /// Physical address of the BootInfo page. Maps at
    /// `ROOTSERVER_BOOTINFO_VBASE`; slot 9.
    pub bootinfo_paddr: u64,
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

    // The linker may emit several PT_LOAD segments that share a
    // single 4 KiB page (e.g. read-only data + .text both starting
    // mid-page). We track already-allocated pages so we don't
    // double-allocate or double-map; subsequent segments touching
    // the same page just write into it at the right offset.
    let mut seen: [PageMapping; 32] = [PageMapping { vaddr: 0, kvaddr: 0 }; 32];
    let mut n_seen: usize = 0;

    for seg in img.load_segments() {
        load_segment(pml4, &seg, &mut seen, &mut n_seen)?;
    }

    // Allocate + map the user stack page.
    let stack_p = alloc_page();
    let stack_phys = kernel_virt_to_phys(stack_p as u64);
    map_user_4k_into_pml4(pml4, STACK_PAGE_VBASE, stack_phys, /* writable */ true);

    // Allocate + map the IPC buffer page.
    let ipcbuf_p = alloc_page();
    let ipcbuf_phys = kernel_virt_to_phys(ipcbuf_p as u64);
    map_user_4k_into_pml4(pml4, ROOTSERVER_IPCBUF_VBASE, ipcbuf_phys, true);

    // Allocate + map the BootInfo page (read-only — userspace reads
    // it but doesn't mutate). The kernel writes the struct via
    // its kernel-half mapping before dispatch.
    let bi_p = alloc_page();
    let bi_phys = kernel_virt_to_phys(bi_p as u64);
    map_user_4k_into_pml4(pml4, ROOTSERVER_BOOTINFO_VBASE, bi_phys, false);

    Ok(RootserverImage {
        pml4_paddr: pml4,
        entry: img.entry,
        stack_top: ROOTSERVER_STACK_VTOP,
        ipc_buffer_paddr: ipcbuf_phys,
        bootinfo_paddr: bi_phys,
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
/// its TCB + CSpace, writes the BootInfo page, demotes the boot
/// thread, swaps CR3, and `sysretq`s into user mode. Never returns;
/// the dispatcher's QEMU-exit hook fires once the rootserver prints
/// `\n`.
pub unsafe fn launch_rootserver() -> ! {
    install_kernel_page_tables();

    let img = load().expect("rootserver loads");

    let s = KERNEL.get();

    // Build the rootserver's CNode (slot 2 of itself = `seL4_CapInitThreadCNode`).
    let cnode_ptr = KernelState::cnode_ptr(ROOTSERVER_CNODE_IDX);
    let cnode_cap = Cap::CNode {
        ptr: cnode_ptr,
        radix: 5,
        guard_size: 59,
        guard: 0,
    };
    // Wipe the CNode in case prior specs left state.
    for slot in s.cnodes[ROOTSERVER_CNODE_IDX].0.iter_mut() {
        slot.set_cap(&Cap::Null);
    }

    // Build the TCB. cspace_root points at the new CNode; the
    // dispatcher consults this for cap lookups.
    let mut t = Tcb::default();
    t.priority = 100;
    t.state = ThreadStateType::Running;
    t.affinity = 0;
    t.user_context = UserContext::for_entry(
        img.entry,
        img.stack_top - 8,
        /* rdi (arg0) */ ROOTSERVER_BOOTINFO_VBASE,
    );
    t.cpu_context.cr3 = img.pml4_paddr;
    t.cspace_root = cnode_cap;
    t.vspace_root = Cap::PML4 {
        ptr: PPtr::<Pml4Storage>::new(img.pml4_paddr).expect("pml4 paddr"),
        mapped: true,
        asid: 0,
    };
    let id = s.scheduler.admit(t);

    // Populate the rootserver's CNode with the canonical initial
    // cap layout (subset of seL4's seL4_RootCNodeCapSlots). The
    // rootserver's own startup code can now invoke any of these by
    // CPtr.
    s.cnodes[ROOTSERVER_CNODE_IDX].0[1] = Cte::with_cap(&Cap::Thread {
        // `decode_tcb` recovers the TcbId via `tcb_ptr.addr() as u16`,
        // so we encode the TcbId directly (slab IDs start from 1
        // after the boot thread, so `PPtr::new` always succeeds).
        tcb: PPtr::<crate::cap::Tcb>::new(id.0 as u64).expect("nonzero tcb id"),
    });
    s.cnodes[ROOTSERVER_CNODE_IDX].0[2] = Cte::with_cap(&cnode_cap);
    s.cnodes[ROOTSERVER_CNODE_IDX].0[3] = Cte::with_cap(&Cap::PML4 {
        ptr: PPtr::<Pml4Storage>::new(img.pml4_paddr).expect("pml4 paddr"),
        mapped: true,
        asid: 0,
    });
    s.cnodes[ROOTSERVER_CNODE_IDX].0[9] = Cte::with_cap(&Cap::Frame {
        ptr: PPtr::<FrameStorage>::new(img.bootinfo_paddr).expect("bi paddr"),
        size: FrameSize::Small,
        rights: FrameRights::ReadOnly,
        mapped: Some(ROOTSERVER_BOOTINFO_VBASE),
        asid: 0,
        is_device: false,
    });
    s.cnodes[ROOTSERVER_CNODE_IDX].0[10] = Cte::with_cap(&Cap::Frame {
        ptr: PPtr::<FrameStorage>::new(img.ipc_buffer_paddr).expect("ipc paddr"),
        size: FrameSize::Small,
        rights: FrameRights::ReadWrite,
        mapped: Some(ROOTSERVER_IPCBUF_VBASE),
        asid: 0,
        is_device: false,
    });
    // First Untyped at slot 11. 16 KiB, in BSS-backed memory.
    let untyped_pool_va = (&raw const ROOTSERVER_UNTYPED_POOL) as u64;
    let untyped_pool_pa =
        crate::arch::x86_64::paging::kernel_virt_to_phys(untyped_pool_va);
    s.cnodes[ROOTSERVER_CNODE_IDX].0[11] = Cte::with_cap(&Cap::Untyped {
        ptr: PPtr::<UntypedStorage>::new(untyped_pool_pa).expect("ut paddr"),
        block_bits: ROOTSERVER_UNTYPED_BITS,
        free_index: 0,
        is_device: false,
    });

    // Build + write the BootInfo struct into its page. We address
    // it via its kernel-virt mapping (still BOOTBOOT-identity-mapped)
    // before the CR3 swap; the rootserver reads it through its
    // user-half mapping after sysretq.
    let bi_ptr = phys_to_kernel_virt(img.bootinfo_paddr) as *mut seL4_BootInfo;
    let bi = build_bootinfo(img.ipc_buffer_paddr, untyped_pool_pa);
    core::ptr::write(bi_ptr, bi);

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

    // Swap CR3 to the rootserver's PML4 (kernel half preserved).
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) img.pml4_paddr,
        options(nostack, preserves_flags),
    );

    let ctx = s.scheduler.slab.get(id).user_context;
    enter_user_via_sysret(&ctx);
}

/// Convert a physical address to its kernel-virt counterpart. The
/// kernel runs with BOOTBOOT's identity map for low memory, so the
/// kernel virt of a physical page is just `paddr +
/// KERNEL_VIRT_TO_PHYS_OFFSET`. We avoid exposing the offset
/// directly; just invert `kernel_virt_to_phys`.
unsafe fn phys_to_kernel_virt(paddr: u64) -> u64 {
    // KERNEL_VIRT_TO_PHYS_OFFSET is set by `install_kernel_page_tables`.
    // Recover it by translating a known kernel symbol.
    let probe_va = (&raw const ROOTSERVER_PAGE_POOL) as u64;
    let probe_pa = kernel_virt_to_phys(probe_va);
    let offset = probe_va - probe_pa;
    paddr + offset
}

unsafe fn build_bootinfo(ipc_buffer_paddr: u64, _untyped_paddr: u64) -> seL4_BootInfo {
    let mut empty_untypeds = [seL4_UntypedDesc::default();
        CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS];
    // Describe the single rootserver Untyped (slot 11).
    empty_untypeds[0] = seL4_UntypedDesc {
        paddr: _untyped_paddr,
        sizeBits: ROOTSERVER_UNTYPED_BITS,
        isDevice: 0,
        padding: [0; 6],
    };

    seL4_BootInfo {
        extraLen: 0,
        nodeID: 0,
        numNodes: crate::bootboot::get_num_cores() as Word,
        numIOPTLevels: 0,
        ipcBuffer: ROOTSERVER_IPCBUF_VBASE as *mut crate::types::seL4_IPCBuffer,
        // Empty cap slots = 12..32 (CNode is radix=5 → 32 slots,
        // and we populated 0/1/2/3/9/10/11).
        empty: seL4_SlotRegion { start: 12, end: 32 },
        sharedFrames: seL4_SlotRegion { start: 0, end: 0 },
        userImageFrames: seL4_SlotRegion { start: 0, end: 0 },
        userImagePaging: seL4_SlotRegion { start: 0, end: 0 },
        ioSpaceCaps: seL4_SlotRegion { start: 0, end: 0 },
        extraBIPages: seL4_SlotRegion { start: 0, end: 0 },
        initThreadCNodeSizeBits: 5,
        initThreadDomain: 0,
        untyped: seL4_SlotRegion { start: 11, end: 12 },
        untypedList: empty_untypeds,
    }
}

// suppress unused parameter warning in helper above
#[allow(dead_code)]
fn _silence_seL4_slotpos_unused(_: seL4_SlotPos) {}

/// Tracks "this page-aligned vaddr has already been allocated +
/// mapped, with kernel-virt = `kvaddr`". Used so multiple PT_LOAD
/// segments that share a 4 KiB page don't fight over allocation.
#[derive(Copy, Clone)]
struct PageMapping {
    vaddr: u64,
    kvaddr: u64,
}

unsafe fn load_segment(
    pml4: u64,
    seg: &LoadSegment,
    seen: &mut [PageMapping],
    n_seen: &mut usize,
) -> Result<(), LoadError> {
    // Iterate every 4 KiB page that the segment touches. We don't
    // require `vaddr` to be page-aligned (lld emits overlapping R-only
    // segments mid-page).
    let start_page = seg.vaddr & !0xFFF;
    let end_page = (seg.vaddr + seg.mem_size + 0xFFF) & !0xFFF;

    let mut page_vaddr = start_page;
    while page_vaddr < end_page {
        // Find or allocate the kernel-virt backing for this page.
        let kva = match find_seen(seen, *n_seen, page_vaddr) {
            Some(kv) => kv,
            None => {
                let p = alloc_page() as u64;
                let phys = kernel_virt_to_phys(p);
                map_user_4k_into_pml4(
                    pml4, page_vaddr, phys, /* writable */ seg.writable(),
                );
                if *n_seen >= seen.len() {
                    return Err(LoadError::UnalignedSegment); // pool small
                }
                seen[*n_seen] = PageMapping { vaddr: page_vaddr, kvaddr: p };
                *n_seen += 1;
                p
            }
        };

        // Copy the slice of this segment that lies in this page:
        // [max(seg.vaddr, page_vaddr) .. min(seg.vaddr + filesize, page_vaddr + 4096)).
        // Anything beyond filesize stays zero (BSS tail; alloc_page
        // zero-filled).
        let seg_file_end = seg.vaddr + seg.file_size;
        let copy_start = seg.vaddr.max(page_vaddr);
        let copy_end = seg_file_end.min(page_vaddr + 0x1000);
        if copy_end > copy_start {
            let file_off = seg.file_off + (copy_start - seg.vaddr);
            let src = ROOTSERVER_ELF.as_ptr().add(file_off as usize);
            let dst = (kva + (copy_start - page_vaddr)) as *mut u8;
            let len = (copy_end - copy_start) as usize;
            core::ptr::copy_nonoverlapping(src, dst, len);
        }

        page_vaddr += 0x1000;
    }

    Ok(())
}

fn find_seen(seen: &[PageMapping], n: usize, vaddr: u64) -> Option<u64> {
    for i in 0..n {
        if seen[i].vaddr == vaddr {
            return Some(seen[i].kvaddr);
        }
    }
    None
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
