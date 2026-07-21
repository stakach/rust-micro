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
use crate::rootserver_image::rootserver_elf;
use crate::tcb::{Tcb, ThreadStateType};
use crate::types::{
    seL4_BootInfo, seL4_SlotPos, seL4_SlotRegion, seL4_UntypedDesc,
    seL4_Word as Word, CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS,
};

// ---------------------------------------------------------------------------
// Page pool — backing memory for the rootserver's user-mode pages.
//
// Phase 41 — instead of preallocating in kernel BSS (which doesn't
// scale; sel4test-driver alone is ~3.9 MiB of LOAD segments), we
// reserve a contiguous chunk of BOOTBOOT-identity-mapped low memory
// at boot time and hand out paddrs from it. `alloc_page` returns
// the paddr; because BOOTBOOT identity-maps the lower 1 GiB at
// PML4[0], that paddr also serves as a valid kernel-virtual pointer
// for the loader to memcpy ELF data into the page. No translation
// step needed.
//
// `boot::kernel_init` carves the chunk via `crate::boot::reserve`
// and calls `install_user_page_region` before the loader runs.
// ---------------------------------------------------------------------------

struct UserPageRegion {
    base_paddr: u64,
    size: u64,
    used: u64,
}

static mut USER_PAGE_REGION: UserPageRegion = UserPageRegion {
    base_paddr: 0,
    size: 0,
    used: 0,
};

/// Wire the boot-time-reserved low-memory region into the loader.
/// Call exactly once at boot, before `launch_rootserver`.
pub unsafe fn install_user_page_region(base_paddr: u64, size: u64) {
    USER_PAGE_REGION.base_paddr = base_paddr;
    USER_PAGE_REGION.size = size;
    USER_PAGE_REGION.used = 0;
}

/// Allocate a 4 KiB page from the user-page region. Returns the
/// paddr — also a valid kernel-virtual pointer (BOOTBOOT identity
/// at PML4[0]). The page is zero-filled before return.
unsafe fn alloc_page() -> u64 {
    let region = &raw mut USER_PAGE_REGION;
    let used = (*region).used;
    assert!(used + 4096 <= (*region).size,
        "rootserver user-page region exhausted: {}/{} bytes used",
        used, (*region).size);
    let paddr = (*region).base_paddr + used;
    (*region).used = used + 4096;
    // Zero the page through the kernel-half linear map.
    let p = crate::arch::x86_64::paging::phys_to_lin(paddr) as *mut u8;
    for i in 0..4096 {
        core::ptr::write_volatile(p.add(i), 0);
    }
    paddr
}

/// Reset the page pool. Used by spec teardown to keep multiple
/// loader runs deterministic.
#[cfg(feature = "spec")]
pub unsafe fn reset_page_pool() {
    USER_PAGE_REGION.used = 0;
}

// ---------------------------------------------------------------------------
// Layout. The rootserver linker script picks the text vaddr; we
// place the user stack and (Phase 29d) IPC buffer + BootInfo at
// known offsets above the image.
// ---------------------------------------------------------------------------

/// Number of 4 KiB pages reserved for the rootserver's user stack.
/// The NT executive has deep loader/component dispatch chains; keep enough headroom that adding a
/// late gate cannot move an allocator call into the guard page through optimizer spill changes.
const ROOTSERVER_STACK_PAGES: u64 = 8;

/// Kernel-side CNode index reserved for the rootserver's CSpace.
///
/// * sel4test (built-in rootserver): the big-pool CNode at virtual
///   index 3 (radix 12 = 4096 slots). Matches the AY-demo convention
///   (CNodes 1, 2 went to sender/receiver); cnode_ptr(3) backs
///   `Cap::CNode` slot 2 in the rootserver's own CNode.
/// * extern-rootserver (the NT executive): the executive allocates
///   caps monotonically into its root CNode and, when demand-paging
///   large DLLs, blows well past the 4096-slot big-pool ceiling. Back
///   its root CNode with the XL pool page (radix 17 = 131072 slots)
///   instead. The executive never allocates XL CNodes itself (its
///   spawned processes use CN_RADIX=5 → small pool), so xl[0] is free
///   to dedicate to the root task. This virtual index stays inside
///   `cnode_pool_count()` so revoke/delete pool scans still see it.
#[cfg(not(feature = "extern-rootserver"))]
pub const ROOTSERVER_CNODE_IDX: usize = 3;
#[cfg(feature = "extern-rootserver")]
pub const ROOTSERVER_CNODE_IDX: usize =
    crate::kernel::MAX_CNODES + crate::kernel::MAX_SMALL_CNODES;

/// Radix (log2 of the slot count) of the rootserver's root CNode.
/// Must match the storage width of the CNode page backing
/// `ROOTSERVER_CNODE_IDX`, and is what the cap's `radix`/`guard_size`
/// and `BootInfo.initThreadCNodeSizeBits`/`empty.end` are derived
/// from — they MUST all agree or cptr resolution corrupts.
#[cfg(not(feature = "extern-rootserver"))]
pub const ROOTSERVER_CNODE_RADIX: u8 = crate::kernel::CNODE_RADIX;
#[cfg(feature = "extern-rootserver")]
pub const ROOTSERVER_CNODE_RADIX: u8 = crate::kernel::XL_CNODE_RADIX;

/// The device untypeds exposed to the root task, as `(paddr, size_bits)`. This is
/// the SINGLE SOURCE OF TRUTH used both to stamp the untyped caps into the CSpace
/// (slots 21..) and to build the matching `BootInfo.untypedList` — they MUST agree,
/// or `bi.untyped` advertises a slot whose cap is missing/wrong (a device UT would
/// alias the first user-image-frame slot → retype yields a bad cap → map #PFs).
///   * 0x00080000 (512 KiB): low 1 MiB — BIOS/ACPI/legacy (sel4test ACPI discovery).
///   * 0xFEC00000 / 0xFED00000 / 0xFEE00000 (4 KiB each): IOAPIC / HPET / LAPIC MMIO.
///   * 0x81060000 (128 KiB): the e1000e NIC BAR0 (QEMU q35 assigns it here; the PCI
///     hole is at 0x80000000+ with 1 GiB RAM). Exposed so a driver host maps its regs.
pub const DEVICE_UTS: &[(u64, u8)] = &[
    (0x00080000, 19),
    (0xFEC00000, 12),
    (0xFED00000, 12),
    (0xFEE00000, 12),
    (0x81060000, 17), // e1000e (82574) NIC BAR0 (default q35 NIC)
    (0x81085000, 12), // AHCI ABAR (BAR5) of the add-in `-device ahci` (00:3.0) — boot disk on port 0
];

/// Phase 0a (extern-rootserver only) — the BOOTBOOT linear framebuffer,
/// exposed to the NT rootserver as one extra DEVICE untyped appended
/// after `DEVICE_UTS`. Returns `(paddr, block_bits, geometry)` where the
/// untyped covers `[fb_paddr, fb_paddr + 2^block_bits)` — `block_bits`
/// is the smallest power-of-two size (≥ the framebuffer's byte size, ≥
/// one 4 KiB frame) so the rootserver can retype every framebuffer
/// frame out of it. `fb_paddr` is 4 KiB-aligned (BOOTBOOT hands out a
/// page-aligned LFB); the kernel's `untyped_retype` hands out frames at
/// `base + i*4K` and imposes no base-vs-size alignment, so a covering
/// power-of-two block is all that's required. `None` when BOOTBOOT
/// reported no framebuffer.
#[cfg(feature = "extern-rootserver")]
fn fb_device_untyped() -> Option<(u64, u8, crate::bootboot::FramebufferInfo)> {
    let fb = crate::bootboot::framebuffer_info()?;
    // Smallest block_bits with 2^block_bits >= fb.size, floored at 12
    // (a single 4 KiB frame). `size` is u32, so 32 bits is ample.
    let mut block_bits: u8 = 12;
    while (1u64 << block_bits) < fb.size as u64 {
        block_bits += 1;
    }
    Some((fb.paddr, block_bits, fb))
}

/// Phase 42 — backing memory for the rootserver's Untyped cap is
/// reserved at boot from BOOTBOOT free memory rather than from
/// kernel BSS (kernel-image BSS is constrained by the high-memory
/// virtual region; sel4test needs tens of MiB). `boot.rs` calls
/// `install_rootserver_untyped` with the chunk's paddr + power-of-2
/// size_bits before the rootserver dispatch.
struct RootserverUntyped {
    base_paddr: u64,
    size_bits: u8,
}

static mut ROOTSERVER_UT: RootserverUntyped = RootserverUntyped {
    base_paddr: 0,
    size_bits: 0,
};

/// Wire the boot-time-reserved rootserver Untyped region. Call once
/// before `launch_rootserver`. paddr must be 2^size_bits-aligned.
pub unsafe fn install_rootserver_untyped(base_paddr: u64, size_bits: u8) {
    ROOTSERVER_UT.base_paddr = base_paddr;
    ROOTSERVER_UT.size_bits = size_bits;
}

/// Phase 37a — backing storage for the rootserver's pre-allocated
/// AsidPool (one 4 KiB page, holds 512 PML4 paddrs in seL4). The
/// kernel installs `Cap::AsidPool { ptr: ROOTSERVER_ASID_POOL_PADDR,
/// asid_base: 0 }` at canonical slot 6 of the rootserver's CNode.
#[repr(C, align(4096))]
struct AsidPoolPage([u8; 4096]);
static mut ROOTSERVER_ASID_POOL: AsidPoolPage = AsidPoolPage([0; 4096]);

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
    /// Phase 41 — derived at load time from the parsed ELF's
    /// highest PT_LOAD vaddr, so an arbitrary upstream rootserver
    /// (sel4test-driver, hello.elf, Rust rootserver, ...) gets aux
    /// allocations placed cleanly above its image.
    pub stack_top: Word,
    /// User vaddr the IPC buffer page is mapped at (chosen
    /// dynamically — see `stack_top`). seL4_BootInfo.ipcBuffer
    /// holds this; the kernel also stores it on the rootserver TCB.
    pub ipc_buffer_vaddr: u64,
    /// User vaddr the BootInfo page is mapped at (chosen
    /// dynamically — see `stack_top`). Passed to `_start` in `rdi`.
    pub bootinfo_vaddr: u64,
    /// Physical address of the rootserver's IPC buffer page —
    /// stored in the Frame cap at slot 10 of the rootserver's CNode.
    pub ipc_buffer_paddr: u64,
    /// Physical address of the BootInfo page; slot 9.
    pub bootinfo_paddr: u64,
    /// User vaddr of the extended BootInfo page (sized chunks of
    /// optional info — the TSC frequency lives here today).
    pub extra_bi_vaddr: u64,
    /// Physical address of the extended BootInfo page.
    pub extra_bi_paddr: u64,
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
    let img = elf::parse(rootserver_elf()).map_err(LoadError::Elf)?;
    let pml4 = make_user_pml4();

    // The linker may emit several PT_LOAD segments that share a
    // single 4 KiB page (e.g. read-only data + .text both starting
    // mid-page). The IMAGE_PAGES table dedupes those overlapping
    // pages and also feeds `userImageFrames` later — so its
    // (vaddr, paddr, writable) entries are the ground truth for
    // "which user pages the loader pre-mapped on the rootserver's
    // behalf."
    let seen: &mut [PageMapping; IMAGE_PAGES_CAP] = unsafe { &mut IMAGE_PAGES };
    for s in seen.iter_mut() {
        *s = PageMapping { vaddr: 0, paddr: 0, writable: false };
    }
    let mut n_seen: usize = 0;

    // Phase 41 — track the highest vaddr any PT_LOAD segment
    // covers. Auxiliary allocations (stack, IPC buffer, BootInfo)
    // get placed past this so they can't collide with the ELF's
    // own layout, regardless of which rootserver the user packed
    // into the initrd.
    let mut image_top: u64 = 0;

    for seg in img.load_segments() {
        load_segment(pml4, &seg, seen, &mut n_seen)?;
        let seg_end = seg.vaddr + seg.mem_size;
        if seg_end > image_top {
            image_top = seg_end;
        }
    }

    // Round the auxiliary base up to a 4 KiB boundary, then leave a
    // one-page guard so a stack overflow in the rootserver hits an
    // unmapped page rather than scribbling onto its own .bss.
    let page = 0x1000u64;
    let aux_base = (image_top + page - 1) & !(page - 1);
    let stack_base = aux_base + page; // skip guard page
    let stack_top = stack_base + ROOTSERVER_STACK_PAGES * page;
    let ipc_buffer_vaddr = stack_top + page; // skip another guard
    let bootinfo_vaddr = ipc_buffer_vaddr + page;

    // Allocate + map the stack pages. `alloc_page` returns a paddr
    // that's also a valid kernel-virtual pointer (BOOTBOOT identity
    // at PML4[0]) — the loader maps it user-side at `stack_base + i
    // * page` and the kernel can write into it via paddr-as-vaddr.
    // Each aux page is also recorded in IMAGE_PAGES so it appears in
    // userImageFrames; sel4utils then knows not to hand the same
    // vaddr out to its heap allocator.
    for i in 0..ROOTSERVER_STACK_PAGES {
        let stack_phys = alloc_page();
        let vaddr = stack_base + i * page;
        map_user_4k_into_pml4(pml4, vaddr, stack_phys, /* writable */ true, /* NX */ true);
        record_image_page(seen, &mut n_seen, vaddr, stack_phys, true)?;
    }

    // Allocate + map the IPC buffer page (data → NX).
    let ipcbuf_phys = alloc_page();
    map_user_4k_into_pml4(pml4, ipc_buffer_vaddr, ipcbuf_phys, true, /* NX */ true);
    record_image_page(seen, &mut n_seen, ipc_buffer_vaddr, ipcbuf_phys, true)?;

    // Allocate + map the BootInfo page (read-only — userspace reads
    // it but doesn't mutate). The kernel writes the struct via the
    // BOOTBOOT identity map before dispatch.
    let bi_phys = alloc_page();
    map_user_4k_into_pml4(pml4, bootinfo_vaddr, bi_phys, false, /* NX */ true);
    record_image_page(seen, &mut n_seen, bootinfo_vaddr, bi_phys, false)?;

    // Phase 42 — extended BootInfo page. sel4test's
    // `x86_get_tsc_freq_from_simple` looks here for a
    // `SEL4_BOOTINFO_HEADER_X86_TSC_FREQ` chunk; without it
    // `plat_init` aborts after `init_timer` succeeds. Mapping a
    // single page right after `bootinfo_vaddr` is enough for the
    // headers we currently emit.
    let extra_bi_vaddr = bootinfo_vaddr + page;
    let extra_bi_phys = alloc_page();
    map_user_4k_into_pml4(pml4, extra_bi_vaddr, extra_bi_phys, false, /* NX */ true);
    record_image_page(seen, &mut n_seen, extra_bi_vaddr, extra_bi_phys, false)?;

    // Publish the count for the BootInfo builder.
    IMAGE_PAGE_COUNT = n_seen;

    Ok(RootserverImage {
        pml4_paddr: pml4,
        entry: img.entry,
        stack_top,
        ipc_buffer_vaddr,
        bootinfo_vaddr,
        ipc_buffer_paddr: ipcbuf_phys,
        bootinfo_paddr: bi_phys,
        extra_bi_vaddr,
        extra_bi_paddr: extra_bi_phys,
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

/// Phase 32g — after the 29h IPC banner finishes (3rd newline),
/// the rootserver moves to the MCS phase: it spawns two child
/// TCBs bound to high- and low-budget SCs that print 'H' and 'B'
/// respectively. The kernel exit hook counts those bytes and
/// exits once we've seen enough to verify both children ran.
pub static MCS_DEMO_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static MCS_H_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static MCS_B_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Phase 34a — when the rootserver is built with `--features
/// microtest`, the kernel's syscall_entry watches for the byte
/// stream `[microtest done]\n` and qemu_exits as soon as it sees
/// that suffix in `SysDebugPutChar` output. The harness prints
/// per-test pass/fail lines first, then the sentinel.
pub static MICROTEST_MATCH_POS: AtomicUsize = AtomicUsize::new(0);
pub const MICROTEST_SENTINEL: &[u8] = b"[microtest done]\n";

/// Feed one debug-put-char byte through the sentinel matcher.
/// Returns true on the byte that completes `MICROTEST_SENTINEL`.
pub fn microtest_check_byte(b: u8) -> bool {
    let pos = MICROTEST_MATCH_POS.load(Ordering::Relaxed);
    let expect = MICROTEST_SENTINEL[pos];
    if b == expect {
        let new_pos = pos + 1;
        if new_pos == MICROTEST_SENTINEL.len() {
            MICROTEST_MATCH_POS.store(0, Ordering::Relaxed);
            return true;
        }
        MICROTEST_MATCH_POS.store(new_pos, Ordering::Relaxed);
        false
    } else {
        // Restart, but credit a 1-char match if `b` is the start.
        MICROTEST_MATCH_POS.store(
            if b == MICROTEST_SENTINEL[0] { 1 } else { 0 },
            Ordering::Relaxed,
        );
        false
    }
}

/// Phase 29e — replace the AY demo. Loads the rootserver, builds
/// its TCB + CSpace, writes the BootInfo page, demotes the boot
/// thread, swaps CR3, and `sysretq`s into user mode. Never returns;
/// the dispatcher's QEMU-exit hook fires once the rootserver prints
/// `\n`.
/// Write `cap` into slot `si` of the rootserver's root CNode,
/// dispatching to whichever pool (big or XL) backs
/// `ROOTSERVER_CNODE_IDX`. Replaces the old direct
/// `s.cnodes[ROOTSERVER_CNODE_IDX].0[si] = …` writes, which only
/// worked when the root CNode lived in the big pool.
#[inline]
unsafe fn rs_set(s: &mut KernelState, si: usize, cap: &Cap) {
    *s.cnode_slot_mut(ROOTSERVER_CNODE_IDX, si)
        .expect("rootserver cnode slot in range") = Cte::with_cap(cap);
}

pub unsafe fn launch_rootserver() -> ! {
    install_kernel_page_tables();

    let img = load().expect("rootserver loads");

    let s = KERNEL.get();

    // Build the rootserver's CNode (slot 2 of itself = `seL4_CapInitThreadCNode`).
    // Phase 42 — the cap's `radix` MUST match the underlying CNode
    // storage width (`CNODE_RADIX`). When sel4test allocates new
    // children at high offsets via Untyped::Retype it then addresses
    // them via cptr = node_offset; with radix=6 those high offsets
    // are unreachable through the cap and `lookup_cap` short-circuits
    // to slot 0. `guard_size` makes up the remaining bits to a
    // full 64-bit cptr so userspace can pass small (low-bit) cptrs.
    let cnode_ptr = KernelState::cnode_ptr(ROOTSERVER_CNODE_IDX);
    let cnode_cap = Cap::CNode {
        ptr: cnode_ptr,
        radix: ROOTSERVER_CNODE_RADIX,
        guard_size: 64 - ROOTSERVER_CNODE_RADIX,
        guard: 0,
    };
    // Wipe the CNode in case prior specs left state. Dispatched via
    // `cnode_slots_at_mut` so it works whether the root CNode lives in
    // the big pool (sel4test) or the XL pool (extern-rootserver).
    for slot in s
        .cnode_slots_at_mut(ROOTSERVER_CNODE_IDX)
        .expect("rootserver cnode storage")
        .iter_mut()
    {
        slot.set_cap(&Cap::Null);
    }
    // Phase 43 — claim the rootserver's CNode in the in-use bitmap.
    // Direct init bypasses `alloc_cnode`, which is what stamps in_use,
    // so a later `alloc_cnode` would otherwise see cn3 as free, reuse
    // it for a sub-CSpace allocation, and zero every rootserver cap.
    // DOMAINS0001 hit this after sel4test's per-test allocator
    // exhausted MAX_CNODES and started recycling slots.
    s.claim_cnode(ROOTSERVER_CNODE_IDX);

    // Build the TCB. cspace_root points at the new CNode; the
    // dispatcher consults this for cap lookups.
    let mut t = Tcb::default();
    // Rootserver runs at seL4_MaxPrio (255). sel4test's driver
    // assumes it is strictly higher priority than every test process
    // it spawns (env->init->priority is always seL4_MaxPrio - 1) so
    // that result-send IPCs immediately preempt the test process and
    // the driver's tear_down runs before the test process resumes.
    t.priority = 255;
    t.mcp = 255;
    t.state = ThreadStateType::Running;
    t.affinity = 0;
    t.user_context = UserContext::for_entry(
        img.entry,
        img.stack_top - 8,
        /* rdi (arg0) */ img.bootinfo_vaddr,
    );
    t.cpu_context.cr3 = img.pml4_paddr;
    // Phase 34c — register the rootserver's IPC buffer with the
    // kernel so long-message IPC can read/write it via paddr.
    t.ipc_buffer = img.ipc_buffer_vaddr;
    t.ipc_buffer_paddr = img.ipc_buffer_paddr;
    t.cspace_root = cnode_cap;
    // Phase 43 — assign a reserved sentinel ASID (1) to the
    // rootserver's vspace so Frame::Unmap can locate this PML4 by
    // asid lookup. ASID 0 means "unmapped/unassigned" and would
    // make our Frame::Unmap no-op even for legitimate same-vspace
    // unmaps.
    const ROOTSERVER_ASID: u16 = 1;
    t.vspace_root = Cap::PML4 {
        ptr: PPtr::<Pml4Storage>::new(img.pml4_paddr).expect("pml4 paddr"),
        mapped: true,
        asid: ROOTSERVER_ASID,
    };
    let id = s.scheduler.admit(t);

    // Phase 37b — pre-allocate the InitThreadSC. The rootserver
    // gets a SchedContext bound to it from the start; the cap
    // sits at canonical slot 14 (`seL4_CapInitThreadSC`). Period
    // and budget are large enough that the rootserver effectively
    // never runs out of budget — we treat it as the boot thread,
    // not a budget-constrained worker.
    let init_sc_idx = s.alloc_sched_context()
        .expect("init thread SC pool slot");
    {
        let sc = &mut s.sched_contexts[init_sc_idx];
        *sc = crate::sched_context::SchedContext::new(
            /* period */ 1_000_000, /* budget */ 1_000_000);
        sc.refills[0] = crate::sched_context::Refill {
            release_time: 0,
            amount: 1_000_000,
        };
        sc.head = 0;
        sc.count = 1;
        sc.bound_tcb = Some(id);
    }
    s.scheduler.slab.get_mut(id).sc = Some(init_sc_idx as u16);
    // The rootserver was admitted before its SC existed, so `admit`
    // (which enqueues only schedulable threads) left it off the ready
    // queue. Now that it has an SC, enqueue it.
    s.scheduler.on_sc_gained(id);

    // Populate the rootserver's CNode with the canonical initial
    // cap layout (subset of seL4's seL4_RootCNodeCapSlots). The
    // rootserver's own startup code can now invoke any of these by
    // CPtr.
    rs_set(s, 1, &Cap::Thread {
        // `decode_tcb` recovers the TcbId via `tcb_ptr.addr() as u16`,
        // so we encode the TcbId directly (slab IDs start from 1
        // after the boot thread, so `PPtr::new` always succeeds).
        tcb: PPtr::<crate::cap::Tcb>::new(id.0 as u64).expect("nonzero tcb id"),
    });
    rs_set(s, 2, &cnode_cap);
    rs_set(s, 3, &Cap::PML4 {
        ptr: PPtr::<Pml4Storage>::new(img.pml4_paddr).expect("pml4 paddr"),
        mapped: true,
        asid: ROOTSERVER_ASID,
    });
    rs_set(s, 9, &Cap::Frame {
        ptr: PPtr::<FrameStorage>::new(img.bootinfo_paddr).expect("bi paddr"),
        size: FrameSize::Small,
        rights: FrameRights::ReadOnly,
        mapped: Some(img.bootinfo_vaddr),
        asid: ROOTSERVER_ASID,
        is_device: false,
        map_type: crate::cap::FrameMapType::VSpace,
    });
    rs_set(s, 10, &Cap::Frame {
        ptr: PPtr::<FrameStorage>::new(img.ipc_buffer_paddr).expect("ipc paddr"),
        size: FrameSize::Small,
        rights: FrameRights::ReadWrite,
        mapped: Some(img.ipc_buffer_vaddr),
        asid: ROOTSERVER_ASID,
        is_device: false,
        map_type: crate::cap::FrameMapType::VSpace,
    });
    // Phase 33b / 36e — IRQControl at canonical slot 4.
    rs_set(s, 4, &Cap::IrqControl);
    // Phase 36e — ASIDControl at canonical slot 5.
    rs_set(s, 5, &Cap::AsidControl);
    // Phase 37a — pre-allocated InitThreadASIDPool at canonical
    // slot 6. asid_base = 0 (rootserver gets the first 512 ASIDs).
    let asid_pool_va = (&raw const ROOTSERVER_ASID_POOL) as u64;
    let asid_pool_pa =
        crate::arch::x86_64::paging::kernel_virt_to_phys(asid_pool_va);
    rs_set(s, 6, &Cap::AsidPool {
        ptr: PPtr::<crate::cap::AsidPoolStorage>::new(asid_pool_pa)
            .expect("asid pool paddr"),
        asid_base: 0,
    });
    // Phase 42 — IOPortControl at canonical slot 7
    // (`seL4_CapIOPortControl`). sel4test's pc99 timer driver
    // calls `seL4_X86_IOPortControl_Issue` here when it falls back
    // to PIT (which it does whenever ACPI/HPET discovery fails),
    // so without this cap the timer driver silently bails.
    rs_set(s, 7, &Cap::IOPortControl);
    // Phase 43 — slot 11 is the canonical seL4_CapDomain. sel4test's
    // DOMAINS0001-3 invoke DomainSet_Set on it; the kernel's decode_
    // domain handler stamps the domain field on the target TCB
    // (NUM_DOMAINS=1, so only domain 0 is valid).
    rs_set(s, 11, &Cap::Domain);
    // Phase 44 — master IO-space cap at canonical slot 8
    // (`seL4_CapIOSpace`), present only when a VT-d unit was found.
    // sel4test's IOPT tests CNode_Mint a per-device io_space cap from
    // this master (badge = (domainID << 16) | pciRequestID).
    #[cfg(target_arch = "x86_64")]
    if crate::arch::x86_64::iommu::iommu_present() {
        rs_set(s, 8, &Cap::IoSpace {
            domain_id: 0,
            pci_device: 0,
        });
    }
    // Slots 12, 13, 15: empty (no SMMU / SMC support).
    // Phase 37b — InitThreadSC at canonical slot 14. The
    // SchedContext object was allocated above and bound to the
    // rootserver TCB.
    rs_set(s, 14, &Cap::SchedContext {
        ptr: KernelState::sched_context_ptr(init_sc_idx),
        size_bits: crate::object_type::MIN_SCHED_CONTEXT_BITS as u8,
    });
    // Phase 36e — per-CPU SchedControl caps in the schedcontrol
    // region [16, 16+ncores). bi.schedcontrol points at this range.
    let n_cores = crate::bootboot::get_num_cores() as usize;
    let schedcontrol_start: usize = 16;
    for core in 0..n_cores.min(4) {
        rs_set(s, schedcontrol_start + core,
            &Cap::SchedControl { core: core as u32 });
    }
    // Phase 36e / 42 — Untyped at slot 20 (after the schedcontrol
    // region). bi.untyped points here. Backing memory is reserved
    // at boot from BOOTBOOT free memory (see install_rootserver_untyped).
    let ut_paddr = ROOTSERVER_UT.base_paddr;
    let ut_size_bits = ROOTSERVER_UT.size_bits;
    let untyped_slot: usize = 20;
    rs_set(s, untyped_slot, &Cap::Untyped {
        ptr: PPtr::<UntypedStorage>::new(ut_paddr).expect("ut paddr"),
        block_bits: ut_size_bits,
        free_index: 0,
        is_device: false,
    });
    // Phase 42 — device untypeds at slots 21.., paralleling
    // build_bootinfo's untypedList[1..]. Single source of truth is the
    // module-level DEVICE_UTS so the caps here and the BootInfo metadata
    // can't drift (see DEVICE_UTS doc).
    for (i, &(paddr, sb)) in DEVICE_UTS.iter().enumerate() {
        rs_set(s, untyped_slot + 1 + i, &Cap::Untyped {
            ptr: PPtr::<UntypedStorage>::new(paddr.max(1)).expect("dev ut paddr"),
            block_bits: sb,
            free_index: 0,
            is_device: true,
        });
    }
    // Phase 0a — the BOOTBOOT framebuffer as one more device untyped,
    // in the slot immediately after the DEVICE_UTS block. `n_extra_uts`
    // (0 or 1) shifts `user_image_start` by the same amount build_bootinfo
    // shifts `untyped_end`, so caps and BootInfo metadata can't drift.
    // Fully gated so the default (sel4test) build path is unchanged.
    #[cfg(feature = "extern-rootserver")]
    let n_extra_uts: usize = if let Some((fb_paddr, fb_bits, _)) = fb_device_untyped() {
        rs_set(s, untyped_slot + 1 + DEVICE_UTS.len(), &Cap::Untyped {
            ptr: PPtr::<UntypedStorage>::new(fb_paddr.max(1)).expect("fb ut paddr"),
            block_bits: fb_bits,
            free_index: 0,
            is_device: true,
        });
        1
    } else {
        0
    };

    // Phase 42 — userImageFrames: install one `Cap::Frame` per page
    // the loader pre-mapped for the rootserver (image + stack + IPC
    // buffer + BootInfo). sel4utils' vspace bootstrap walks these
    // and registers the mapped vaddrs as reserved, which keeps its
    // heap allocator from picking vaddrs that overlap the loader's
    // already-installed PTs (without this, allocman's PT_Map fails
    // with `seL4_DeleteFirst` whenever it tries to reuse a PD slot
    // the loader already populated).
    #[cfg(not(feature = "extern-rootserver"))]
    let user_image_start: Word = (untyped_slot as Word) + 1 + DEVICE_UTS.len() as Word;
    #[cfg(feature = "extern-rootserver")]
    let user_image_start: Word =
        (untyped_slot as Word) + 1 + DEVICE_UTS.len() as Word + n_extra_uts as Word;
    let n_image_pages = IMAGE_PAGE_COUNT;
    for i in 0..n_image_pages {
        let pm = IMAGE_PAGES[i];
        let rights = if pm.writable {
            crate::cap::FrameRights::ReadWrite
        } else {
            crate::cap::FrameRights::ReadOnly
        };
        rs_set(s, user_image_start as usize + i, &Cap::Frame {
            ptr: PPtr::<FrameStorage>::new(pm.paddr).expect("image page paddr"),
            size: FrameSize::Small,
            rights,
            mapped: Some(pm.vaddr),
            asid: ROOTSERVER_ASID,
            is_device: false,
            map_type: crate::cap::FrameMapType::VSpace,
        });
    }
    let user_image_end: Word = user_image_start + n_image_pages as Word;

    // Phase 42 — populate the extended BootInfo page with the
    // TSC-frequency chunk sel4test's `x86_get_tsc_freq_from_simple`
    // looks up. The header is `{ id: u64, len: u64 }` followed by
    // a 4-byte TSC freq in MHz. We hardcode 1000 MHz (1 GHz) — the
    // QEMU default for `-cpu host` is in this ballpark, and sel4test
    // uses the value only for relative timing; off-by-a-factor is
    // acceptable for getting the test suite running.
    const SEL4_BI_HEADER_SIZE: usize = 16; // u64 id + u64 len
    const TSC_FREQ_HEADER_ID: u64 = 5; // SEL4_BOOTINFO_HEADER_X86_TSC_FREQ
    const TSC_FREQ_MHZ: u32 = 1000;
    let extra_bi_kvaddr = phys_to_kernel_virt(img.extra_bi_paddr);
    let extra_bi_ptr = extra_bi_kvaddr as *mut u8;
    // Header.id
    core::ptr::write_volatile(extra_bi_ptr as *mut u64, TSC_FREQ_HEADER_ID);
    // Header.len (header + payload)
    core::ptr::write_volatile(
        (extra_bi_ptr as *mut u64).add(1),
        (SEL4_BI_HEADER_SIZE + 4) as u64,
    );
    // Payload: TSC freq in MHz (u32).
    core::ptr::write_volatile(
        extra_bi_ptr.add(SEL4_BI_HEADER_SIZE) as *mut u32,
        TSC_FREQ_MHZ,
    );
    let extra_bi_total_len: Word = (SEL4_BI_HEADER_SIZE + 4) as Word;

    // Build + write the BootInfo struct into its page. We address
    // it via its kernel-virt mapping (still BOOTBOOT-identity-mapped)
    // before the CR3 swap; the rootserver reads it through its
    // user-half mapping after sysretq.
    let bi_ptr = phys_to_kernel_virt(img.bootinfo_paddr) as *mut seL4_BootInfo;
    let bi = build_bootinfo(
        img.ipc_buffer_vaddr,
        ut_paddr,
        ut_size_bits,
        user_image_start,
        user_image_end,
        extra_bi_total_len,
    );
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

    // Phase 44 — initialize per-object cap refcounts from the
    // actual pool contents. Everything written before this point
    // (boot CNode planting, spec runs, the rootserver caps above)
    // may have bypassed the `Cte::set_cap` hook; from here on the
    // hook keeps counts exact and cap-delete liveness checks are
    // O(1) instead of whole-pool sweeps.
    crate::kernel::recount_refcounts();
    // Spec-phase MakePool/Assign runs pollute the ASID allocator
    // statics (NEXT_ASID_BASE, ASID_POOLS_MADE, per-pool used counts);
    // reset them so the real test suite starts from a clean slate
    // (VSPACE0005 overassigns a freshly-made pool and counts exactly
    // 512 ASIDs).
    crate::invocation::reset_asid_state();

    // LAPIC-timer migration — the kernel's preemption clock
    // (TICK_COUNT + scheduler.tick + mcs_tick) is the LAPIC timer,
    // calibrated against the PIT before anything else touches the
    // chip. The PIT itself belongs to user space: sel4test's
    // ltimer driver programs it through IOPort caps and its IRQs
    // fan through `pit_irq_dispatch` to the user IRQ 2
    // notification. The kernel only installs the handler and
    // unmasks the line (after specs — the PIT spec's mask_all()
    // would otherwise leave IRQ 0 dead).
    crate::arch::x86_64::pic::init_pic();
    crate::arch::x86_64::lapic::calibrate_timer_with_pit();
    crate::arch::x86_64::lapic::enable_periodic_kernel_timer();
    crate::arch::x86_64::pit::install_irq_handler();

    // Swap CR3 to the rootserver's PML4 (kernel half preserved).
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) img.pml4_paddr,
        options(nostack, preserves_flags),
    );

    // SMP: establish the rootserver as this core's FPU owner so its
    // x87/SSE state is tracked from first entry (otherwise a later
    // switch wouldn't save it).
    #[cfg(feature = "smp")]
    crate::arch::x86_64::fpu_ctx::fpu_switch_to(&mut s.scheduler.slab, id);

    let ctx = s.scheduler.slab.get(id).user_context;
    enter_user_via_sysret(&ctx);
}

/// Convert a physical address to its kernel-virt counterpart. The
/// kernel runs with BOOTBOOT's identity map for low memory, so the
/// kernel virt of a physical page is just `paddr +
/// KERNEL_VIRT_TO_PHYS_OFFSET`. We avoid exposing the offset
/// directly; just invert `kernel_virt_to_phys`.
unsafe fn phys_to_kernel_virt(paddr: u64) -> u64 {
    // Phase 42 — single regime: every paddr (alloc_page output,
    // kernel-image-pool output, etc.) is reachable through the
    // kernel-half linear map.
    crate::arch::x86_64::paging::phys_to_lin(paddr)
}

unsafe fn build_bootinfo(
    ipc_buffer_vaddr: u64,
    untyped_paddr: u64,
    untyped_size_bits: u8,
    user_image_start: Word,
    user_image_end: Word,
    extra_bi_size: Word,
) -> seL4_BootInfo {
    let mut empty_untypeds = [seL4_UntypedDesc::default();
        CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS];
    // Phase 42 — slot 20: the rootserver's RAM Untyped (allocman
    // carves all TCBs / CNodes / frames / page tables out of this).
    empty_untypeds[0] = seL4_UntypedDesc {
        paddr: untyped_paddr,
        sizeBits: untyped_size_bits,
        isDevice: 0,
        padding: [0; 6],
    };
    // Phase 42 — device untypeds (BIOS/ACPI low 1 MiB, IOAPIC/HPET/LAPIC
    // MMIO, e1000e NIC BAR). Built from the SAME `DEVICE_UTS` the cap
    // placement uses, so `untypedList` and the CSpace caps can never drift.
    for (i, &(paddr, sb)) in DEVICE_UTS.iter().enumerate() {
        empty_untypeds[1 + i] = seL4_UntypedDesc {
            paddr,
            sizeBits: sb,
            isDevice: 1,
            padding: [0; 6],
        };
    }
    #[cfg(not(feature = "extern-rootserver"))]
    let untyped_count: Word = 1 + DEVICE_UTS.len() as Word;
    // Phase 0a — append the framebuffer device untyped (extern-rootserver).
    // Kept in lockstep with the cap placed in launch_rootserver (same slot,
    // same paddr/size_bits) so `untypedList[fb]` and the CSpace cap agree.
    #[cfg(feature = "extern-rootserver")]
    let untyped_count: Word = {
        let mut untyped_count: Word = 1 + DEVICE_UTS.len() as Word;
        if let Some((fb_paddr, fb_bits, _)) = fb_device_untyped() {
            empty_untypeds[untyped_count as usize] = seL4_UntypedDesc {
                paddr: fb_paddr,
                sizeBits: fb_bits,
                isDevice: 1,
                padding: [0; 6],
            };
            untyped_count += 1;
        }
        untyped_count
    };

    let n_cores = crate::bootboot::get_num_cores() as Word;
    // Phase 36e / 42 — canonical slot layout under MCS:
    //   0..15  initial caps (some Null where unsupported)
    //   16..(16+n_cores)  per-CPU SchedControl
    //   20..20+untyped_count  Untypeds (RAM at 20, device at 21..)
    //   (rest)  empty (sel4test allocates here)
    let schedcontrol_start: Word = 16;
    let schedcontrol_end: Word = schedcontrol_start + n_cores.min(4);
    let untyped_start: Word = 20;
    let untyped_end: Word = untyped_start + untyped_count;
    let cnode_slots: Word = 1u64 << ROOTSERVER_CNODE_RADIX;
    seL4_BootInfo {
        extraLen: extra_bi_size,
        nodeID: 0,
        numNodes: n_cores,
        // Phase 44 — VT-d uses 4 IO page-table levels (see iommu.rs);
        // 0 when no IOMMU is present.
        numIOPTLevels: {
            #[cfg(target_arch = "x86_64")]
            {
                if crate::arch::x86_64::iommu::iommu_present() {
                    crate::arch::x86_64::iommu::num_iopt_levels() as Word
                } else {
                    0
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                0
            }
        },
        ipcBuffer: ipc_buffer_vaddr as *mut crate::types::seL4_IPCBuffer,
        empty: seL4_SlotRegion { start: user_image_end, end: cnode_slots },
        sharedFrames: seL4_SlotRegion { start: 0, end: 0 },
        userImageFrames: seL4_SlotRegion {
            start: user_image_start,
            end: user_image_end,
        },
        // userImagePaging would describe the PT/PD/PDPT caps backing
        // the rootserver image's mappings. Our loader's PT/PD/PDPT
        // pages are pulled from a kernel-image pool (`KPT_POOL`) and
        // never exposed as caps; sel4utils tolerates an empty range
        // here as long as userImageFrames is correct (it can't unmap
        // image pages but we don't need that for sel4test bring-up).
        userImagePaging: seL4_SlotRegion { start: 0, end: 0 },
        ioSpaceCaps: seL4_SlotRegion { start: 0, end: 0 },
        extraBIPages: seL4_SlotRegion { start: 0, end: 0 },
        initThreadCNodeSizeBits: ROOTSERVER_CNODE_RADIX as Word,
        initThreadDomain: 0,
        schedcontrol: seL4_SlotRegion {
            start: schedcontrol_start,
            end: schedcontrol_end,
        },
        untyped: seL4_SlotRegion { start: untyped_start, end: untyped_end },
        untypedList: empty_untypeds,
        // Phase 0a — framebuffer geometry (extern-rootserver). All-zero
        // when BOOTBOOT exposed no framebuffer.
        #[cfg(feature = "extern-rootserver")]
        fb_paddr: fb_device_untyped().map(|(p, _, _)| p).unwrap_or(0),
        #[cfg(feature = "extern-rootserver")]
        fb_width: fb_device_untyped().map(|(_, _, g)| g.width).unwrap_or(0),
        #[cfg(feature = "extern-rootserver")]
        fb_height: fb_device_untyped().map(|(_, _, g)| g.height).unwrap_or(0),
        #[cfg(feature = "extern-rootserver")]
        fb_scanline: fb_device_untyped().map(|(_, _, g)| g.scanline).unwrap_or(0),
        #[cfg(feature = "extern-rootserver")]
        fb_size: fb_device_untyped().map(|(_, _, g)| g.size).unwrap_or(0),
        #[cfg(feature = "extern-rootserver")]
        fb_type: fb_device_untyped().map(|(_, _, g)| g.fb_type as u32).unwrap_or(0),
    }
}

// suppress unused parameter warning in helper above
#[allow(dead_code)]
fn _silence_seL4_slotpos_unused(_: seL4_SlotPos) {}

/// Tracks "this page-aligned vaddr has been mapped at `paddr`". The
/// loader uses it to dedupe overlapping PT_LOAD segments; later the
/// BootInfo builder iterates IMAGE_PAGES to emit `userImageFrames`
/// Frame caps so sel4utils' vspace allocator knows which user vaddrs
/// the loader pre-reserved for the rootserver image, stack, IPC
/// buffer and BootInfo page.
#[derive(Copy, Clone)]
pub struct PageMapping {
    pub vaddr: u64,
    pub paddr: u64,
    /// True if the page was mapped writable (for the eventual Frame
    /// cap rights — readonly = ReadOnly, writable = ReadWrite).
    pub writable: bool,
}

/// Capacity of the per-rootserver page-mapping table. Sized for
/// sel4test-driver-class workloads (~3.6 MiB image ≈ 900 pages plus
/// stack/IPC/BootInfo aux pages).
pub const IMAGE_PAGES_CAP: usize = 2048;

/// All user-image pages the loader installed in the rootserver's
/// PML4. Populated by `load()`, consumed by `install_rootserver_initial_caps`
/// to materialise `userImageFrames`.
pub static mut IMAGE_PAGES: [PageMapping; IMAGE_PAGES_CAP] =
    [PageMapping { vaddr: 0, paddr: 0, writable: false }; IMAGE_PAGES_CAP];
pub static mut IMAGE_PAGE_COUNT: usize = 0;

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
        // `alloc_page` returns a paddr; we reach it from kernel mode
        // through the linear map at `phys_to_lin(paddr)`.
        let writable = seg.writable();
        // W^X: only the executable (code) segment gets X; data + read-only
        // segments (incl. the heap in .bss) are mapped NX. Non-executable
        // segments never carry code, so this never breaks execution.
        let execute_never = !seg.executable();
        let phys_addr = match find_seen(seen, *n_seen, page_vaddr) {
            Some(p) => p,
            None => {
                let phys = alloc_page();
                map_user_4k_into_pml4(pml4, page_vaddr, phys, writable, execute_never);
                record_image_page(seen, n_seen, page_vaddr, phys, writable)?;
                phys
            }
        };
        let kva = crate::arch::x86_64::paging::phys_to_lin(phys_addr);

        // Copy the slice of this segment that lies in this page:
        // [max(seg.vaddr, page_vaddr) .. min(seg.vaddr + filesize, page_vaddr + 4096)).
        // Anything beyond filesize stays zero (BSS tail; alloc_page
        // zero-filled).
        let seg_file_end = seg.vaddr + seg.file_size;
        let copy_start = seg.vaddr.max(page_vaddr);
        let copy_end = seg_file_end.min(page_vaddr + 0x1000);
        if copy_end > copy_start {
            let file_off = seg.file_off + (copy_start - seg.vaddr);
            let src = rootserver_elf().as_ptr().add(file_off as usize);
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
            return Some(seen[i].paddr);
        }
    }
    None
}

fn record_image_page(
    seen: &mut [PageMapping],
    n_seen: &mut usize,
    vaddr: u64,
    paddr: u64,
    writable: bool,
) -> Result<(), LoadError> {
    if *n_seen >= seen.len() {
        return Err(LoadError::UnalignedSegment); // pool small
    }
    seen[*n_seen] = PageMapping { vaddr, paddr, writable };
    *n_seen += 1;
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
            let used_before = super::USER_PAGE_REGION.used;
            let result = super::load().expect("rootserver loads");

            // Entry must equal the ELF's e_entry (sanity vs the
            // 29b spec).
            let img = crate::elf::parse(super::rootserver_elf()).unwrap();
            assert_eq!(result.entry, img.entry);

            // Stack-top must sit above the highest PT_LOAD vaddr —
            // Phase 41 made aux placement dynamic per ELF.
            let mut image_top: u64 = 0;
            for seg in img.load_segments() {
                let end = seg.vaddr + seg.mem_size;
                if end > image_top { image_top = end; }
            }
            assert!(result.stack_top > image_top,
                "stack_top {:#x} must be past image_top {:#x}",
                result.stack_top, image_top);
            assert!(result.ipc_buffer_vaddr > result.stack_top,
                "IPC buffer must sit above stack");
            assert!(result.bootinfo_vaddr > result.ipc_buffer_vaddr,
                "BootInfo must sit above IPC buffer");

            // PML4 is non-zero and 4 KiB-aligned.
            assert!(result.pml4_paddr != 0);
            assert_eq!(result.pml4_paddr & 0xFFF, 0);

            // We allocated at least one page per segment + one for the
            // stack.
            let mut seg_pages = 0u64;
            for seg in img.load_segments() {
                seg_pages += (seg.mem_size + 0xFFF) / 0x1000;
            }
            let used_after = super::USER_PAGE_REGION.used;
            let pages_alloc = (used_after - used_before) / 0x1000;
            assert!(
                pages_alloc >= seg_pages + 1,
                "expected ≥{} pages allocated, got {}",
                seg_pages + 1,
                pages_alloc,
            );
            arch::log("  ✓ rootserver loads + segments map into a fresh PML4\n");
        }
    }
}
