// configure Rust compiler
#![no_std]
#![no_main]

#[cfg(all(feature = "arch-x86_64", feature = "arch-aarch64"))]
compile_error!("select exactly one architecture feature");
#[cfg(not(any(feature = "arch-x86_64", feature = "arch-aarch64")))]
compile_error!("select an architecture feature");
#[cfg(all(target_arch = "x86_64", not(feature = "arch-x86_64")))]
compile_error!("x86_64 targets require the `arch-x86_64` feature");
#[cfg(all(target_arch = "aarch64", not(feature = "arch-aarch64")))]
compile_error!("aarch64 targets require the `arch-aarch64` feature");
#[cfg(all(feature = "arch-x86_64", not(target_arch = "x86_64")))]
compile_error!("the `arch-x86_64` feature requires an x86_64 target");
#[cfg(all(feature = "arch-aarch64", not(target_arch = "aarch64")))]
compile_error!("the `arch-aarch64` feature requires an aarch64 target");
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("supported kernel targets are x86_64 and aarch64");

#[allow(dead_code)]
mod simpleboot;

// Required for -Z build-std flag.
extern crate rlibc;

// Loads the appropriate architecture code
mod arch;

// Generated bitfield types from codegen/structures_64.bf — see build.rs.
mod structures;

// Generated syscall and invocation-label enums.
mod syscalls;

// Hand-coded public ABI types matching libsel4 layouts byte-for-byte.
mod types;

// Idiomatic Rust capability enum and round-trip with the on-the-wire
// encoding emitted by the generated bitfield types.
mod cap;

// Capability Table Entry — single-cell storage for one cap plus its
// MDB bookkeeping.
mod cte;

// x86 ASID-pool bookkeeping.
mod asid;

// CSpace lookup — resolveAddressBits, lookupCap, lookupSlot.
mod cspace;

// Memory-region types and alignment helpers.
mod region;

// seL4 object types and per-type sizes.
mod object_type;

// Untyped retype — kernel object allocator.
mod untyped;

// Thread Control Block + slab allocator.
mod tcb;

// Priority scheduler over the TCB slab.
mod scheduler;

// Static kernel state singleton (current TCB pointer, scheduler).
mod kernel;

// Unified KResult / KException error type.
mod error;

// Syscall dispatcher (handle_syscall + handle_unknown_syscall).
mod syscall_handler;

// Phase 34c — IPC-buffer layout offsets (mirrors libsel4's
// seL4_IPCBuffer struct in u64-word offsets).
mod ipc_buffer;

// Endpoint state machine (slowpath IPC).
mod endpoint;

// Phase 16 — invocation dispatcher (Untyped::Retype, CNode::Copy,
// TCB::Suspend, etc. as syscalls).
mod invocation;

// Phase 22 — fault delivery via fault EP cap.
mod fault;

// Notification state machine (signal/wait).
mod notification;

// IRQ → notification dispatch.
mod interrupt;

// Phase 34e — Reply objects + kernel-side pool.
mod reply;

// x86_64 virtual-address-space helpers — re-exported from
// arch::x86_64::vspace so callers can stay arch-neutral. ARM and
// RISC-V will land sibling modules with their own paging layouts.
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::vspace;

// Phase 11c — kernel boot: memory-map discovery + rootserver placement.
mod boot;

// Phase 10a — MCS scheduling-context object (gated behind cargo
// `mcs` feature). Adds sporadic-server refill bookkeeping on top of
// the classic scheduler.
mod sched_context;

// Phase 10b / 28 — multi-CPU support: per-CPU NodeState + IPI
// dispatch. Always-on now that Simpleboot drops every configured CPU
// at `_start`; the `smp` cargo feature still gates the spec runner
// for the smp module to keep its tests scoped.
mod smp;

// Phase 39 / Simpleboot — initrd (USTAR tar) walker. Simpleboot loads
// the archive as the first Multiboot2 module; the kernel walks it at
// runtime to find the rootserver ELF.
mod initrd;

// Phase 29a / 39 — locator for the rootserver ELF inside the initrd.
// Pre-39 this was an `include_bytes!` of a sibling crate's output;
// now it's a runtime `initrd::find_file("boot/rootserver")`.
mod rootserver_image;

// Phase 29b — minimal ELF64 parser. Reads the embedded
// rootserver image and exposes its entry point + PT_LOAD segments.
mod elf;

// Phase 29c — rootserver loader: parses ROOTSERVER_ELF, allocates
// user pages, builds a fresh PML4 + user stack.
#[cfg(target_arch = "x86_64")]
mod rootserver;

// Phase 10c — IPC fastpath bypassing the slowpath book-keeping for
// the common-case Call / ReplyRecv shape.
#[cfg(feature = "fastpath")]
mod fastpath;

// Phase 10d — lazy FPU switch state machine.
#[cfg(feature = "fpu")]
mod fpu;

// Phase 10e — VT-x VCPU lifecycle.
#[cfg(feature = "vmx")]
mod vcpu;

// Loads tests if we're running specs
#[cfg(feature = "spec")]
mod spec;

/********************************************
 * Entry point, called by Simpleboot Loader *
 ********************************************/
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .section .text.boot,"ax"
    .global _arm64_image_start
_arm64_image_start:
    b _start
    nop
    .quad 0x00200000
    .quad __kernel_end - _arm64_image_start
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .word 0x644d5241
    .word 0
"#
);

// NOTE: Simpleboot enters this path on all configured x86 cores.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
extern "C" fn _start(magic: u64, mbi_addr: u64) -> ! {
    simpleboot::init(magic, mbi_addr);
    kernel_entry()
}

/// QEMU's AArch64 `virt` direct-kernel ABI enters with the FDT physical
/// address in X0. Establish a kernel-owned stack before calling Rust.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[no_mangle]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "adrp x2, {stack}",
        "add x2, x2, :lo12:{stack}",
        "add x2, x2, {stack_size}",
        "and x2, x2, #-16",
        "mov sp, x2",
        // Match seL4's non-hypervisor `disableFpuEL0`: EL1 may use
        // FP/SIMD while EL0 remains trapped for lazy context switching.
        "mrs x3, cpacr_el1",
        "orr x3, x3, #0x100000",
        "msr cpacr_el1, x3",
        "isb",
        "b {entry}",
        stack = sym BSP_BIG_STACK,
        stack_size = const core::mem::size_of::<BspStack>(),
        entry = sym aarch64_start,
    );
}

#[cfg(target_arch = "aarch64")]
extern "C" fn aarch64_start(fdt_addr: u64) -> ! {
    simpleboot::init_fdt(fdt_addr);
    kernel_entry()
}

fn kernel_entry() -> ! {
    // Only initialize on the bootstrap processor
    // Check if current APIC ID matches the Simpleboot BSP ID
    let current_apic_id = arch::get_cpu_id();
    let simpleboot_bsp_id = simpleboot::get_bootstrap_processor_id() as arch::CpuId;

    if current_apic_id == simpleboot_bsp_id {
        bsp_main();
    } else {
        ap_main(current_apic_id);
    }
}

/// Bootloader stacks are intentionally small. The BSP hops onto this
/// BSS-allocated stack first thing so kernel specs can build larger
/// test fixtures without depending on loader stack policy.
#[repr(C, align(16))]
struct BspStack([u8; 4 * 1024 * 1024]);
static mut BSP_BIG_STACK: BspStack = BspStack([0; 4 * 1024 * 1024]);

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct ApStack([u8; 1024 * 1024]);
#[cfg(target_arch = "x86_64")]
static mut AP_BIG_STACKS: [ApStack; smp::MAX_CPUS] =
    [const { ApStack([0; 1024 * 1024]) }; smp::MAX_CPUS];

/// BSP entry — runs all global init (serial, GDT contents, IDT
/// contents, exception vectors), signals APs to come up, waits for
/// the AP barrier, then runs spec runner / demo.
fn bsp_main() -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let top = (&raw const BSP_BIG_STACK as u64) + core::mem::size_of::<BspStack>() as u64;
        core::arch::asm!(
            "mov rsp, {top}",
            "jmp {cont}",
            top = in(reg) top & !0xF,
            cont = sym bsp_main_big_stack,
            options(noreturn),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    bsp_main_big_stack()
}

fn bsp_main_big_stack() -> ! {
    arch::init_serial();
    arch::log("Serial initialized!\n");

    arch::log("Initializing GDT/TSS...\n");
    arch::init_gdt();

    arch::log("Initializing interrupts...\n");
    arch::init_interrupts();

    arch::log("Initializing exception handlers...\n");
    arch::init_exceptions();

    arch::log("Initializing SYSCALL MSRs...\n");
    arch::init_syscall_msrs();

    // SMP FPU save/restore: ensure CR4.OSFXSR and capture the canonical
    // FINIT FXSAVE image so every new TCB starts from valid FPU state.
    #[cfg(all(target_arch = "x86_64", feature = "smp"))]
    crate::arch::x86_64::fpu_ctx::init_fpu_template();

    // Phase 28d — install kernel page tables (so the LAPIC is
    // mapped at KERNEL_LAPIC_VBASE) then software-enable the BSP's
    // LAPIC. Once enabled, IPI delivery works in either direction.
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::paging::install_kernel_page_tables();
        unsafe {
            crate::arch::x86_64::ioapic::initialize(
                crate::simpleboot::acpi_table_address(),
                crate::arch::get_cpu_id(),
            )
            .expect("firmware IOAPIC topology must validate");
        }
        crate::arch::x86_64::lapic::init_lapic();
    }

    arch::log("Kernel initialization complete on BSP\n");

    // Release APs — the shared GDT and IDT are now populated, so
    // they can safely lgdt/lidt and load their per-CPU TSS.
    let n_cores = simpleboot::get_num_cores() as u32;
    let n_aps = n_cores.saturating_sub(1);
    smp::signal_bsp_ready();
    if n_aps > 0 {
        arch::log("Waiting for APs to come up...\n");
        smp::wait_for_aps(n_aps);
        arch::log("All APs up\n");
    }

    // Phase 41 — reserve the rootserver user-page region from
    // Simpleboot free memory before specs run. The rootserver-loader
    // spec calls super::load() which allocates from this region,
    // and sel4test-driver's image alone is ~3.9 MiB — too big for
    // a kernel-image BSS pool.
    #[cfg(target_arch = "x86_64")]
    if let Err(e) = boot::reserve_user_page_region() {
        arch::log("boot: reserve_user_page_region failed: ");
        match e {
            boot::BootError::TooManyRegions => arch::log("TooManyRegions"),
            boot::BootError::NoSuitableRegion => arch::log("NoSuitableRegion"),
            boot::BootError::OverlapInternal => arch::log("OverlapInternal"),
        }
        arch::log("\n");
    }

    // Phase 44 — initialise the VT-d IOMMU now that the IOMMU table
    // pool has been carved from low RAM (in reserve_user_page_region).
    // Sets numIOPTLevels + the master io_space cap availability before
    // the rootserver's CNode is populated.
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::iommu::vtd_init();

    #[cfg(feature = "spec")]
    spec::test_main();

    // Real boot orchestration: read the loader's memory map,
    // place the rootserver. Phase 12d runs this on the live
    // Simpleboot-supplied state — useful as an end-to-end smoke
    // test that the boot code that's been spec'd in synthetic
    // form actually copes with real-hardware data.
    #[cfg(target_arch = "x86_64")]
    match boot::kernel_init() {
        Ok(_) => arch::log("boot: kernel_init succeeded\n"),
        Err(e) => {
            arch::log("boot: kernel_init failed: ");
            match e {
                boot::BootError::TooManyRegions => arch::log("TooManyRegions"),
                boot::BootError::NoSuitableRegion => arch::log("NoSuitableRegion"),
                boot::BootError::OverlapInternal => arch::log("OverlapInternal"),
            }
            arch::log("\n");
        }
    }

    // Phase 29e — boot the rootserver. Loads the bundled ELF (built
    // separately from `rootserver/`), builds its VSpace + TCB, and
    // sysretq's into user mode at its `_start`. Replaces the AY
    // hand-asm demo as the canonical "kernel actually runs userspace"
    // bootstrap. The dispatcher exits QEMU when the rootserver
    // prints '\n' (closing its banner).
    #[cfg(target_arch = "x86_64")]
    unsafe {
        crate::rootserver::launch_rootserver();
    }

    #[cfg(any(not(target_arch = "x86_64"), not(feature = "spec")))]
    loop {}
}

/// AP entry — wait for BSP to finish populating shared structures,
/// then load them, set up per-CPU MSRs, signal alive, halt forever.
/// Phase 28d will replace the halt loop with the per-CPU scheduler.
fn ap_main(apic_id: arch::CpuId) -> ! {
    // For QEMU and most hardware, APIC IDs are dense starting at 0,
    // so we use APIC ID as the per-CPU index. Production may need a
    // MADT-driven apic_id → cpu_index table.
    let cpu_id = apic_id;
    if (cpu_id as usize) >= smp::MAX_CPUS {
        arch::halt_cpu();
        loop {}
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let top = (&raw const AP_BIG_STACKS[cpu_id as usize] as u64)
            + core::mem::size_of::<ApStack>() as u64;
        core::arch::asm!(
            "mov rsp, {top}",
            "mov rdi, {apic}",
            "jmp {cont}",
            top = in(reg) top & !0xF,
            apic = in(reg) apic_id as u64,
            cont = sym ap_main_big_stack,
            options(noreturn),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    ap_main_big_stack(apic_id)
}

fn ap_main_big_stack(apic_id: arch::CpuId) -> ! {
    smp::wait_for_bsp_ready();

    // For QEMU and most hardware, APIC IDs are dense starting at 0,
    // so we use APIC ID as the per-CPU index. Production may need a
    // MADT-driven apic_id → cpu_index table.
    let cpu_id = apic_id;

    arch::init_gdt_for_cpu(cpu_id);
    arch::load_idt();
    arch::init_syscall_msrs();
    // Phase 28d — each AP needs its own LAPIC software-enabled
    // before it can deliver/receive IPIs. The MMIO mapping is
    // shared (Simpleboot identity-maps the LAPIC page); only the
    // SVR + TPR writes are per-CPU.
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::lapic::init_lapic();

    // Each AP needs its own FPU/CR4 set up to match the BSP, or migrated
    // threads run with a different FPU config across cores (FPU0002).
    #[cfg(all(target_arch = "x86_64", feature = "smp"))]
    crate::arch::x86_64::fpu_ctx::init_fpu_ap();

    smp::mark_ap_alive();

    ap_scheduler_loop();
}

/// AP scheduler loop. Each iteration:
///   1. takes the BKL,
///   2. checks this CPU's `current` pointer — if `Some(tcb)`,
///      sets up CR3 + per-CPU user_ctx and dispatches via
///      `enter_user_via_sysret` (never returns to this loop;
///      from then on the user thread cycles through
///      SYSCALL → dispatcher → sysretq on this CPU),
///   3. else releases the BKL and `sti; hlt`s until an IPI / IRQ
///      wakes us.
///
/// Interrupts are kept off while inside the kernel and on while
/// HLTed. STI immediately followed by HLT is the canonical way
/// to atomically "enable interrupts and wait for one" on x86.
fn ap_scheduler_loop() -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        // Capture this CPU's high-half AP stack — it doubles as the
        // kernel-mode stack for SYSCALL re-entry and IRQ entry.
        let my_ksp: u64;
        unsafe {
            core::arch::asm!(
                "mov {}, rsp",
                out(reg) my_ksp,
                options(nomem, nostack, preserves_flags),
            );
        }
        let my_cpu = arch::get_cpu_id();
        crate::arch::x86_64::syscall_entry::set_syscall_kernel_rsp(my_ksp);
        crate::arch::x86_64::gdt::set_kernel_rsp_for_cpu(my_cpu, my_ksp);
    }

    loop {
        smp::bkl_acquire();

        #[cfg(target_arch = "x86_64")]
        {
            let my_cpu = arch::get_cpu_id();
            // Phase 42 — fall through to choose_thread() when
            // `current` is None so an AP that's been HLT'd can
            // pick up newly-runnable threads enqueued by an IRQ-
            // driven make_runnable on this CPU. Without this, AP1
            // stays parked forever once `current` is cleared,
            // even if its queue has work — strands sel4test's
            // per-CPU timer threads.
            let next = unsafe {
                let s = crate::kernel::KERNEL.get();
                match s.scheduler.current_for_cpu(my_cpu) {
                    Some(t) => Some(t),
                    None => {
                        let picked = s.scheduler.choose_thread();
                        if let Some(id) = picked {
                            s.scheduler.set_current(Some(id));
                        }
                        picked
                    }
                }
            };
            if let Some(tcb_id) = next {
                // Only dispatch threads that have a real vspace
                // (cr3 != 0). A bare scheduler-test TCB has cr3=0
                // and would sysretq into RIP=0 → user PF. Specs
                // that want to merely place a TCB on the AP's
                // queue without dispatching should leave cr3=0.
                let dispatchable = unsafe {
                    crate::kernel::KERNEL
                        .get()
                        .scheduler
                        .slab
                        .get(tcb_id)
                        .cpu_context
                        .cr3
                        != 0
                };
                if dispatchable {
                    let ctx_ptr = unsafe {
                        let s = crate::kernel::KERNEL.get();
                        // activateThread — write a pending YieldTo
                        // consumed-report before snapshotting ctx.
                        crate::sched_context::complete_yield_if_pending(tcb_id);
                        let tcb = s.scheduler.slab.get(tcb_id);
                        // Snapshot the context now (Copy) so the FPU
                        // switch below can take `&mut slab` after the
                        // immutable `tcb` borrow has ended.
                        let next_user_ctx = tcb.user_context;

                        // SMP: if this AP went idle since its last
                        // dispatch, reload CR3 to flush a possibly-stale
                        // TLB (shootdown_tlb skips idle cores, expecting
                        // this flush — MULTICORE0002). Otherwise only
                        // reload on a vspace change so the yield-stress
                        // test doesn't crawl (MULTICORE0004).
                        #[cfg(feature = "smp")]
                        let was_idle = crate::smp::take_went_idle();
                        #[cfg(not(feature = "smp"))]
                        let was_idle = false;
                        let cur_cr3: u64;
                        core::arch::asm!(
                            "mov {}, cr3",
                            out(reg) cur_cr3,
                            options(nomem, nostack, preserves_flags),
                        );
                        if was_idle || cur_cr3 != tcb.cpu_context.cr3 {
                            core::arch::asm!(
                                "mov cr3, {}",
                                in(reg) tcb.cpu_context.cr3,
                                options(nostack, preserves_flags),
                            );
                        }

                        // Restore per-thread FS_BASE so userspace TLS
                        // (`%fs:0` reads) sees this thread's TLS.
                        crate::arch::x86_64::msr::wrmsr(
                            crate::arch::x86_64::msr::IA32_FS_BASE,
                            tcb.cpu_context.fs_base,
                        );
                        // Restore the per-thread user %gs base into the swapped-out
                        // MSR: the return-to-user `swapgs` makes `%gs` this thread's
                        // TEB (Windows `%gs:0x30`), while the active %gs stays the
                        // kernel per-CPU base for the next SYSCALL entry. Threads that
                        // never set a gs base carry 0 (harmless).
                        crate::arch::x86_64::msr::wrmsr(
                            crate::arch::x86_64::msr::IA32_KERNEL_GS_BASE,
                            tcb.cpu_context.gs_base,
                        );

                        // SMP: make this thread's FPU state resident on
                        // this AP before resuming it (fxsave outgoing
                        // owner, fxrstor this thread). Critical for
                        // FPU0002 round-robin migration.
                        #[cfg(feature = "smp")]
                        crate::arch::x86_64::fpu_ctx::fpu_switch_to(&mut s.scheduler.slab, tcb_id);

                        let pcc = crate::arch::x86_64::syscall_entry::current_cpu_user_ctx_mut();
                        *pcc = next_user_ctx;
                        s.scheduler.set_active_user(Some(tcb_id));
                        pcc as *const crate::arch::x86_64::syscall_entry::UserContext
                    };

                    // IRQ-preempted threads carry true rcx/r11 GPRs
                    // and RIP/RFLAGS in dedicated fields — resume
                    // via iretq, not sysretq.
                    let use_iretq = unsafe {
                        // Don't clear — use_iretq_resume tracks the save
                        // flavor and persists until the next save.
                        crate::kernel::KERNEL
                            .get()
                            .scheduler
                            .slab
                            .get(tcb_id)
                            .use_iretq_resume
                    };
                    smp::bkl_release();
                    unsafe {
                        if use_iretq {
                            crate::arch::x86_64::syscall_entry::enter_user_via_iretq(ctx_ptr);
                        }
                        crate::arch::x86_64::syscall_entry::enter_user_via_sysret(ctx_ptr);
                    }
                    // unreachable
                }
            }
        }

        // SMP: this AP is about to idle — flush its live FPU state back
        // to the owner TCB so a thread migrated off this idle core (which
        // `remote_tcb_stall` won't stall/flush) restores fresh state.
        // Critical for FPU0002 reliability across 400 migrations.
        #[cfg(all(target_arch = "x86_64", feature = "smp"))]
        unsafe {
            crate::arch::x86_64::fpu_ctx::flush_local_fpu(
                &mut crate::kernel::KERNEL.get().scheduler.slab,
            );
        }
        unsafe {
            crate::kernel::KERNEL.get().scheduler.set_active_user(None);
        }
        // Park on the kernel root page table before idling: a user
        // vspace left in CR3 can be freed by another core's process
        // teardown, after which our next interrupt reads an unmapped
        // IDT and triple-faults (MULTICORE0003 cross-AS teardown).
        #[cfg(all(target_arch = "x86_64", feature = "smp"))]
        crate::arch::x86_64::paging::park_on_kernel_root();
        // Mark went-idle so the next dispatch flushes a possibly-stale
        // TLB (this AP misses shootdowns while idle).
        smp::mark_went_idle();
        smp::bkl_release();

        // Wait for next IPI / IRQ. `cli` after `hlt` restores the
        // kernel's IF=0 invariant before this loop re-acquires the BKL at
        // the top, so an IRQ can't re-enter bkl_acquire while we hold it
        // (the BKL re-entrancy / silent-hang class fixed in the BSP idle
        // loops — syscall_entry.rs / exceptions.rs).
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("sti", "hlt", "cli", options(nostack, preserves_flags),);
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // seL4's AArch64 idle path ultimately waits with WFI. Exception
            // entry will own DAIF masking once the vector table lands.
            core::arch::asm!("wfi", options(nostack, nomem));
        }
    }
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch::log("PANIC: ");
    if let Some(loc) = info.location() {
        arch::log(loc.file());
        arch::log(":");

        let mut n = loc.line();
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        if let Ok(s) = core::str::from_utf8(&buf[i..]) {
            arch::log(s);
        }
    }
    arch::log("\n");

    #[cfg(any(feature = "spec", feature = "extern-rootserver"))]
    arch::qemu_exit(255);

    #[cfg(not(any(feature = "spec", feature = "extern-rootserver")))]
    loop {}
}
