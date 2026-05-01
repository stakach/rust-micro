// configure Rust compiler
#![no_std]
#![no_main]

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
mod bootboot;

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
#[cfg(feature = "mcs")]
mod sched_context;

// Phase 10b / 28 — multi-CPU support: per-CPU NodeState + IPI
// dispatch. Always-on now that BOOTBOOT drops every CPU at
// `_start`; the `smp` cargo feature still gates the spec runner
// for the smp module to keep its tests scoped.
mod smp;

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

/******************************************
 * Entry point, called by BOOTBOOT Loader *
 ******************************************/
// NOTE: this code runs on all cores in parallel
#[no_mangle]
fn _start() -> ! {
    use bootboot::*;

    // use the BOOTBOOT_INFO as a pointer, dereference it and immediately borrow it.
    let _bootboot_r = unsafe { & (*(BOOTBOOT_INFO as *const BOOTBOOT)) };

    // Only initialize on the bootstrap processor
    // Check if current APIC ID matches the BOOTBOOT BSP ID
    let current_apic_id = arch::get_cpu_id();
    let bootboot_bsp_id = bootboot::get_bootstrap_processor_id() as arch::CpuId;
    
    if current_apic_id == bootboot_bsp_id {
        bsp_main();
    } else {
        ap_main(current_apic_id);
    }
}

/// BSP entry — runs all global init (serial, GDT contents, IDT
/// contents, exception vectors), signals APs to come up, waits for
/// the AP barrier, then runs spec runner / demo.
fn bsp_main() -> ! {
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

    // Phase 28d — install kernel page tables (so the LAPIC is
    // mapped at KERNEL_LAPIC_VBASE) then software-enable the BSP's
    // LAPIC. Once enabled, IPI delivery works in either direction.
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::paging::install_kernel_page_tables();
        crate::arch::x86_64::lapic::init_lapic();
    }

    arch::log("Kernel initialization complete on BSP\n");

    // Release APs — the shared GDT and IDT are now populated, so
    // they can safely lgdt/lidt and load their per-CPU TSS.
    let n_cores = bootboot::get_num_cores() as u32;
    let n_aps = n_cores.saturating_sub(1);
    smp::signal_bsp_ready();
    if n_aps > 0 {
        arch::log("Waiting for APs to come up...\n");
        smp::wait_for_aps(n_aps);
        arch::log("All APs up\n");
    }

    #[cfg(feature = "spec")]
    spec::test_main();

    // Real boot orchestration: read the loader's memory map,
    // place the rootserver. Phase 12d runs this on the live
    // BOOTBOOT-supplied state — useful as an end-to-end smoke
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

    // Phase 14d — two-thread IPC ping-pong. Spawns a sender +
    // receiver, both ring-3, sharing an Endpoint cap. The
    // dispatcher exits QEMU once it sees both threads complete
    // their SysDebugPutChar invocations.
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::usermode::launch_two_thread_ipc_demo();

    #[cfg(any(not(target_arch = "x86_64"), not(feature = "spec")))]
    loop {}
}

/// AP entry — wait for BSP to finish populating shared structures,
/// then load them, set up per-CPU MSRs, signal alive, halt forever.
/// Phase 28d will replace the halt loop with the per-CPU scheduler.
fn ap_main(apic_id: arch::CpuId) -> ! {
    smp::wait_for_bsp_ready();

    // For QEMU and most hardware, APIC IDs are dense starting at 0,
    // so we use APIC ID as the per-CPU index. Production may need a
    // MADT-driven apic_id → cpu_index table.
    let cpu_id = apic_id;
    if (cpu_id as usize) >= smp::MAX_CPUS {
        arch::halt_cpu();
        loop {}
    }

    arch::init_gdt_for_cpu(cpu_id);
    arch::load_idt();
    arch::init_syscall_msrs();
    // Phase 28d — each AP needs its own LAPIC software-enabled
    // before it can deliver/receive IPIs. The MMIO mapping is
    // shared (BOOTBOOT identity-maps the LAPIC page); only the
    // SVR + TPR writes are per-CPU.
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::lapic::init_lapic();

    smp::mark_ap_alive();

    ap_scheduler_loop();
}

/// AP idle loop. Each iteration:
///   1. takes the BKL,
///   2. lets the IPI ISR / scheduler decide what should run on this
///      CPU (today, just looks at this CPU's current pointer; once
///      Phase 28f lands per-CPU SYSCALL_SAVE the AP will dispatch
///      user threads here),
///   3. releases the BKL,
///   4. HLTs until an interrupt (typically a Reschedule IPI from
///      another CPU or an IRQ).
///
/// Interrupts are kept on while HLTed and off while inside the
/// kernel. STI immediately followed by HLT is the canonical way
/// to atomically "enable interrupts and wait for one" on x86.
fn ap_scheduler_loop() -> ! {
    loop {
        // Tighten the kernel-vs-user-mode invariant: every wake-up
        // immediately re-enters the kernel under BKL, then exits.
        smp::bkl_acquire();
        // (Future: if `current` is Some(tcb), context-switch into
        // it here. For Phase 28e we just observe the pick.)
        smp::bkl_release();

        // Wait for next IPI / IRQ.
        unsafe {
            core::arch::asm!(
                "sti",
                "hlt",
                options(nostack, preserves_flags),
            );
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

    #[cfg(feature = "spec")]
    arch::qemu_exit(255);

    #[cfg(not(feature = "spec"))]
    loop {}
}
