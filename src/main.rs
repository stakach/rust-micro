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

// Unified KResult / KException error type.
mod error;

// Syscall dispatcher (handle_syscall + handle_unknown_syscall).
mod syscall_handler;

// Endpoint state machine (slowpath IPC).
mod endpoint;

// Notification state machine (signal/wait).
mod notification;

// IRQ → notification dispatch.
mod interrupt;

// x86_64 virtual-address-space helpers (paging algorithm).
mod vspace;

// Phase 10a — MCS scheduling-context object (gated behind cargo
// `mcs` feature). Adds sporadic-server refill bookkeeping on top of
// the classic scheduler.
#[cfg(feature = "mcs")]
mod sched_context;

// Phase 10b — multi-CPU support: per-CPU NodeState + IPI dispatch.
#[cfg(feature = "smp")]
mod smp;

// Phase 10c — IPC fastpath bypassing the slowpath book-keeping for
// the common-case Call / ReplyRecv shape.
#[cfg(feature = "fastpath")]
mod fastpath;

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
        arch::init_serial();
        arch::log("Serial initialized!\n");
        
        arch::log("Initializing interrupts...\n");
        arch::init_interrupts();
        
        arch::log("Initializing exception handlers...\n");
        arch::init_exceptions();
        
        arch::log("Kernel initialization complete on BSP\n");
        
        #[cfg(feature = "spec")]
        spec::test_main();
        
        loop {}
    } else {
        // Non-bootstrap processors should halt until needed
        arch::halt_cpu();
        loop {}
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
