# Rust Micro Kernel Development

* You are an experienced Operating Systems Engineer
* Building a high performance memory safe operating system using Rust programming language
* high performance is gained by using io_uring-like techniques for IPC in a microkernel
  * Zero-copy messaging: Between user space and kernel or driver contexts.
  * High throughput IPC: Via shared ring buffers instead of syscalls or message queues.
  * Event-driven drivers: Drivers reacting to completions rather than polling or blocking.
  * Userspace subsystems: Allowing drivers or services (e.g. network stack, filesystems) to live outside the kernel and communicate async through submission/completion queues.
  * Device access: Also consider IOMMU and DMA-safe buffers for secure async device interaction from userspace.
* Don't use external crates, the kernel should have as few dependencies as possible.
* No half measures. Add TODOs where a shortcut is being taken to move past a blocker. Return to these once you've been able to move forward. This is a critical system.

The kernels source code should be well commented and structured for readability and testability.

## High level architecture

1. Bootloader: Bootboot (implemented)
2. main.rs: setup memory layout + CPU features
  * focus on x86_64 however ensure features are generalized enough to allow for other CPU architectures in the future
3. init.rs
  * Process table, VM maps
  * Page allocator, PMM
  * Ring buffers
  * Minimal IRQ handlers
  * Timer, scheduler
  * Initial userspace tasks (initfs, shell, etc.)

There should be public interfaces for each subsystem that is not architecture specific. This way additional architectures can be added.

* `arch.rs` should be used to define public interfaces

## Building and testing

There are scripts for:

* ./scripts/build_kernel.sh - compiles the kernel with the spec feature flag and any additional ones you pass to it
  * i.e. `./scripts/build_kernel.sh paging` to test paging
* ./scripts/make_image.sh - makes a bootable disk image
* ./scripts/run_specs.sh - runs the kernel in qemu with serial output enabled for debugging

Scope specs to the spec namespace so they can be removed from a production kernel.

* Specs should test public interfaces and not architecture level code. i.e. does the public paging interface work. This way specs can be run against multiple architectures.
* Specs should be written for all public interfaces of subsystems in the kernel. Specs for each subsystem could be implemented behind a feature flag for focused testing.

The kernel should fully initialize before running specs and then exit using `qemu_exit` once spec running is complete.

## Additional notes

* Bootboot initializes all CPU cores so the _start function code runs on all cores in parallel so it might be wise to halt cores that are not the bootstrap_processor_id until the scheduler is initialized. When we're ready for SMP we can use an interrupt to start them again.

## Progress

### Completed Architecture Initialization (2025-07-08)

**Core Architecture Framework:**
- ✅ Created portable architecture abstraction layer in `arch.rs`
- ✅ Implemented x86_64-specific modules: `cpu.rs`, `interrupts.rs`, `exceptions.rs`
- ✅ Bootstrap processor detection using BOOTBOOT structure (`bspid` field)
- ✅ Core halting for non-BSP cores until scheduler initialization
- ✅ Interrupt descriptor table (IDT) initialization
- ✅ Exception handlers for all x86_64 CPU exceptions (divide by zero, page fault, etc.)
- ✅ Fatal exception handling with logging and qemu_exit for unrecoverable errors

**Testing Infrastructure:**
- ✅ Architecture-specific specs in `spec/arch_tests.rs`
- ✅ CPU ID and bootstrap processor detection tests
- ✅ All specs passing successfully

**Key Implementation Details:**
- Only bootstrap processor initializes the kernel (other cores are halted)
- Bootstrap processor ID retrieval is architecture-agnostic (in `bootboot.rs`)
- Architecture-specific functions remain in their respective modules
- Proper APIC ID detection from APIC ID register (offset 0x20 from APIC base, bits 31:24)
- Robust BSP detection with APIC ID correctly matching BOOTBOOT BSP ID
- Comprehensive exception handling with descriptive error messages
- Memory-safe IDT management using shared static arrays
- Proper naked function implementation for low-level interrupt handlers

**Macro-Based Interrupt System (Latest Update):**
- ✅ Implemented clean `interrupt!` and `interrupt_with_error!` macros in `interrupts.rs`
- ✅ Converted all exception handlers to use macro-generated naked functions
- ✅ Proper `naked_asm!` usage with modern Rust syntax (`#[unsafe(naked)]`)
- ✅ Exported macros with `pub(crate) use` for module access
- ✅ Removed all legacy naked function definitions
- ✅ All builds pass with only minor warnings (unused traits, functions)
- ✅ Full test suite continues to pass with macro-based system

**Current Status:**
The kernel successfully boots, initializes core x86_64 features with a clean macro-based interrupt system, and passes all architecture tests. The interrupt handling infrastructure is now production-ready. Ready for next phase: memory management and process initialization.
