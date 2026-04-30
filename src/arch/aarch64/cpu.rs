//! aarch64 CPU stubs. Phase 10f leaves these as TODO bodies — the
//! kernel core is portable and the spec runner doesn't exercise
//! these paths on aarch64 (we don't have a target spec or boot
//! protocol pinned for the second architecture yet). Adding a real
//! aarch64 boot path is purely additive.

use crate::arch::CpuId;

pub fn get_cpu_id() -> CpuId {
    // MPIDR_EL1 holds the affinity-aware CPU identifier in real
    // aarch64 boot. Return 0 so the BSP-only assertion in main.rs
    // would let us through in a hypothetical aarch64 build.
    let mut mpidr: u64 = 0;
    unsafe {
        core::arch::asm!("mrs {x}, mpidr_el1", x = out(reg) mpidr,
            options(nostack, nomem, preserves_flags));
    }
    (mpidr & 0xFF) as CpuId
}

pub fn halt_cpu() {
    // WFI = wait-for-interrupt. Park the core until an IRQ wakes
    // it.
    unsafe {
        core::arch::asm!("wfi", options(nostack, nomem, preserves_flags));
    }
}
