//! aarch64 exception handlers stub.
//!
//! Real aarch64 has 16 exception entries (sync/IRQ/FIQ/SError × 4
//! exception levels) in the vector table. The handlers there
//! decode ESR_EL1 to dispatch to the right kernel routine. Pinning
//! that out is the same shape as the x86_64 IDT setup; we leave it
//! TODO so the trait is satisfied.

pub fn init_exceptions() {
    // TODO: VBAR_EL1 = vector_table_addr; per-class handlers.
}
