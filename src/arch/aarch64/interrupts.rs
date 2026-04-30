//! aarch64 interrupts stub.
//!
//! Real aarch64 sets up the GIC (Generic Interrupt Controller) and
//! installs an exception-vector table at VBAR_EL1. None of that is
//! wired here — the function is a TODO so the public arch interface
//! compiles. A future commit replaces this with a proper GIC driver
//! and naked vector entries similar to the x86_64 IDT setup.

pub fn init_interrupts() {
    // TODO: install vector table, configure GIC distributor and
    // CPU interface, mask all IRQs until the scheduler is up.
}
