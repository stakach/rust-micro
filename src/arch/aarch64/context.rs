//! Saved EL0 register state.

/// Register order matches seL4's `enum _register` in
/// `include/arch/arm/arch/64/mode/machine/registerset.h`: `x0..x30`,
/// `SP_EL0`, `ELR_EL1`, `SPSR_EL1`, `FaultIP`, `TPIDR_EL0`, and
/// `TPIDRRO_EL0`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UserContext {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub fault_ip: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
}

const _: () = assert!(core::mem::size_of::<UserContext>() == 37 * core::mem::size_of::<u64>());

impl UserContext {
    pub const fn new_zero() -> Self {
        Self {
            x: [0; 31],
            sp_el0: 0,
            elr_el1: 0,
            spsr_el1: 0,
            fault_ip: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
        }
    }
}
