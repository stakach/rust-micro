//! AArch64 hardware-debug state compatible with seL4's Cortex-A53 ABI.

use crate::arch::UserContext;

pub const SEL4_DATA_BREAKPOINT: u64 = 0;
pub const SEL4_INSTRUCTION_BREAKPOINT: u64 = 1;
pub const SEL4_SINGLE_STEP: u64 = 2;
pub const SEL4_SOFTWARE_BREAK_REQUEST: u64 = 3;

pub const SEL4_BREAK_ON_READ: u64 = 0;
pub const SEL4_BREAK_ON_WRITE: u64 = 1;
pub const SEL4_BREAK_ON_READWRITE: u64 = 2;

pub const SEL4_NUM_EXCLUSIVE_BREAKPOINTS: usize = 6;
pub const SEL4_NUM_EXCLUSIVE_WATCHPOINTS: usize = 4;
pub const SEL4_NUM_HW_BREAKPOINTS: usize =
    SEL4_NUM_EXCLUSIVE_BREAKPOINTS + SEL4_NUM_EXCLUSIVE_WATCHPOINTS;

const CONTROL_ENABLE: u64 = 1;
const CONTROL_USER: u64 = 2 << 1;
const MDSCR_SS: u64 = 1;
const MDSCR_MDE: u64 = 1 << 15;
const SPSR_SS: u64 = 1 << 21;

#[derive(Copy, Clone, Debug)]
pub struct DebugState {
    breakpoint_value: [u64; SEL4_NUM_EXCLUSIVE_BREAKPOINTS],
    breakpoint_control: [u64; SEL4_NUM_EXCLUSIVE_BREAKPOINTS],
    watchpoint_value: [u64; SEL4_NUM_EXCLUSIVE_WATCHPOINTS],
    watchpoint_control: [u64; SEL4_NUM_EXCLUSIVE_WATCHPOINTS],
    used_breakpoints_bf: u32,
    pub n_instructions: u64,
    pub single_step_enabled: bool,
}

impl DebugState {
    pub const fn new() -> Self {
        Self {
            breakpoint_value: [0; SEL4_NUM_EXCLUSIVE_BREAKPOINTS],
            breakpoint_control: [0; SEL4_NUM_EXCLUSIVE_BREAKPOINTS],
            watchpoint_value: [0; SEL4_NUM_EXCLUSIVE_WATCHPOINTS],
            watchpoint_control: [0; SEL4_NUM_EXCLUSIVE_WATCHPOINTS],
            used_breakpoints_bf: 0,
            n_instructions: 0,
            single_step_enabled: false,
        }
    }
}

impl Default for DebugState {
    fn default() -> Self {
        Self::new()
    }
}

fn size_to_bas(size: u64) -> u64 {
    match size {
        1 => 0x01,
        2 => 0x03,
        8 => 0xff,
        _ => 0x0f,
    }
}

fn bas_to_size(bas: u64) -> u64 {
    match bas {
        0x01 => 1,
        0x03 => 2,
        0xff => 8,
        _ => 4,
    }
}

fn access_to_lsc(access: u64) -> u64 {
    match access {
        SEL4_BREAK_ON_READ => 1,
        SEL4_BREAK_ON_WRITE => 2,
        _ => 3,
    }
}

fn lsc_to_access(lsc: u64) -> u64 {
    match lsc {
        1 => SEL4_BREAK_ON_READ,
        2 => SEL4_BREAK_ON_WRITE,
        _ => SEL4_BREAK_ON_READWRITE,
    }
}

pub fn valid_id_for_type(bp_num: usize, ty: u64) -> bool {
    if ty == SEL4_INSTRUCTION_BREAKPOINT {
        bp_num < SEL4_NUM_EXCLUSIVE_BREAKPOINTS
    } else {
        (SEL4_NUM_EXCLUSIVE_BREAKPOINTS..SEL4_NUM_HW_BREAKPOINTS).contains(&bp_num)
    }
}

pub fn set_breakpoint(
    state: &mut DebugState,
    bp_num: usize,
    vaddr: u64,
    ty: u64,
    size: u64,
    access: u64,
) {
    if ty == SEL4_INSTRUCTION_BREAKPOINT {
        state.breakpoint_value[bp_num] = vaddr;
        state.breakpoint_control[bp_num] = CONTROL_ENABLE | CONTROL_USER | (0x0f << 5);
    } else {
        let index = bp_num - SEL4_NUM_EXCLUSIVE_BREAKPOINTS;
        state.watchpoint_value[index] = vaddr;
        state.watchpoint_control[index] =
            CONTROL_ENABLE | CONTROL_USER | (access_to_lsc(access) << 3) | (size_to_bas(size) << 5);
    }
    state.used_breakpoints_bf |= 1 << bp_num;
}

pub fn get_breakpoint(state: &DebugState, bp_num: usize) -> (u64, u64, u64, u64, u64) {
    if bp_num < SEL4_NUM_EXCLUSIVE_BREAKPOINTS {
        (
            state.breakpoint_value[bp_num],
            SEL4_INSTRUCTION_BREAKPOINT,
            0,
            SEL4_BREAK_ON_READ,
            state.breakpoint_control[bp_num] & CONTROL_ENABLE,
        )
    } else {
        let index = bp_num - SEL4_NUM_EXCLUSIVE_BREAKPOINTS;
        let control = state.watchpoint_control[index];
        (
            state.watchpoint_value[index],
            SEL4_DATA_BREAKPOINT,
            bas_to_size((control >> 5) & 0xff),
            lsc_to_access((control >> 3) & 0x3),
            control & CONTROL_ENABLE,
        )
    }
}

pub fn unset_breakpoint(state: &mut DebugState, bp_num: usize) {
    if bp_num < SEL4_NUM_EXCLUSIVE_BREAKPOINTS {
        state.breakpoint_value[bp_num] = 0;
        state.breakpoint_control[bp_num] &= !CONTROL_ENABLE;
    } else {
        let index = bp_num - SEL4_NUM_EXCLUSIVE_BREAKPOINTS;
        state.watchpoint_value[index] = 0;
        state.watchpoint_control[index] &= !CONTROL_ENABLE;
    }
    state.used_breakpoints_bf &= !(1 << bp_num);
}

pub fn configure_single_stepping(state: &mut DebugState, n_instructions: u64) -> bool {
    state.single_step_enabled = n_instructions != 0;
    state.n_instructions = n_instructions;
    true
}

pub fn single_step_counter_ready(state: &mut DebugState) -> bool {
    if state.n_instructions > 0 {
        state.n_instructions -= 1;
    }
    state.n_instructions == 0
}

pub fn active_breakpoint(state: &DebugState, vaddr: u64, reason: u64) -> Option<usize> {
    if reason == SEL4_INSTRUCTION_BREAKPOINT {
        state
            .breakpoint_value
            .iter()
            .zip(state.breakpoint_control.iter())
            .position(|(&value, &control)| control & CONTROL_ENABLE != 0 && value == vaddr)
    } else {
        state
            .watchpoint_value
            .iter()
            .zip(state.watchpoint_control.iter())
            .position(|(&value, &control)| {
                if control & CONTROL_ENABLE == 0 {
                    return false;
                }
                let size = bas_to_size((control >> 5) & 0xff);
                value == vaddr & !(size - 1)
            })
            .map(|index| index + SEL4_NUM_EXCLUSIVE_BREAKPOINTS)
    }
}

macro_rules! debug_register_writers {
    ($write:ident, $($index:literal => $register:literal),+ $(,)?) => {
        unsafe fn $write(index: usize, value: u64) {
            match index {
                $($index => core::arch::asm!(concat!("msr ", $register, ", {value}"), value = in(reg) value, options(nomem, nostack)),)+
                _ => unreachable!(),
            }
        }
    };
}

debug_register_writers!(write_bvr,
    0 => "dbgbvr0_el1", 1 => "dbgbvr1_el1", 2 => "dbgbvr2_el1",
    3 => "dbgbvr3_el1", 4 => "dbgbvr4_el1", 5 => "dbgbvr5_el1",
);
debug_register_writers!(write_bcr,
    0 => "dbgbcr0_el1", 1 => "dbgbcr1_el1", 2 => "dbgbcr2_el1",
    3 => "dbgbcr3_el1", 4 => "dbgbcr4_el1", 5 => "dbgbcr5_el1",
);
debug_register_writers!(write_wvr,
    0 => "dbgwvr0_el1", 1 => "dbgwvr1_el1", 2 => "dbgwvr2_el1", 3 => "dbgwvr3_el1",
);
debug_register_writers!(write_wcr,
    0 => "dbgwcr0_el1", 1 => "dbgwcr1_el1", 2 => "dbgwcr2_el1", 3 => "dbgwcr3_el1",
);

pub fn init() {
    unsafe {
        let mut mdscr: u64;
        core::arch::asm!("mrs {value}, mdscr_el1", value = out(reg) mdscr, options(nomem, nostack));
        mdscr = (mdscr | MDSCR_MDE) & !MDSCR_SS;
        core::arch::asm!("msr mdscr_el1, {value}", value = in(reg) mdscr, options(nomem, nostack));
        for index in 0..SEL4_NUM_EXCLUSIVE_BREAKPOINTS {
            write_bvr(index, 0);
            write_bcr(index, 0);
        }
        for index in 0..SEL4_NUM_EXCLUSIVE_WATCHPOINTS {
            write_wvr(index, 0);
            write_wcr(index, 0);
        }
        core::arch::asm!("isb", options(nomem, nostack));
    }
}

pub fn restore_user_debug_context(state: &DebugState, context: &mut UserContext) {
    unsafe {
        for index in 0..SEL4_NUM_EXCLUSIVE_BREAKPOINTS {
            if state.used_breakpoints_bf & (1 << index) != 0 {
                write_bvr(index, state.breakpoint_value[index]);
                write_bcr(index, state.breakpoint_control[index]);
            } else {
                write_bcr(index, 0);
            }
        }
        for index in 0..SEL4_NUM_EXCLUSIVE_WATCHPOINTS {
            if state.used_breakpoints_bf & (1 << (index + SEL4_NUM_EXCLUSIVE_BREAKPOINTS)) != 0 {
                write_wvr(index, state.watchpoint_value[index]);
                write_wcr(index, state.watchpoint_control[index]);
            } else {
                write_wcr(index, 0);
            }
        }
        let mut mdscr: u64;
        core::arch::asm!("mrs {value}, mdscr_el1", value = out(reg) mdscr, options(nomem, nostack));
        if state.single_step_enabled {
            mdscr |= MDSCR_SS;
            context.spsr_el1 |= SPSR_SS;
        } else {
            mdscr &= !MDSCR_SS;
            context.spsr_el1 &= !SPSR_SS;
        }
        core::arch::asm!("msr mdscr_el1, {value}", value = in(reg) mdscr, options(nomem, nostack));
    }
}
