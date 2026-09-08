//! Hardware-debug API backend (CONFIG_HARDWARE_DEBUG_API).
//!
//! Mirrors `seL4/src/arch/x86/machine/breakpoint.c` + the DR7 bit
//! definitions in `include/arch/x86/arch/machine/debug.h`. x86 has 4
//! debug-address registers (DR0-DR3), a status register (DR6) and a
//! control register (DR7). Each of the 4 breakpoints is dual-function
//! (instruction OR data). The per-thread `DebugState` caches the DR
//! values; the live registers are only written on return-to-user
//! (`load_breakpoint_state`).
//!
//! DR6 is captured before clearing live status in the #DB path; raw context installation
//! changes only the register image, not the separate counted-stepping policy.

// ---- API enum values (libsel4 sel4/constants.h) -------------------------
// NB: Data = 0, Instruction = 1 — easy to invert.
pub const SEL4_DATA_BREAKPOINT: u64 = 0;
pub const SEL4_INSTRUCTION_BREAKPOINT: u64 = 1;
pub const SEL4_SINGLE_STEP: u64 = 2;
pub const SEL4_SOFTWARE_BREAK_REQUEST: u64 = 3;

pub const SEL4_BREAK_ON_READ: u64 = 0;
pub const SEL4_BREAK_ON_WRITE: u64 = 1;
pub const SEL4_BREAK_ON_READWRITE: u64 = 2;

pub const SEL4_NUM_HW_BREAKPOINTS: usize = 4;

// ---- DR7 field encodings (debug.h / breakpoint.c) -----------------------
// Preserve the existing seL4 setter's global-enable choice (odd bits). Hardware also accepts
// the local-enable bits at 0,2,4,6; queries, clearing, and raw context loads recognize both.
#[inline]
fn enable_bit(bp: usize) -> u64 {
    1u64 << (2 * bp + 1)
}
const ALL_ENABLE_BITS: u64 = 0xFF;
                                   // Per-bp 2-bit R/W field at 16,20,24,28 and 2-bit LEN field at 18,22,26,30.
#[inline]
fn type_shift(bp: usize) -> u64 {
    16 + 4 * bp as u64
}
#[inline]
fn len_shift(bp: usize) -> u64 {
    18 + 4 * bp as u64
}

// DR7 R/W (type) values.
const X86_BP_TYPE_INSTR: u64 = 0;
const X86_BP_TYPE_DATA_WRITE: u64 = 1;
const X86_BP_TYPE_DATA_READWRITE: u64 = 3;
// DR7 LEN (size) values.
const X86_BP_SIZE_1B: u64 = 0;
const X86_BP_SIZE_2B: u64 = 1;
const X86_BP_SIZE_8B: u64 = 2;
const X86_BP_SIZE_4B: u64 = 3;

// DR6 status bits.
pub const DR6_B0: u64 = 1 << 0;
pub const DR6_SINGLE_STEP: u64 = 1 << 14; // BS

// Reserved-bit init images (rather than snapshotting live regs).
const DR6_INIT: u64 = 0xFFFF_0FF0;
const DR7_INIT: u64 = 0x0000_0400; // bit 10 reserved-must-be-1
const DR6_STATUS_BITS: u64 = 0x0000_e00f; // B0-3, BD, BS, BT
const DR7_ALLOWED_BITS: u64 = 0xffff_07ff; // enables, LE/GE, bit10, RW/LEN

#[inline]
fn enable_pair(bp: usize) -> u64 {
    3u64 << (2 * bp)
}

// RFLAGS bits.
pub const FLAGS_TF: u64 = 1 << 8; // trap flag (single step)
pub const FLAGS_RF: u64 = 1 << 16; // resume flag

/// Per-thread debug state. `dr[0..3]` = breakpoint vaddrs, `dr[4]` =
/// DR6 cache, `dr[5]` = DR7 cache.
#[derive(Copy, Clone, Debug)]
pub struct DebugState {
    pub dr: [u64; 6],
    pub used_breakpoints_bf: u32,
    pub n_instructions: u64,
    pub single_step_enabled: bool,
}

impl Default for DebugState {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugState {
    pub const fn new() -> Self {
        Self {
            dr: [0, 0, 0, 0, DR6_INIT, DR7_INIT],
            used_breakpoints_bf: 0,
            n_instructions: 0,
            single_step_enabled: false,
        }
    }

    #[inline]
    pub fn any_breakpoint_used(&self) -> bool {
        self.used_breakpoints_bf != 0
    }

    fn set_used(&mut self, bp: usize) {
        self.used_breakpoints_bf |= 1 << bp;
    }
    fn clear_used(&mut self, bp: usize) {
        self.used_breakpoints_bf &= !(1u32 << bp);
    }
}

/// Fully validated register image. This carries no scheduling or counted-stepping policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawDebugContext {
    dr: [u64; 6],
    used_breakpoints_bf: u32,
}

/// Stage generic x86-64 hardware state, not NT's distinct address/control sanitization policy.
/// Every address must be safe for MOV DR; enabled comparators must describe a lower-user span.
pub fn validate_raw_context(mut dr: [u64; 6]) -> Result<RawDebugContext, ()> {
    if dr[4] & !(DR6_INIT | DR6_STATUS_BITS) != 0 || dr[5] & !DR7_ALLOWED_BITS != 0 {
        return Err(());
    }
    let mut used = 0;
    for bp in 0..SEL4_NUM_HW_BREAKPOINTS {
        if !super::vspace::canonical(dr[bp]) {
            return Err(());
        }
        let ty = (dr[5] >> type_shift(bp)) & 3;
        let len = (dr[5] >> len_shift(bp)) & 3;
        // I/O breakpoints need a distinct CR4.DE/port authority contract that is not exposed.
        if ty == 2 {
            return Err(());
        }
        if dr[5] & enable_pair(bp) == 0 {
            continue;
        }
        let bytes = if ty == X86_BP_TYPE_INSTR {
            if len != 0 { return Err(()); }
            1
        } else {
            arch_to_size(SEL4_DATA_BREAKPOINT, len)
        };
        if dr[bp] % bytes != 0
            || dr[bp] >= super::vspace::USER_VADDR_END
            || dr[bp].checked_add(bytes).is_none_or(|end| end > super::vspace::USER_VADDR_END)
        {
            return Err(());
        }
        used |= 1 << bp;
    }
    dr[4] = (dr[4] & DR6_STATUS_BITS) | DR6_INIT;
    dr[5] |= DR7_INIT;
    Ok(RawDebugContext { dr, used_breakpoints_bf: used })
}

/// Install only a prevalidated register image; live execution must already be quiescent.
pub fn install_raw_context(st: &mut DebugState, context: &RawDebugContext) {
    st.dr = context.dr;
    st.used_breakpoints_bf = context.used_breakpoints_bf;
}

/// Consume an acknowledged debug event without carrying sticky status into a later trap.
pub fn acknowledge_fault(st: &mut DebugState) {
    st.dr[4] = DR6_INIT;
}

#[inline]
pub fn breakpoint_enabled(st: &DebugState, bp: usize) -> bool {
    st.dr[5] & enable_pair(bp) != 0
}

// seL4_BreakpointType/Access -> DR7 R/W field.
fn type_and_access_to_arch(ty: u64, rw: u64) -> u64 {
    if ty == SEL4_INSTRUCTION_BREAKPOINT {
        X86_BP_TYPE_INSTR
    } else if rw == SEL4_BREAK_ON_WRITE {
        X86_BP_TYPE_DATA_WRITE
    } else {
        // x86 has no read-only DR mode; Read / ReadWrite both map to RW.
        X86_BP_TYPE_DATA_READWRITE
    }
}

fn size_to_arch(ty: u64, size: u64) -> u64 {
    if ty == SEL4_INSTRUCTION_BREAKPOINT {
        X86_BP_SIZE_1B
    } else {
        match size {
            1 => X86_BP_SIZE_1B,
            2 => X86_BP_SIZE_2B,
            8 => X86_BP_SIZE_8B,
            _ => X86_BP_SIZE_4B, // 4
        }
    }
}

fn arch_to_type_and_access(arch_rw: u64) -> (u64, u64) {
    match arch_rw {
        X86_BP_TYPE_INSTR => (SEL4_INSTRUCTION_BREAKPOINT, SEL4_BREAK_ON_READ),
        X86_BP_TYPE_DATA_WRITE => (SEL4_DATA_BREAKPOINT, SEL4_BREAK_ON_WRITE),
        _ => (SEL4_DATA_BREAKPOINT, SEL4_BREAK_ON_READWRITE),
    }
}

fn arch_to_size(ty: u64, arch_len: u64) -> u64 {
    if ty == SEL4_INSTRUCTION_BREAKPOINT {
        0
    } else {
        match arch_len {
            X86_BP_SIZE_1B => 1,
            X86_BP_SIZE_2B => 2,
            X86_BP_SIZE_8B => 8,
            _ => 4,
        }
    }
}

/// `setBreakpoint` (breakpoint.c:402).
pub fn set_breakpoint(st: &mut DebugState, bp: usize, vaddr: u64, ty: u64, size: u64, rw: u64) {
    let ts = type_shift(bp);
    let ls = len_shift(bp);
    let dr7val = (type_and_access_to_arch(ty, rw) << ts) | (size_to_arch(ty, size) << ls);
    st.dr[bp] = vaddr;
    // Clear this bp's type+size bits, then OR in the new config + enable.
    st.dr[5] &= !((0x3u64 << ls) | (0x3u64 << ts));
    st.dr[5] |= dr7val;
    st.dr[5] |= enable_bit(bp);
    st.set_used(bp);
}

/// `getBreakpoint` (breakpoint.c:445) -> (vaddr, type, size, rw, enabled).
pub fn get_breakpoint(st: &DebugState, bp: usize) -> (u64, u64, u64, u64, u64) {
    let ts = type_shift(bp);
    let ls = len_shift(bp);
    let arch_rw = (st.dr[5] >> ts) & 0x3;
    let arch_len = (st.dr[5] >> ls) & 0x3;
    let (ty, rw) = arch_to_type_and_access(arch_rw);
    let size = arch_to_size(ty, arch_len);
    let enabled = breakpoint_enabled(st, bp) as u64;
    (st.dr[bp], ty, size, rw, enabled)
}

/// `unsetBreakpoint` (breakpoint.c:467).
pub fn unset_breakpoint(st: &mut DebugState, bp: usize) {
    let ts = type_shift(bp);
    let ls = len_shift(bp);
    st.dr[5] &= !enable_pair(bp);
    st.dr[5] &= !((0x3u64 << ls) | (0x3u64 << ts));
    st.dr[bp] = 0;
    st.clear_used(bp);
}

/// `configureSingleStepping` (breakpoint.c:517). Returns bp_was_consumed
/// (always false on x86 — single-step is TF-based, no DR consumed).
/// The caller clears/sets TF on the thread's saved RFLAGS.
pub fn configure_single_stepping(st: &mut DebugState, n_instr: u64) -> bool {
    st.single_step_enabled = n_instr != 0;
    st.n_instructions = n_instr;
    false
}

/// `singleStepFaultCounterReady` (debug.h:74). Decrement the counter on
/// each single-step #DB; the fault is delivered only when it reaches 0.
pub fn single_step_counter_ready(st: &mut DebugState) -> bool {
    if st.n_instructions > 0 {
        st.n_instructions -= 1;
    }
    st.n_instructions == 0
}

/// Reason carried in a HW-breakpoint DebugException = the breakpoint
/// TYPE (Instruction=1 / Data=0), read from the DR7 cache.
pub fn breakpoint_reason(st: &DebugState, bp: usize) -> u64 {
    let arch_rw = (st.dr[5] >> type_shift(bp)) & 0x3;
    arch_to_type_and_access(arch_rw).0
}

// ---- live debug-register access ----------------------------------------

#[inline]
pub unsafe fn read_dr6() -> u64 {
    let v: u64;
    core::arch::asm!("mov {}, dr6", out(reg) v, options(nomem, nostack));
    v
}

#[inline]
pub unsafe fn write_dr6(v: u64) {
    core::arch::asm!("mov dr6, {}", in(reg) v, options(nomem, nostack));
}

#[inline]
pub unsafe fn write_dr7(v: u64) {
    core::arch::asm!("mov dr7, {}", in(reg) v, options(nomem, nostack));
}

/// Load a thread's full breakpoint context into the live DR registers.
/// DR7 is written last (it activates the configuration).
pub unsafe fn load_breakpoint_state(st: &DebugState) {
    load_register_image(st, st.dr[5]);
}

unsafe fn load_register_image(st: &DebugState, dr7: u64) {
    // Withdraw the previous thread's comparators before changing any address/status register.
    write_dr7(DR7_INIT);
    core::arch::asm!("mov dr0, {}", in(reg) st.dr[0], options(nomem, nostack));
    core::arch::asm!("mov dr1, {}", in(reg) st.dr[1], options(nomem, nostack));
    core::arch::asm!("mov dr2, {}", in(reg) st.dr[2], options(nomem, nostack));
    core::arch::asm!("mov dr3, {}", in(reg) st.dr[3], options(nomem, nostack));
    write_dr6(st.dr[4]);
    write_dr7(dr7);
}

/// Restore disabled state too: a TF exception must not inherit another thread's live DR6.
pub unsafe fn load_all_disabled(st: &DebugState) {
    load_register_image(st, st.dr[5] & !ALL_ENABLE_BITS);
}

#[cfg(feature = "spec")]
pub(crate) mod spec;
