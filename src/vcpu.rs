//! Phase 10e — VT-x VCPU object.
//!
//! Mirrors `seL4/src/arch/x86/object/vcpu.c` for the VCPU
//! lifecycle: a userland thread creates a VCPU cap, configures its
//! VMCS through VMRead/VMWrite invocations, attaches an EPT root,
//! injects a virtual IRQ, then asks the kernel to enter the guest
//! via `seL4_VMEnter`. Hardware bits (vmptrld, vmlaunch, vmresume,
//! VMCS field encodings) are stubbed; the state machine and cap
//! plumbing are testable today.
//!
//! Behind the `vmx` cargo feature.

#![cfg(feature = "vmx")]

use crate::tcb::TcbId;
use crate::types::seL4_Word as Word;

/// Subset of the VMCS guest-state fields we track. Real VMCSes have
/// ~140 fields; we expose just enough for the lifecycle to be
/// meaningful at the spec level.
#[derive(Copy, Clone, Debug, Default)]
pub struct GuestState {
    pub rip: Word,
    pub rsp: Word,
    pub rflags: Word,
    pub cr0: Word,
    pub cr3: Word,
    pub cr4: Word,
    pub ept_root: Word,
}

/// VCPU lifecycle.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum VcpuState {
    /// VMCS region cleared, no thread bound.
    #[default]
    Inactive,
    /// Bound to a thread; VMCS holds last-known guest state on this
    /// CPU (or migrated from another).
    Loaded,
    /// Currently executing in non-root mode. Only one thread per
    /// CPU may be in this state.
    Running,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Vcpu {
    pub state: VcpuState,
    pub guest: GuestState,
    /// Thread that holds this VCPU cap and is responsible for
    /// driving the run loop. seL4 calls this `vcpu->vcpuTCB`.
    pub bound_tcb: Option<TcbId>,
    /// Pending virtual IRQ vector (or 0 if none).
    pub pending_intr: u8,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VcpuError {
    /// Operation requires the VCPU to be in a particular state.
    BadState,
    /// VCPU is already bound to another thread.
    AlreadyBound,
}

/// Mirrors `seL4_X86_VCPU_SetTCB`. Bind the VCPU to a thread.
pub fn bind(vcpu: &mut Vcpu, tcb: TcbId) -> Result<(), VcpuError> {
    if vcpu.bound_tcb.is_some() {
        return Err(VcpuError::AlreadyBound);
    }
    vcpu.bound_tcb = Some(tcb);
    if vcpu.state == VcpuState::Inactive {
        vcpu.state = VcpuState::Loaded;
    }
    Ok(())
}

/// Mirrors `seL4_X86_VCPU_WriteRegisters`. Userspace stages guest
/// register state before launching.
pub fn write_guest(vcpu: &mut Vcpu, state: GuestState) -> Result<(), VcpuError> {
    if !matches!(vcpu.state, VcpuState::Loaded) {
        return Err(VcpuError::BadState);
    }
    vcpu.guest = state;
    Ok(())
}

/// Mirrors `seL4_X86_Page_MapEPT`. Attach an EPT root for guest
/// physical translation.
pub fn set_ept_root(vcpu: &mut Vcpu, ept_root: Word) -> Result<(), VcpuError> {
    if !matches!(vcpu.state, VcpuState::Loaded) {
        return Err(VcpuError::BadState);
    }
    vcpu.guest.ept_root = ept_root;
    Ok(())
}

/// Inject an interrupt into the guest on the next entry.
pub fn inject_intr(vcpu: &mut Vcpu, vector: u8) -> Result<(), VcpuError> {
    if !matches!(vcpu.state, VcpuState::Loaded) {
        return Err(VcpuError::BadState);
    }
    vcpu.pending_intr = vector;
    Ok(())
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ExitReason {
    /// Guest issued cpuid; userspace must emulate.
    Cpuid,
    /// Guest accessed an unmapped EPT region.
    EptViolation { gpa: Word },
    /// Guest issued a hlt instruction.
    Hlt,
    /// Pending interrupt window opened.
    InterruptWindow,
}

/// Drive the VCPU into non-root mode. Returns the exit reason when
/// the guest exits back to root mode. Hardware vmlaunch / vmresume
/// is stubbed; the spec drives the state machine directly via
/// `inject_exit`.
pub fn vmenter(vcpu: &mut Vcpu) -> Result<(), VcpuError> {
    if !matches!(vcpu.state, VcpuState::Loaded) {
        return Err(VcpuError::BadState);
    }
    vcpu.state = VcpuState::Running;
    Ok(())
}

/// Test hook: simulate the guest exiting with the given reason.
/// Real hardware does this implicitly — the kernel's exit handler
/// observes the VMCS exit-reason field.
pub fn inject_exit(vcpu: &mut Vcpu, reason: ExitReason) -> Result<ExitReason, VcpuError> {
    if !matches!(vcpu.state, VcpuState::Running) {
        return Err(VcpuError::BadState);
    }
    vcpu.state = VcpuState::Loaded;
    // Pending interrupt is consumed when the window opens.
    if matches!(reason, ExitReason::InterruptWindow) {
        vcpu.pending_intr = 0;
    }
    Ok(reason)
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

#[cfg(feature = "spec")]
pub mod spec {
    use super::*;
    use crate::arch;

    pub fn test_vcpu() {
        arch::log("Running VT-x VCPU tests...\n");
        bind_then_load();
        write_guest_requires_loaded();
        run_then_exit_cycle();
        injected_intr_clears_on_window();
        double_bind_rejected();
        arch::log("VT-x VCPU tests completed\n");
    }

    #[inline(never)]
    fn bind_then_load() {
        let mut v = Vcpu::default();
        assert_eq!(v.state, VcpuState::Inactive);
        bind(&mut v, TcbId(2)).unwrap();
        assert_eq!(v.state, VcpuState::Loaded);
        assert_eq!(v.bound_tcb, Some(TcbId(2)));
        arch::log("  ✓ bind transitions Inactive → Loaded\n");
    }

    #[inline(never)]
    fn write_guest_requires_loaded() {
        let mut v = Vcpu::default();
        // Inactive → BadState.
        assert_eq!(write_guest(&mut v, GuestState::default()), Err(VcpuError::BadState));
        bind(&mut v, TcbId(1)).unwrap();
        // Loaded → ok.
        let mut g = GuestState::default();
        g.rip = 0xFFFF_F000;
        g.cr3 = 0x100_0000;
        write_guest(&mut v, g).unwrap();
        assert_eq!(v.guest.rip, 0xFFFF_F000);
        assert_eq!(v.guest.cr3, 0x100_0000);
        arch::log("  ✓ write_guest only works in Loaded state\n");
    }

    #[inline(never)]
    fn run_then_exit_cycle() {
        let mut v = Vcpu::default();
        bind(&mut v, TcbId(1)).unwrap();
        // Can't exit without entering.
        assert_eq!(inject_exit(&mut v, ExitReason::Hlt), Err(VcpuError::BadState));
        // Enter, then exit on Hlt.
        vmenter(&mut v).unwrap();
        assert_eq!(v.state, VcpuState::Running);
        assert_eq!(inject_exit(&mut v, ExitReason::Hlt), Ok(ExitReason::Hlt));
        assert_eq!(v.state, VcpuState::Loaded);
        arch::log("  ✓ vmenter → run → inject_exit cycles state machine\n");
    }

    #[inline(never)]
    fn injected_intr_clears_on_window() {
        let mut v = Vcpu::default();
        bind(&mut v, TcbId(1)).unwrap();
        inject_intr(&mut v, 32).unwrap();
        assert_eq!(v.pending_intr, 32);
        vmenter(&mut v).unwrap();
        // Exit on interrupt window — pending vector consumed.
        inject_exit(&mut v, ExitReason::InterruptWindow).unwrap();
        assert_eq!(v.pending_intr, 0);
        // Other exits don't clear it.
        inject_intr(&mut v, 33).unwrap();
        vmenter(&mut v).unwrap();
        inject_exit(&mut v, ExitReason::Hlt).unwrap();
        assert_eq!(v.pending_intr, 33);
        arch::log("  ✓ pending IRQ consumed by interrupt-window exit\n");
    }

    #[inline(never)]
    fn double_bind_rejected() {
        let mut v = Vcpu::default();
        bind(&mut v, TcbId(1)).unwrap();
        assert_eq!(bind(&mut v, TcbId(2)), Err(VcpuError::AlreadyBound));
        arch::log("  ✓ double-bind rejected\n");
    }
}
