//! Placeholder for the AArch64 hardware-debug register bank.
//!
//! Debug-capability invocations remain unavailable until exception entry can
//! save and restore `DBGBCR<n>_EL1`/`DBGWCR<n>_EL1` state.

#[derive(Copy, Clone, Debug)]
pub struct DebugState;

impl DebugState {
    pub const fn new() -> Self {
        Self
    }
}
