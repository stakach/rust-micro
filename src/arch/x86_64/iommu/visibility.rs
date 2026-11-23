//! Visibility of legacy VT-d tables on noncoherent and write-buffered remappers.

use core::sync::atomic::{fence, Ordering};

use super::retirement::{VtdError, INVALIDATION_SPINS};

const WRITE_BUFFER_FLUSH: u32 = 1 << 27;
// Match the persistent state fields of GCMD and GSTS (TE, QIE, IRE and CFI).
const PERSISTENT_COMMANDS: u32 = (1 << 31) | (1 << 26) | (1 << 25) | (1 << 23);

pub fn global_command(status: u32, request: u32) -> u32 {
    (status & PERSISTENT_COMMANDS) | request
}

/// GCMD and GSTS are individual 32-bit registers.
pub trait VtdGlobalRegisters {
    fn status(&mut self) -> u32;
    fn command(&mut self, value: u32);
}

fn wait_write_buffer_idle(regs: &mut impl VtdGlobalRegisters) -> Result<u32, VtdError> {
    for _ in 0..INVALIDATION_SPINS {
        let status = regs.status();
        if status & WRITE_BUFFER_FLUSH == 0 {
            return Ok(status);
        }
        core::hint::spin_loop();
    }
    Err(VtdError::TimedOut)
}

pub fn flush_write_buffer(regs: &mut impl VtdGlobalRegisters) -> Result<(), VtdError> {
    let status = wait_write_buffer_idle(regs)?;
    regs.command(global_command(status, WRITE_BUFFER_FLUSH));
    wait_write_buffer_idle(regs).map(|_| ())
}

/// CLFLUSH availability and width are enumerated in CPUID.01H.
pub fn cache_line_bytes(ebx: u32, edx: u32) -> Option<usize> {
    let bytes = ((ebx >> 8) & 0xff) as usize * 8;
    // Keep the two words of each aligned context entry on the same line.
    (edx & (1 << 19) != 0 && bytes >= 16 && bytes.is_power_of_two()).then_some(bytes)
}

#[derive(Clone, Copy)]
pub struct TableVisibility {
    coherent: bool,
    write_buffer_flush: bool,
}

impl TableVisibility {
    pub const fn new(coherent: bool, write_buffer_flush: bool) -> Self {
        Self {
            coherent,
            write_buffer_flush,
        }
    }

    /// Clean after a table entry write, before the invalidation path's fence.
    /// Context and IOTLB invalidations drain the hardware write buffer implicitly.
    pub fn clean_noncoherent(self, clean: impl FnOnce()) {
        if !self.coherent {
            clean();
        }
    }

    /// Finish initialization before publishing the pointer that exposes the table.
    /// The new table has no preceding invalidation to drain posted writes.
    pub fn prepare_unlinked(
        self,
        clean: impl FnOnce(),
        flush: impl FnOnce() -> Result<(), VtdError>,
    ) -> Result<(), VtdError> {
        self.clean_noncoherent(clean);
        fence(Ordering::SeqCst);
        if self.write_buffer_flush {
            flush()?;
        }
        Ok(())
    }
}
