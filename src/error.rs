//! Unified kernel error type. Mirrors seL4's `exception_t` plus the
//! associated `current_syscall_error` / `current_lookup_fault` /
//! `current_fault` thread-local data, but as a single Rust enum so
//! `?` propagates everywhere a kernel function can fail.
//!
//! seL4's C signature is `exception_t handleX(...)`, where the
//! caller checks the returned tag and consults globals for detail.
//! We collapse that to `KResult<T>` returning the detail by value —
//! the same information, no globals.

use crate::cspace::LookupFault;
use crate::types::seL4_Error;
use crate::untyped::RetypeError;

/// Top-level reason a kernel call failed. Variants line up with
/// `enum exception` in seL4/include/types.h.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum KException {
    /// User error reportable to userspace via the IPC return path.
    /// Carries a typed error code; the kernel may attach extra detail
    /// through the IPC buffer in later phases.
    SyscallError(SyscallError),
    /// Lookup failed walking the CSpace. Maps to seL4's
    /// `EXCEPTION_LOOKUP_FAULT`.
    LookupFault(LookupFault),
    /// A user thread faulted (page fault, capability fault, etc.).
    /// We carry only the discriminant for now; full fault-message
    /// construction lands when IPC fault delivery does.
    Fault(FaultKind),
    /// The kernel needs to yield because of an interrupt or
    /// timeslice expiry — same role as `EXCEPTION_PREEMPTED` in
    /// seL4. The caller should restart the operation later.
    Preempted,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FaultKind {
    /// Userspace did something invalid that wasn't a recoverable
    /// error (e.g. an unmapped page). Carries the seL4 fault type
    /// tag the user thread will see in its fault message.
    CapFault,
    UnknownSyscall { number: i64 },
    UserException { number: u32, code: u32 },
    VmFault { addr: u64, fsr: u64 },
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SyscallError {
    pub code: seL4_Error,
}

impl SyscallError {
    pub const fn new(code: seL4_Error) -> Self {
        Self { code }
    }
}

pub type KResult<T = ()> = Result<T, KException>;

// ---------------------------------------------------------------------------
// `?` conversions from the per-subsystem error types.
// ---------------------------------------------------------------------------

impl From<LookupFault> for KException {
    fn from(f: LookupFault) -> Self {
        KException::LookupFault(f)
    }
}

impl From<RetypeError> for KException {
    fn from(e: RetypeError) -> Self {
        let code = match e {
            RetypeError::RangeError => seL4_Error::seL4_RangeError,
            RetypeError::InvalidArgument => seL4_Error::seL4_InvalidArgument,
            RetypeError::NotEnoughMemory => seL4_Error::seL4_NotEnoughMemory,
            RetypeError::IllegalOperationDeviceMemory => seL4_Error::seL4_IllegalOperation,
        };
        KException::SyscallError(SyscallError::new(code))
    }
}
