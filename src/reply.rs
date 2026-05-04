//! Phase 34e — Reply objects + kernel-side pool.
//!
//! Reply caps under MCS point at a kernel-side `Reply` struct that
//! tracks which thread the cap is bound to. `Untyped::Retype(Reply)`
//! allocates a slot from the kernel pool; `Cap::Reply` carries a
//! `PPtr<ReplyStorage>` whose `addr - 1` is the pool index (same
//! `+1` trick we use for Endpoint / Notification / SchedContext).
//!
//! The pool data structure itself only carries `bound_tcb` for
//! now. seL4's full Reply object also tracks the next reply in
//! the call-stack chain (for stacked Calls); we'll add that when
//! the IPC path actually starts wiring through reply caps in a
//! follow-up phase.

#![allow(dead_code)]

use crate::tcb::TcbId;

/// Kernel-side state for a `Cap::Reply`. One slot per pool index.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Reply {
    /// TCB this reply object is currently bound to (the caller in
    /// an in-flight Call). `None` means "unbound — no Call has
    /// claimed it yet".
    pub bound_tcb: Option<TcbId>,
}

impl Reply {
    pub const fn new() -> Self {
        Self { bound_tcb: None }
    }
}
